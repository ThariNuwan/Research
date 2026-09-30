from pathlib import Path

from iacrisk.context.privilege import (
    action_services,
    extract,
    parse_policy_document,
    privilege_level,
)
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
AUTHORED = REPO_ROOT / "corpus" / "authored"

HEREDOC = (
    '"<<EOF\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n'
    '      "Action": [\n        "s3:*",\n        "ec2:*",\n        "rds:*"\n      ],\n'
    '      "Effect": "Allow",\n      "Resource": "*"\n    }\n  ]\n}\nEOF"'
)
JSONENCODE = (
    '${jsonencode({Version = "2012-10-17", Statement = '
    '[{Effect = "Allow", Action = ["s3:*"], Resource = "*"}]})}'
)


def _finding(identity: str, issue_class: str = "iam-overpermissive-policy") -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=3,
        platform="terraform",
        resource_identity=identity,
        identity_kind="terraform",
        file_path="x.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )


def _terragoat() -> dict[str, TerraformResource]:
    return build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)


def _authored() -> dict[str, TerraformResource]:
    return build_index(sorted(AUTHORED.glob("*.tf")), AUTHORED)


def test_a_heredoc_policy_parses_to_clean_unquoted_values() -> None:
    document = parse_policy_document(HEREDOC)
    assert document is not None
    statement = document["Statement"][0]
    assert statement["Action"] == ["s3:*", "ec2:*", "rds:*"]
    assert statement["Resource"] == "*"


def test_a_jsonencode_policy_parses_via_hcl2_reparse() -> None:
    """jsonencode carries HCL object syntax, not JSON, so json.loads fails on it, and
    hcl2 retains quotes on every string so the result needs deep-unquoting.
    """
    document = parse_policy_document(JSONENCODE)
    assert document is not None
    statement = document["Statement"][0]
    assert statement["Action"] == ["s3:*"]
    assert statement["Resource"] == "*"
    assert statement["Effect"] == "Allow"


def test_an_opaque_policy_reference_does_not_parse() -> None:
    assert parse_policy_document('"${var.policy_json}"') is None
    assert parse_policy_document('"${data.aws_iam_policy_document.d.json}"') is None
    assert parse_policy_document(None) is None
    assert parse_policy_document(123) is None


def test_action_services_collapses_wildcards_and_prefixes() -> None:
    assert action_services(["s3:*"]) == {"s3"}
    assert action_services(["s3:GetObject", "s3:PutObject"]) == {"s3"}
    assert action_services(["s3:*", "ec2:*", "rds:*"]) == {"s3", "ec2", "rds"}
    assert action_services(["*"]) == {"*"}


def test_the_level_mapping_matches_spec_section_5_4_exactly() -> None:
    """Every corpus IAM case lands on a distinct level. If the first two collapse to
    one level, the pair privilege-iam-bucket-to-account stops isolating its factor -
    it would still pass on rank, for a reason fencing forbids.
    """
    assert privilege_level(["s3:*"], ["arn:aws:s3:::bucket/*"]) == 2
    assert privilege_level(["s3:*"], ["*"]) == 3
    assert privilege_level(["s3:*", "ec2:*", "rds:*"], ["*"]) == 4
    assert privilege_level(["*"], ["*"]) == 5


def test_a_single_read_only_action_on_a_bounded_resource_is_one() -> None:
    assert privilege_level(["s3:GetObject"], ["arn:aws:s3:::bucket/*"]) == 1


def test_the_three_authored_iam_cases_resolve_to_two_three_and_five() -> None:
    """Gate 7's core. These three are the corpus's two privilege contrastive pairs."""
    index = _authored()
    levels = {
        name: extract(_finding(f"aws_iam_policy.{name}"), index).level
        for name in ("s3_bucket_scope", "s3_account_scope", "unrestricted_scope")
    }
    assert levels == {"s3_bucket_scope": 2, "s3_account_scope": 3, "unrestricted_scope": 5}


def test_both_privilege_pairs_separate_on_the_factor_itself() -> None:
    """Not on class count. If bucket and account collapsed to one level the first pair
    would still pass on rank, because account-scope carries an extra issue class and so
    an extra scored finding - but it would pass for a reason severity_context_fencing
    forbids, since a class difference cannot move a factor.
    """
    index = _authored()
    bucket = extract(_finding("aws_iam_policy.s3_bucket_scope"), index).scored_level
    account = extract(_finding("aws_iam_policy.s3_account_scope"), index).scored_level
    unrestricted = extract(_finding("aws_iam_policy.unrestricted_scope"), index).scored_level
    assert account > bucket
    assert unrestricted > account


def test_the_vendored_heredoc_policies_resolve_to_four() -> None:
    """Both carry wildcards across several services on Resource = "*"."""
    index = _terragoat()
    assert extract(_finding("aws_iam_role_policy.ec2policy"), index).level == 4
    assert extract(_finding("aws_iam_user_policy.userpolicy"), index).level == 4


def test_a_trust_policy_grants_no_permission_and_leaves_the_role_unresolved() -> None:
    """Decision 12. aws_iam_role.ec2role's assume_role_policy carries
    Action = "sts:AssumeRole" with a Principal and NO Resource - it declares who may
    assume the role rather than granting the role anything. Scoring it on the permission
    ladder reads the grant backwards; sts:AssumeRole would land at 4 as an escalation
    enabler when it is the role's own trust boundary. Resolving 0 would falsely reassure,
    because the role's real permissions live in separate attached policy resources.
    """
    value = extract(_finding("aws_iam_role.ec2role"), _terragoat())
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 4
    assert "trust policy" in value.evidence


def test_a_data_source_trust_policy_is_also_unresolved() -> None:
    value = extract(_finding("aws_iam_role.iam_for_eks"), _terragoat())
    assert value.state is FactorState.UNRESOLVED


def test_an_aws_managed_policy_attachment_is_unresolved_not_guessed() -> None:
    """Spec section 5.2, decision 6: the contents are not in this repository and reading
    them needs a live account, which is outside static pre-deployment analysis.
    """
    value = extract(
        _finding("aws_iam_role_policy_attachment.policy_attachment-AmazonEKSClusterPolicy"),
        _terragoat(),
    )
    assert value.state is FactorState.UNRESOLVED
    assert "AmazonEKSClusterPolicy" in value.evidence


def test_a_non_iam_resource_has_no_privilege_dimension() -> None:
    value = extract(_finding("aws_db_parameter_group.default"), _terragoat())
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_a_missing_resource_is_unresolved() -> None:
    value = extract(_finding("aws_iam_policy.absent"), {})
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 4


def test_an_unevaluated_condition_never_reduces_the_level() -> None:
    """Spec section 5.3. Treating a condition the extractor cannot evaluate as
    mitigating is the false-reassurance failure mode PLAN Q9 forbids.
    """
    with_condition = (
        '${jsonencode({Version = "2012-10-17", Statement = [{Effect = "Allow", '
        'Action = ["*"], Resource = "*", Condition = {StringEquals = {"aws:x" = "y"}}}]})}'
    )
    document = parse_policy_document(with_condition)
    assert document is not None
    statement = document["Statement"][0]
    assert privilege_level(statement["Action"], [statement["Resource"]]) == 5


def test_a_deny_statement_does_not_contribute_a_level() -> None:
    """An earlier version of this test asserted only that Effect parsed as "Deny", which
    would have stayed green with the Deny guard deleted. It now asserts the outcome: a
    policy whose only statement is a Deny of everything yields no permission level at all,
    so the resource resolves unresolved rather than 5.
    """
    index = {
        "aws_iam_policy.deny_all": TerraformResource(
            identity="aws_iam_policy.deny_all",
            type="aws_iam_policy",
            name="deny_all",
            body={
                "policy": '${jsonencode({Version = "2012-10-17", Statement = '
                '[{Effect = "Deny", Action = ["*"], Resource = "*"}]})}'
            },
            file_path="x.tf",
        )
    }
    value = extract(_finding("aws_iam_policy.deny_all"), index)
    assert value.state is FactorState.UNRESOLVED
    assert value.level is None


def test_the_level_does_not_depend_on_the_issue_class() -> None:
    index = _authored()
    a = extract(_finding("aws_iam_policy.unrestricted_scope", "iam-overpermissive-policy"), index)
    b = extract(_finding("aws_iam_policy.unrestricted_scope", "storage-logging-audit"), index)
    assert a.level == b.level == 5


def test_kubernetes_wildcard_rbac_resolves_to_five() -> None:
    k8s = {
        "rbac.authorization.k8s.io/v1/ClusterRole/super": {
            "kind": "ClusterRole",
            "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
        }
    }
    value = extract(_finding("rbac.authorization.k8s.io/v1/ClusterRole/super"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 5)


def test_a_cluster_admin_binding_resolves_to_five() -> None:
    k8s = {
        "rbac.authorization.k8s.io/v1/ClusterRoleBinding/ca": {
            "kind": "ClusterRoleBinding",
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        }
    }
    value = extract(_finding("rbac.authorization.k8s.io/v1/ClusterRoleBinding/ca"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 5)


def test_secrets_access_resolves_to_four() -> None:
    k8s = {
        "rbac.authorization.k8s.io/v1/Role/reader": {
            "kind": "Role",
            "rules": [{"verbs": ["get"], "resources": ["secrets"]}],
        }
    }
    value = extract(_finding("rbac.authorization.k8s.io/v1/Role/reader"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 4)


def test_a_read_only_role_resolves_to_one() -> None:
    k8s = {
        "rbac.authorization.k8s.io/v1/Role/ro": {
            "kind": "Role",
            "rules": [{"verbs": ["get", "list"], "resources": ["pods"]}],
        }
    }
    value = extract(_finding("rbac.authorization.k8s.io/v1/Role/ro"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 1)


def test_a_binding_to_a_non_admin_role_is_unresolved_not_zero() -> None:
    """The bound role's rules are a separate resource this bounded extractor does not
    aggregate, so its breadth is genuinely unknown rather than absent.
    """
    k8s = {
        "rbac.authorization.k8s.io/v1/RoleBinding/rb": {
            "kind": "RoleBinding",
            "roleRef": {"kind": "Role", "name": "some-role"},
        }
    }
    value = extract(_finding("rbac.authorization.k8s.io/v1/RoleBinding/rb"), {}, k8s)
    assert value.state is FactorState.UNRESOLVED
