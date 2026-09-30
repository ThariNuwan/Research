from pathlib import Path

from iacrisk.context.exposure import extract, is_public_cidr
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
AUTHORED = REPO_ROOT / "corpus" / "authored"


def _finding(identity: str, issue_class: str = "networking-ingress-exposure") -> NormalizedFinding:
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
        file_path="db-app.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )


def _terragoat() -> dict[str, TerraformResource]:
    return build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)


def _authored() -> dict[str, TerraformResource]:
    return build_index(sorted(AUTHORED.glob("*.tf")), AUTHORED)


def test_is_public_cidr_separates_rfc1918_from_internet_routable() -> None:
    """The reserved ranges are worth pinning explicitly. An earlier version of this test
    expected 203.0.113.0/24 to be public; it is TEST-NET-3 (RFC 5737 documentation), and
    Python's ipaddress classifies it non-global - correctly, since a documentation range
    in a security group is no more an internet exposure than an RFC1918 one. The
    implementation was right and the expectation was wrong.
    """
    assert is_public_cidr("0.0.0.0/0") is True
    assert is_public_cidr("1.1.1.0/24") is True
    assert is_public_cidr("8.8.8.8/32") is True
    assert is_public_cidr("10.0.0.0/16") is False
    assert is_public_cidr("192.168.1.0/24") is False
    assert is_public_cidr("172.16.0.0/12") is False
    assert is_public_cidr("203.0.113.0/24") is False  # TEST-NET-3, RFC 5737
    assert is_public_cidr("127.0.0.1/32") is False
    assert is_public_cidr("not-a-cidr") is False


def test_a_literal_any_source_ingress_opening_resolves_to_four() -> None:
    """aws_security_group.web-node carries two ingress blocks with literal 0.0.0.0/0
    (ec2.tf:77-115), which the rubric's precedence rule forces to >= 4.
    """
    value = extract(_finding("aws_security_group.web-node"), _terragoat())
    assert value.state is FactorState.RESOLVED
    assert value.level == 4


def test_an_egress_any_source_opening_is_not_inbound_exposure() -> None:
    """The finding that corrects this plan's original assertion.

    aws_security_group_rule.egress carries a literal 0.0.0.0/0 but type = "egress".
    Exposure is inbound reachability, so it must NOT trigger the precedence rule -
    corpus-v1's networking scenario places sgr-egress-unrestricted in its bottom tier,
    and reading egress as inbound would force it to 4 and invert that ordering. Egress
    risk maps to networking-egress-exposure, which no rubric factor covers (spec 1.4).
    """
    value = extract(_finding("aws_security_group_rule.egress"), _terragoat())
    assert value.state is FactorState.RESOLVED
    assert value.level == 0
    assert "egress" in value.evidence


def test_an_interpolated_ingress_cidr_is_unresolved_and_never_low() -> None:
    """The corpus case sgr-ingress-vpc-interpolated. Unresolved routes to the rubric
    default 3, never to 0 or 1 - PLAN Q9's hard rule.
    """
    value = extract(_finding("aws_security_group_rule.ingress"), _terragoat())
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 3


def test_a_security_group_with_no_ingress_block_resolves_low_not_unresolved() -> None:
    """Resolved-negative is not unresolved: the extractor looked and found no opening.
    Routing this to unresolved would score it 3, which the networking scenario places
    ABOVE it - sg-default-low-exposure shares the bottom tier with the egress rule.
    """
    value = extract(_finding("aws_security_group.default"), _terragoat())
    assert value.state is FactorState.RESOLVED
    assert value.level == 0


def test_the_networking_scenarios_three_tiers_are_reproduced_by_the_extractor() -> None:
    """corpus-v1.json's networking scenario expects, top to bottom:
    [sg-web-node-high-exposure], [sgr-ingress-vpc-interpolated],
    [sgr-egress-unrestricted, sg-default-low-exposure] - the last two tied.

    All four cases declare identical context, so Public Exposure is the only factor with
    room to move and this is the scenario's whole mechanism. Asserting it here means a
    regression in any single branch surfaces as a failed ordering rather than as a
    scenario that silently stops discriminating.
    """
    index = _terragoat()
    scored = {
        name: extract(_finding(name), index).scored_level
        for name in (
            "aws_security_group.web-node",
            "aws_security_group_rule.ingress",
            "aws_security_group_rule.egress",
            "aws_security_group.default",
        )
    }
    assert scored["aws_security_group.web-node"] > scored["aws_security_group_rule.ingress"]
    assert scored["aws_security_group_rule.ingress"] > scored["aws_security_group_rule.egress"]
    assert scored["aws_security_group_rule.egress"] == scored["aws_security_group.default"]


def test_a_bucket_with_public_access_block_fully_enabled_resolves_to_zero() -> None:
    value = extract(_finding("aws_s3_bucket.private_baseline"), _authored())
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_a_bucket_with_the_block_disabled_plus_a_public_policy_resolves_to_five() -> None:
    """Spec section 4.4's enumerated combination. Reaching it at all requires resolving
    `bucket = aws_s3_bucket.public_exposed.id` as an address, which is why
    resource_reference exists - without it this pattern is unresolvable and the storage
    exposure contrastive pair cannot be reproduced.
    """
    value = extract(_finding("aws_s3_bucket.public_exposed"), _authored())
    assert (value.state, value.level) == (FactorState.RESOLVED, 5)


def test_the_storage_exposure_pair_separates_in_the_expected_direction() -> None:
    index = _authored()
    high = extract(_finding("aws_s3_bucket.public_exposed"), index).scored_level
    low = extract(_finding("aws_s3_bucket.private_baseline"), index).scored_level
    assert high > low


def test_an_unsupported_pattern_is_unresolved_not_zero() -> None:
    """Scoring 0 would assert 'no exposure surface', which the extractor has not
    established for a resource type outside the closed pattern list.
    """
    value = extract(_finding("aws_db_parameter_group.default"), _terragoat())
    assert value.state is FactorState.UNRESOLVED


def test_a_missing_resource_is_unresolved() -> None:
    value = extract(_finding("aws_s3_bucket.not_in_the_index"), {})
    assert value.state is FactorState.UNRESOLVED


def test_extraction_never_rewrites_the_findings_identity() -> None:
    """Spec section 4.3: attribution changes the factor, never the identity. Rewriting
    it would undo S3a's dedupe separation of rule-level from target-level findings.
    """
    finding = _finding("aws_security_group_rule.egress")
    extract(finding, _terragoat())
    assert finding.resource_identity == "aws_security_group_rule.egress"


def test_the_level_does_not_depend_on_the_issue_class() -> None:
    """severity_context_fencing, at the unit level. Gate 5 runs the corpus-wide form."""
    index = _terragoat()
    a = extract(_finding("aws_security_group.web-node", "networking-ingress-exposure"), index)
    b = extract(_finding("aws_security_group.web-node", "networking-config-hygiene"), index)
    assert a.level == b.level


def test_a_kubernetes_service_resolves_by_type() -> None:
    k8s = {
        "v1/Service/default/lb": {"kind": "Service", "spec": {"type": "LoadBalancer"}},
        "v1/Service/default/np": {"kind": "Service", "spec": {"type": "NodePort"}},
        "v1/Service/default/cip": {"kind": "Service", "spec": {"type": "ClusterIP"}},
        "v1/Service/default/bare": {"kind": "Service", "spec": {}},
    }
    levels = {name.split("/")[-1]: extract(_finding(name), {}, k8s).level for name in k8s}
    assert levels == {"lb": 3, "np": 2, "cip": 1, "bare": 1}


def test_a_kubernetes_ingress_resolves_to_three() -> None:
    k8s = {"networking.k8s.io/v1/Ingress/default/ing": {"kind": "Ingress", "spec": {}}}
    value = extract(_finding("networking.k8s.io/v1/Ingress/default/ing"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 3)
