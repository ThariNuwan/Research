from pathlib import Path

from iacrisk.context.encryption import extract
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def _finding(identity: str, issue_class: str = "storage-encryption-at-rest") -> NormalizedFinding:
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


def _res(rtype: str, name: str, **body: object) -> TerraformResource:
    return TerraformResource(
        identity=f"{rtype}.{name}", type=rtype, name=name, body=dict(body), file_path="x.tf"
    )


def _terragoat() -> dict[str, TerraformResource]:
    return build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)


def test_an_explicitly_encrypted_volume_scores_zero() -> None:
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=True)}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_an_explicitly_unencrypted_volume_scores_two() -> None:
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=False)}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 2)


def test_the_vendored_unencrypted_databases_resolve_to_two() -> None:
    """Both carry a literal storage_encrypted = false."""
    index = _terragoat()
    assert extract(_finding("aws_db_instance.default"), index).level == 2
    assert extract(_finding("aws_neptune_cluster.default"), index).level == 2


def test_an_absent_attribute_is_unresolved_because_the_platform_default_is_invisible() -> None:
    """The corpus case ebs-web-host-storage-compute. aws_ebs_volume.web_host_storage
    declares no `encrypted` attribute at all - measured, its body carries only
    availability_zone, size and tags - and AWS's effective default depends on an
    account-level encryption-by-default setting that is not in the source.

    Absent is therefore not false. Resolving 2 from the finding's existence would violate
    severity_context_fencing; resolving 0 would falsely reassure. Unresolved scores 2 -
    the same number as a confirmed-unencrypted volume, and a different state, which the
    coverage report keeps apart.
    """
    value = extract(_finding("aws_ebs_volume.web_host_storage"), _terragoat())
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 2
    assert "not visible in this source" in value.evidence


def test_a_non_literal_encryption_block_is_unresolved_and_never_reaches_three() -> None:
    """aws_s3_bucket.logs carries a server_side_encryption_configuration whose contents
    are interpolated. Spec section 6.1: level 3 requires positively-established mandate
    evidence, which a non-literal read cannot supply.
    """
    value = extract(_finding("aws_s3_bucket.logs"), _terragoat())
    assert value.state is FactorState.UNRESOLVED
    assert value.level != 3
    assert value.scored_level == 2


def test_a_literal_kms_key_counts_as_configured() -> None:
    index = {
        "aws_sqs_queue.q": _res(
            "aws_sqs_queue", "q", kms_master_key_id='"arn:aws:kms:us-east-1:1:key/abc"'
        )
    }
    value = extract(_finding("aws_sqs_queue.q"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_the_level_does_not_come_from_the_issue_class() -> None:
    """Spec section 6.2, the fencing constraint's sharpest case. An encrypted volume
    scores 0 even when the finding's class is storage-encryption-at-rest.
    """
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=True)}
    a = extract(_finding("aws_ebs_volume.v", "storage-encryption-at-rest"), index)
    b = extract(_finding("aws_ebs_volume.v", "storage-logging-audit"), index)
    assert a.level == b.level == 0


def test_a_resource_with_no_data_at_rest_dimension_scores_zero() -> None:
    value = extract(_finding("aws_security_group.default"), _terragoat())
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_a_missing_resource_is_unresolved() -> None:
    value = extract(_finding("aws_ebs_volume.absent"), {})
    assert value.state is FactorState.UNRESOLVED


def test_a_kubernetes_secret_is_unresolved_rather_than_three() -> None:
    """etcd encryption-at-rest is a cluster-level EncryptionConfiguration, not a property
    of the Secret manifest, so a manifest read establishes nothing either way. Resolving
    3 would assert mandate evidence this read does not have.
    """
    k8s = {"v1/Secret/default/s": {"kind": "Secret", "data": {}}}
    value = extract(_finding("v1/Secret/default/s"), {}, k8s)
    assert value.state is FactorState.UNRESOLVED
    assert value.level != 3


def test_a_kubernetes_non_secret_kind_scores_zero() -> None:
    k8s = {"v1/Service/default/svc": {"kind": "Service", "spec": {}}}
    value = extract(_finding("v1/Service/default/svc"), {}, k8s)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)
