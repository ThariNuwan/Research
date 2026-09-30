from pathlib import Path

from iacrisk.context.extract import (
    CONTEXT_FACTOR_KEYS,
    LOW_CONFIDENCE_THRESHOLD,
    contextualize,
    defaulted_and_unresolved_are_disjoint,
)
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def _finding(
    identity: str, *, eligible: bool = True, issue_class: str = "storage-encryption-at-rest"
) -> NormalizedFinding:
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
        context_eligible=eligible,
    )


def _terragoat() -> dict[str, TerraformResource]:
    return build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)


def test_the_threshold_is_three_and_is_frozen() -> None:
    """Spec section 8.1, fixed 2026-09-30 before any scoring output existed. Later
    movement is reported as sensitivity analysis, never tuned to fit.
    """
    assert LOW_CONFIDENCE_THRESHOLD == 3


def test_there_are_exactly_five_context_factor_keys() -> None:
    assert CONTEXT_FACTOR_KEYS == (
        "exposure",
        "privilege",
        "sensitivity",
        "criticality",
        "encryption",
    )


def test_a_context_ineligible_finding_gets_no_context_block_at_all() -> None:
    """Not defaults, not unresolved markers - nothing. Defaulting these re-opens the
    washout S3a closed with context_eligible.
    """
    (result,) = contextualize([_finding("aws_s3_bucket.x", eligible=False)], {}, {})
    assert result.exposure is None
    assert result.privilege is None
    assert result.sensitivity is None
    assert result.criticality is None
    assert result.encryption is None
    assert result.factors == ()
    assert result.defaulted_factors == ()
    assert result.unresolved_factors == ()
    assert result.low_confidence is False


def test_an_eligible_finding_always_carries_all_five_factors() -> None:
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    assert len(result.factors) == 5
    assert {v.key for v in result.factors} == set(CONTEXT_FACTOR_KEYS)


def test_defaulted_and_unresolved_are_disjoint_and_split_by_provenance() -> None:
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    assert set(result.defaulted_factors) & set(result.unresolved_factors) == set()
    assert set(result.defaulted_factors) <= {"sensitivity", "criticality"}
    assert set(result.unresolved_factors) <= {"exposure", "privilege", "encryption"}
    assert defaulted_and_unresolved_are_disjoint([result])


def test_a_finding_with_nothing_resolved_is_low_confidence() -> None:
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    assert len(result.defaulted_factors) + len(result.unresolved_factors) == 5
    assert result.low_confidence is True


def test_declared_context_removes_both_factors_from_the_defaulted_list() -> None:
    declared = {"aws_ebs_volume.absent": {"sensitivity": 5, "criticality": 5}}
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], declared, {})
    assert result.defaulted_factors == ()
    assert result.sensitivity is not None and result.sensitivity.level == 5
    assert result.criticality is not None and result.criticality.level == 5


def test_a_fully_resolved_finding_is_not_low_confidence() -> None:
    """aws_db_instance.default resolves encryption from a literal storage_encrypted, and
    with declared context supplied only exposure and privilege can still be unresolved -
    two, which is below the threshold.
    """
    declared = {"aws_db_instance.default": {"sensitivity": 4, "criticality": 4}}
    (result,) = contextualize([_finding("aws_db_instance.default")], declared, _terragoat())
    assert result.defaulted_factors == ()
    assert len(result.unresolved_factors) < LOW_CONFIDENCE_THRESHOLD
    assert result.low_confidence is False


def test_the_orchestrator_preserves_input_order_and_count() -> None:
    findings = [
        _finding("aws_db_instance.default"),
        _finding("aws_s3_bucket.x", eligible=False),
        _finding("aws_ebs_volume.absent"),
    ]
    results = contextualize(findings, {}, _terragoat())
    assert len(results) == 3
    assert [r.finding.resource_identity for r in results] == [f.resource_identity for f in findings]


def test_the_orchestrator_never_mutates_the_input_findings() -> None:
    finding = _finding("aws_security_group_rule.egress")
    contextualize([finding], {}, _terragoat())
    assert finding.resource_identity == "aws_security_group_rule.egress"
    assert finding.issue_class == "storage-encryption-at-rest"
