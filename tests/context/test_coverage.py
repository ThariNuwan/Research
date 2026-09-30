import json
from pathlib import Path

from iacrisk import taxonomy
from iacrisk.context.coverage import build, to_json
from iacrisk.context.extract import contextualize
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def _finding(
    identity: str, issue_class: str = "storage-encryption-at-rest", *, eligible: bool = True
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


def test_the_resolution_distribution_has_every_key_from_zero_to_five() -> None:
    """An absent key is indistinguishable from an unmeasured one."""
    results = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    coverage = build(results)
    assert sorted(coverage.resolution_distribution) == [0, 1, 2, 3, 4, 5]


def test_per_factor_rates_are_separate_and_split_by_provenance() -> None:
    """PLAN Q4's missing-declared-value and PLAN Q9's extractor-failure are separate
    reports, and merging them makes the split impossible to reconstruct afterwards.
    """
    results = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    coverage = build(results)
    assert set(coverage.per_factor_defaulted) == {"sensitivity", "criticality"}
    assert set(coverage.per_factor_unresolved) == {"exposure", "privilege", "encryption"}
    assert coverage.per_factor_defaulted == {"sensitivity": 1, "criticality": 1}
    assert coverage.per_factor_unresolved == {"exposure": 1, "privilege": 1, "encryption": 1}


def test_every_taxonomy_class_appears_even_with_no_findings() -> None:
    """Spec section 8.4: S4 rules on the three classes that map to no rubric factor from
    this report, and a class missing from it reads as a class with no findings.
    """
    coverage = build([])
    assert set(coverage.per_class_coverage) == set(taxonomy.classes())
    assert len(coverage.per_class_coverage) == 28
    assert all(entry.findings == 0 for entry in coverage.per_class_coverage.values())


def test_an_unmapped_class_is_counted_under_its_own_key_not_dropped() -> None:
    results = contextualize(
        [_finding("aws_ebs_volume.absent", "unmapped:checkov:CKV_AWS_62")], {}, {}
    )
    coverage = build(results)
    assert coverage.per_class_coverage["unmapped:checkov:CKV_AWS_62"].findings == 1
    assert sum(e.findings for e in coverage.per_class_coverage.values()) == 1


def test_context_ineligible_findings_are_excluded_from_the_distribution_but_counted() -> None:
    results = contextualize(
        [_finding("aws_s3_bucket.x", eligible=False), _finding("aws_ebs_volume.absent")], {}, {}
    )
    coverage = build(results)
    assert coverage.ineligible == 1
    assert coverage.eligible == 1
    assert sum(coverage.resolution_distribution.values()) == 1


def test_a_fully_resolved_finding_lands_in_the_zero_bucket() -> None:
    declared = {"aws_db_instance.default": {"sensitivity": 4, "criticality": 4}}
    results = contextualize([_finding("aws_db_instance.default")], declared, _terragoat())
    coverage = build(results)
    # Assert zero explicitly. An earlier version computed `missing` from the result under
    # test and asserted the distribution at that index, which stays green under any
    # regression while the test's name becomes false.
    assert results[0].defaulted_factors == ()
    assert results[0].unresolved_factors == ()
    assert coverage.resolution_distribution[0] == 1
    assert coverage.fully_resolved == 1


def test_the_low_confidence_count_uses_the_frozen_threshold() -> None:
    results = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    coverage = build(results)
    assert coverage.low_confidence_count == 1


def test_per_class_coverage_accumulates_resolved_over_possible() -> None:
    declared = {"aws_db_instance.default": {"sensitivity": 4, "criticality": 4}}
    results = contextualize(
        [
            _finding("aws_db_instance.default", "storage-encryption-at-rest"),
            _finding("aws_db_instance.default", "storage-encryption-at-rest"),
        ],
        declared,
        _terragoat(),
    )
    coverage = build(results)
    entry = coverage.per_class_coverage["storage-encryption-at-rest"]
    assert entry.findings == 2
    assert entry.possible_factors == 10
    assert 0 < entry.resolved_factors <= entry.possible_factors


def test_to_json_is_serialisable_with_string_keys() -> None:
    coverage = build(contextualize([_finding("aws_ebs_volume.absent")], {}, {}))
    payload = to_json(coverage)
    json.dumps(payload)  # must not raise
    assert sorted(payload["resolution_distribution"]) == ["0", "1", "2", "3", "4", "5"]
    assert len(payload["per_class_coverage"]) == 28
