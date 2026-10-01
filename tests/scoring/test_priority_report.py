import json

from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.engine import ScoredFinding, score
from iacrisk.scoring.report import build, to_json

BANDS = {"Critical", "High", "Medium", "Low"}


def _scored(
    *,
    target: int = 20,
    issue_class: str = "storage-encryption-at-rest",
    identity: str = "aws_s3_bucket.b",
    unresolved: tuple[str, ...] = (),
    severity_unknown: bool = False,
) -> ScoredFinding:
    assert 1 <= target <= 28
    remainder = target - 1
    severity_extra = min(4, remainder)
    remainder -= severity_extra
    caps = {"exposure": 5, "privilege": 5, "sensitivity": 5, "criticality": 5, "encryption": 3}
    levels: dict[str, int] = {}
    for key, cap in caps.items():
        take = min(cap, remainder)
        levels[key] = take
        remainder -= take

    finding = NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level="unknown" if severity_unknown else 1 + severity_extra,
        platform="terraform",
        resource_identity=identity,
        identity_kind="terraform",
        file_path="x.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )

    def fv(key: str) -> FactorValue:
        if key in unresolved:
            return FactorValue.unresolved(key, "t")
        return FactorValue.resolved(key, levels[key], "t")

    ctx = ContextualizedFinding(
        finding=finding,
        exposure=fv("exposure"),
        privilege=fv("privilege"),
        sensitivity=fv("sensitivity"),
        criticality=fv("criticality"),
        encryption=fv("encryption"),
    )
    return score(ctx)


def test_all_four_band_keys_are_present_even_at_zero() -> None:
    report = build([_scored(target=20)])
    assert set(report.overall) == BANDS
    assert report.overall["High"] == 1
    assert report.overall["Low"] == 0


def test_all_six_defaulted_count_keys_are_present() -> None:
    report = build([_scored(target=20)])
    assert sorted(report.by_defaulted_count) == [0, 1, 2, 3, 4, 5]
    assert set(report.by_defaulted_count[0]) == BANDS


def test_the_defaulted_count_split_counts_an_unknown_severity_too() -> None:
    """severity is one of the six factors, so an unknown severity is a missing factor like
    any other - omitting it would understate the split the coherence rule asks for.
    """
    report = build([_scored(target=20, severity_unknown=True, unresolved=("exposure",))])
    assert sum(report.by_defaulted_count[2].values()) == 1


def test_the_three_gap_views_are_reported_separately() -> None:
    """Spec section 1.4 splits 434 gap findings into 178 self-declared-minor and 256
    substantive. One number would overstate the limitation by nearly double.
    """
    report = build(
        [
            _scored(issue_class="storage-encryption-at-rest"),  # not a gap
            _scored(issue_class="containers-image-supply-chain"),  # substantive gap
            _scored(issue_class="containers-workload-reliability"),  # self-declared minor gap
        ]
    )
    assert sum(report.including_factor_gap.values()) == 3
    assert sum(report.excluding_substantive_gap.values()) == 2
    assert sum(report.excluding_all_gap.values()) == 1
    assert report.factor_gap_count == 2
    assert report.substantive_gap_count == 1


def test_the_contingency_table_is_counts_only() -> None:
    report = build([_scored(target=20), _scored(target=20, identity="aws_s3_bucket.c")])
    assert all(isinstance(v, int) for v in report.framework_vs_baseline.values())
    assert sum(report.framework_vs_baseline.values()) == 2


def test_per_factor_contribution_shows_a_near_constant_column() -> None:
    """Spec section 1.2 made visible: a factor unresolved on almost everything contributes
    a flat default, which this column is what exposes.
    """
    report = build([_scored(target=20, unresolved=("exposure",)) for _ in range(10)])
    exposure = report.per_factor["exposure"]
    assert exposure.defaulted_or_unresolved == 10
    assert exposure.resolved == 0
    assert exposure.distribution == {3: 10}


def test_per_factor_covers_all_six_factors_even_with_no_findings() -> None:
    report = build([])
    assert set(report.per_factor) == {
        "severity",
        "exposure",
        "privilege",
        "sensitivity",
        "criticality",
        "encryption",
    }
    assert report.total == 0


def test_low_confidence_and_weighted_counts_are_reported() -> None:
    report = build([_scored(unresolved=("exposure", "privilege", "encryption")), _scored()])
    assert report.low_confidence_count == 1
    assert report.weighted_count == 0


def test_to_json_is_serialisable_with_string_keys() -> None:
    payload = to_json(build([_scored(target=20)]))
    json.dumps(payload)
    assert sorted(payload["by_defaulted_count"]) == ["0", "1", "2", "3", "4", "5"]
    assert all("|" in key for key in payload["framework_vs_baseline"])
    assert set(payload["per_factor"]) == {
        "severity",
        "exposure",
        "privilege",
        "sensitivity",
        "criticality",
        "encryption",
    }
