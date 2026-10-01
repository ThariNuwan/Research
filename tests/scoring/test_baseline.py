from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.baseline import SEVERITY_BAND_MAP, baseline_band, baseline_coverage


def _finding(severity: int | str) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class="storage-encryption-at-rest",
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=severity,
        platform="terraform",
        resource_identity="aws_s3_bucket.b",
        identity_kind="terraform",
        file_path="x.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )


def test_the_map_covers_every_level_the_rubric_defines() -> None:
    """The rubric's token_scale is CRITICAL 5, HIGH 4, MEDIUM 3, LOW 2, NONE 1, so the
    baseline map must cover 1-5 with no gap - a missing level would silently drop findings
    out of the comparison.
    """
    assert SEVERITY_BAND_MAP == {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Low"}


def test_each_severity_bands_as_the_committed_map_says() -> None:
    assert baseline_band(_finding(5)) == "Critical"
    assert baseline_band(_finding(4)) == "High"
    assert baseline_band(_finding(3)) == "Medium"
    assert baseline_band(_finding(2)) == "Low"
    assert baseline_band(_finding(1)) == "Low"


def test_an_unknown_severity_bands_through_the_rubrics_unknown_resolution() -> None:
    """unknown_resolves_to is 4, so High - and the rate is reported separately because
    489 of 1055 corpus findings reach the baseline this way.
    """
    assert baseline_band(_finding("unknown")) == "High"


def test_the_baseline_is_a_band_not_a_score() -> None:
    """Spec section 6.1. A 1-5 severity cannot be banded against a 1-28 ceiling, and
    scaling it there would invent precision the scanner never supplied. The module
    therefore exposes no score function at all.
    """
    import iacrisk.scoring.baseline as module

    assert not hasattr(module, "baseline_score")
    assert all(isinstance(v, str) for v in SEVERITY_BAND_MAP.values())


def test_coverage_reports_the_unknown_rate_separately_from_the_bands() -> None:
    coverage = baseline_coverage([_finding(5), _finding("unknown"), _finding("unknown")])
    assert coverage.total == 3
    assert coverage.from_unknown == 2
    assert coverage.per_band["Critical"] == 1
    assert coverage.per_band["High"] == 2


def test_every_band_key_is_present_even_at_zero() -> None:
    """An absent band is indistinguishable from an unmeasured one."""
    coverage = baseline_coverage([_finding(5)])
    assert set(coverage.per_band) == {"Critical", "High", "Medium", "Low"}
    assert coverage.per_band["Low"] == 0


def test_an_empty_input_reports_zeroes_rather_than_an_empty_report() -> None:
    coverage = baseline_coverage([])
    assert coverage.total == 0
    assert coverage.from_unknown == 0
    assert set(coverage.per_band) == {"Critical", "High", "Medium", "Low"}


def test_an_out_of_range_severity_is_a_hard_error_not_a_guess() -> None:
    import pytest

    with pytest.raises(KeyError):
        baseline_band(_finding(9))
