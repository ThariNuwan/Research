from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorState, FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.engine import FACTOR_ORDER, score, severity_factor


def _finding(
    severity: int | str = 3,
    *,
    issue_class: str = "storage-encryption-at-rest",
    eligible: bool = True,
) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
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
        context_eligible=eligible,
    )


def _ctx(finding: NormalizedFinding, **levels: int | None) -> ContextualizedFinding:
    def fv(key: str) -> FactorValue | None:
        if key not in levels:
            return None
        value = levels[key]
        if value is None:
            return FactorValue.unresolved(key, f"{key} unresolved in test")
        return FactorValue.resolved(key, value, f"{key}={value} in test")

    return ContextualizedFinding(
        finding=finding,
        exposure=fv("exposure"),
        privilege=fv("privilege"),
        sensitivity=fv("sensitivity"),
        criticality=fv("criticality"),
        encryption=fv("encryption"),
    )


def _full(finding: NormalizedFinding, **levels: int | None) -> ContextualizedFinding:
    """A contextualized finding carrying all five factors, defaulting to 1 each."""
    base: dict[str, int | None] = {
        "exposure": 1,
        "privilege": 1,
        "sensitivity": 1,
        "criticality": 1,
        "encryption": 1,
    }
    base.update(levels)
    return _ctx(finding, **base)


def test_the_factor_order_is_the_rubrics_formula_order() -> None:
    assert FACTOR_ORDER == (
        "severity",
        "exposure",
        "privilege",
        "sensitivity",
        "criticality",
        "encryption",
    )


def test_an_integer_severity_becomes_a_resolved_factor_value() -> None:
    value = severity_factor(_finding(5))
    assert (value.state, value.level, value.scored_level) == (FactorState.RESOLVED, 5, 5)


def test_an_unknown_severity_becomes_an_unresolved_factor_value_scoring_four() -> None:
    """severity_level is ALREADY normalized by S3a and is `int | str`, the trap both the
    S1 and S3a handoffs record. Converting once at this boundary is what stops a string
    reaching six call sites.
    """
    value = severity_factor(_finding("unknown"))
    assert value.state is FactorState.UNRESOLVED
    assert value.level is None
    assert value.scored_level == 4


def test_the_score_is_the_sum_of_six_contributions() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert scored.contributions == {
        "severity": 3,
        "exposure": 4,
        "privilege": 2,
        "sensitivity": 5,
        "criticality": 4,
        "encryption": 1,
    }
    assert scored.score == 19
    assert sum(scored.contributions.values()) == scored.score


def test_the_band_and_action_come_from_the_rubric() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert scored.band == "High"
    assert scored.action == "Fix before production / require approval"


def test_an_all_unresolved_finding_still_scores_and_lands_in_high() -> None:
    """Spec section 1.1's washout, asserted rather than described: the five context
    defaults sum to 16 and unknown severity resolves to 4, so this lands on exactly 20.
    """
    scored = score(
        _ctx(
            _finding("unknown"),
            exposure=None,
            privilege=None,
            sensitivity=None,
            criticality=None,
            encryption=None,
        )
    )
    assert scored.score == 20
    assert scored.band == "High"


def test_the_minimum_and_maximum_attainable_scores_are_the_frozen_bounds() -> None:
    low = score(
        _ctx(_finding(1), exposure=0, privilege=0, sensitivity=0, criticality=0, encryption=0)
    )
    high = score(
        _ctx(_finding(5), exposure=5, privilege=5, sensitivity=5, criticality=5, encryption=3)
    )
    assert (low.score, low.band) == (1, "Low")
    assert (high.score, high.band) == (28, "Critical")


def test_every_scored_finding_carries_one_explanation_line_per_factor() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert len(scored.explanation) == 6
    for key in FACTOR_ORDER:
        assert any(line.startswith(key) for line in scored.explanation), key
    assert all(line.strip() for line in scored.explanation)


def test_an_unresolved_factor_says_so_in_its_explanation_line() -> None:
    scored = score(
        _ctx(_finding(3), exposure=None, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    exposure_line = next(line for line in scored.explanation if line.startswith("exposure"))
    assert "unresolved" in exposure_line
    assert "3" in exposure_line  # the default it scored


def test_a_context_ineligible_finding_scores_on_severity_alone() -> None:
    """Spec section 3.3. Defaulting its five factors would re-open the washout that
    `context_eligible` exists to close.
    """
    scored = score(_ctx(_finding(4, eligible=False)))
    assert scored.contributions == {"severity": 4}
    assert scored.score == 4
    assert scored.band == "Low"
    assert scored.baseline_only_informational is True
    assert len(scored.explanation) == 1


def test_the_factor_gap_marker_is_derived_from_the_table() -> None:
    gap = score(_full(_finding(3, issue_class="containers-image-supply-chain")))
    not_gap = score(_full(_finding(3, issue_class="storage-encryption-at-rest")))
    assert gap.factor_gap is True
    assert not_gap.factor_gap is False


def test_an_unmapped_class_is_not_marked_a_factor_gap() -> None:
    """Two different exclusions: PLAN Q7 excludes `unmapped:` from quality claims, while
    spec section 2.3 deliberately does not exclude factor-gap findings. Conflating them
    would make one of the two reports impossible.
    """
    scored = score(_full(_finding(3, issue_class="unmapped:checkov:CKV_AWS_62")))
    assert scored.factor_gap is False
    assert scored.unmapped is True


def test_a_weight_map_other_than_all_ones_is_marked_weighted() -> None:
    """Spec section 4.4: weights exist so S5's sensitivity analysis need not fork the
    engine, and the frozen primary model must not silently become weighted.
    """
    ctx = _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    weighted = score(ctx, weights={"exposure": 2})
    assert weighted.score != 19
    assert weighted.weighted is True
    assert score(ctx).weighted is False


def test_an_all_ones_weight_map_is_not_marked_weighted() -> None:
    """Passing explicit ones is the frozen model, not a weighted variant."""
    ctx = _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    explicit = score(ctx, weights=dict.fromkeys(FACTOR_ORDER, 1))
    assert explicit.weighted is False
    assert explicit.score == 19


def test_low_confidence_is_carried_through_from_layer_three() -> None:
    scored = score(
        _ctx(
            _finding(3),
            exposure=None,
            privilege=None,
            sensitivity=None,
            criticality=1,
            encryption=1,
        )
    )
    assert scored.low_confidence is True
    assert score(_full(_finding(3))).low_confidence is False
