"""The rubric is frozen at the end of S1 and mirrored verbatim in the dissertation.

Every number here is fixed a priori from the score structure (spec section 0).
These tests are the freeze: later movement of a range, a band, or an unresolved
default has to break a test and be reported as sensitivity analysis (PLAN Q10),
not slipped in to fit the data.
"""

from __future__ import annotations

import pytest

from iacrisk import rubric

# Factor key -> (minimum, maximum, unresolved default, unresolved policy).
# Spec section 3.2, reproduced as the freeze.
EXPECTED_FACTORS = {
    "severity": (1, 5, 4, "conservative-scored"),
    "exposure": (0, 5, 3, "sensitivity-analysed"),
    "privilege": (0, 5, 4, "conservative-scored"),
    "sensitivity": (0, 5, 3, "conservative-scored"),
    "criticality": (0, 5, 4, "conservative-scored"),
    "encryption": (0, 3, 2, "conservative-scored"),
}

# The standards the spec section 3 anchors name. A level whose source cites none
# of these is unanchored, which is the section 3.6 gate's failure mode.
ANCHORS = ("CVSS", "NIST", "NSA", "OWASP", "FIPS")


def test_the_six_factors_are_exactly_the_model_terms() -> None:
    """Six factors, no more: a seventh term would move the score ceiling."""
    assert tuple(EXPECTED_FACTORS) == rubric.FACTOR_KEYS
    assert set(rubric.factors()) == set(EXPECTED_FACTORS)


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_factor_range_matches_the_frozen_model(key: str) -> None:
    """Ranges are frozen: Severity 1-5, four context factors 0-5, Encryption 0-3."""
    minimum, maximum, _, _ = EXPECTED_FACTORS[key]
    factor = rubric.factors()[key]

    assert (factor.minimum, factor.maximum) == (minimum, maximum)


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_every_score_point_in_the_range_has_exactly_one_level(key: str) -> None:
    """A gap or a duplicate would make a score point unjustifiable (spec 3.6)."""
    minimum, maximum, _, _ = EXPECTED_FACTORS[key]
    scores = [level.score for level in rubric.factors()[key].levels]

    assert scores == list(range(minimum, maximum + 1))


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_every_level_is_source_anchored_and_justified(key: str) -> None:
    """Spec section 3.6: every score point cites a standard and says why.

    The 8-agent verification pass (spec 3.1) found no fabricated standard; this
    test is what stops one being introduced later.
    """
    for level in rubric.factors()[key].levels:
        assert level.meaning.strip(), f"{key} level {level.score} has no meaning"
        assert level.justification.strip(), f"{key} level {level.score} has no justification"
        assert any(anchor in level.source for anchor in ANCHORS), (
            f"{key} level {level.score} cites no recognised standard: {level.source!r}"
        )


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_unresolved_default_and_policy_match_the_spec(key: str) -> None:
    """Spec section 3.2, verified against PLAN Q9's never-silently-low rule."""
    _, _, default, policy = EXPECTED_FACTORS[key]
    factor = rubric.factors()[key]

    assert factor.unresolved_default == default
    assert factor.unresolved_policy == policy
    assert rubric.unresolved_default(key) == default
    assert factor.unresolved_rationale.strip(), f"{key} default has no recorded rationale"


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_no_unresolved_default_sits_in_the_bottom_half_of_its_range(key: str) -> None:
    """PLAN Q9: unresolved is never silently scored low.

    Stated as a property rather than a restatement of the six numbers, so it
    still bites if a default is ever revised downward.
    """
    factor = rubric.factors()[key]
    midpoint = (factor.minimum + factor.maximum) / 2

    assert factor.unresolved_default > midpoint, (
        f"{key} unresolved default {factor.unresolved_default} is not above the "
        f"midpoint of {factor.minimum}..{factor.maximum}"
    )


def test_only_exposure_carries_a_sensitivity_sweep() -> None:
    """Spec section 3.2: Q9 names exposure as the factor a fixed default distorts."""
    assert rubric.factors()["exposure"].sensitivity_sweep == (2, 5)
    for key in EXPECTED_FACTORS:
        if key != "exposure":
            assert rubric.factors()[key].sensitivity_sweep is None


def test_the_structural_freeze_and_the_citation_audit_are_separate_claims() -> None:
    """One flag covering both is how a real defect survived six reviews.

    The structure - six factors, their ranges, the 1-28 bounds, the bands - was
    fixed before any scoring output existed and is pinned by computation, so it
    is genuinely frozen. The per-level source strings are a different claim with
    different evidence: the verification pass's corrections lived in spec prose
    and did not reach this artifact, and nothing caught it because every check
    compared the artifact to a design input carrying the same uncorrected text.

    So the two are asserted separately, and this test is what stops them being
    merged back into a single reassuring boolean. `citations_audited` flips only
    when an independent re-verification against the primary sources is
    committed - not when the suite is green, because no test here can read a
    standard.
    """
    assert rubric.structure_frozen() is True
    assert rubric.citations_audited() is False, (
        "citations_audited is True - if an audit was genuinely committed, update this "
        "test and cite it; if not, the flag is overclaiming"
    )


def test_only_exposure_carries_a_precedence_rule() -> None:
    """Spec section 3.4: a `0.0.0.0/0` opening forces exposure to at least 4.

    Carried on the factor rather than left in spec prose, so S3 cannot reinvent
    it - the same discipline that puts the section 3.5 coherence rules in the
    artifact. No other factor has an override of this kind, and asserting that
    keeps one from being added without a decision.
    """
    exposure = rubric.factors()["exposure"]

    assert exposure.precedence_rule is not None
    assert "0.0.0.0/0" in exposure.precedence_rule
    assert "never across it" in exposure.precedence_rule

    for key, factor in rubric.factors().items():
        if key != "exposure":
            assert factor.precedence_rule is None, f"{key} gained an undeclared override"


def test_score_bounds_are_the_frozen_1_to_28() -> None:
    """Sum of the factor ranges. Changing any range must move this number."""
    assert rubric.score_bounds() == (1, 28)
    assert sum(f.minimum for f in rubric.factors().values()) == 1
    assert sum(f.maximum for f in rubric.factors().values()) == 28


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (28, "Critical"),
        (22, "Critical"),  # the flagship knife-edge: spec 4.4 flags it explicitly
        (21, "High"),
        (16, "High"),
        (15, "Medium"),
        (9, "Medium"),
        (8, "Low"),
        (1, "Low"),
    ],
)
def test_band_boundaries_are_frozen(score: int, band: str) -> None:
    """Critical >= 22, High 16-21, Medium 9-15, Low < 9 - fixed a priori."""
    assert rubric.band_for(score) == band


def test_bands_tile_the_whole_score_range_without_gap_or_overlap() -> None:
    """Every reachable score lands in exactly one band."""
    minimum, maximum = rubric.score_bounds()
    for score in range(minimum, maximum + 1):
        matches = [b.name for b in rubric.bands() if b.minimum <= score <= b.maximum]
        assert len(matches) == 1, f"score {score} matched bands {matches}"


@pytest.mark.parametrize("score", [0, 29])
def test_a_score_outside_the_model_is_rejected_not_silently_banded(score: int) -> None:
    """An out-of-range total means the caller broke the frozen model."""
    with pytest.raises(ValueError, match="outside the frozen model range"):
        rubric.band_for(score)


def test_the_model_is_equal_weighted_and_additive() -> None:
    """Spec section 3.6: the equal-weighted additive sum is the primary model."""
    model = rubric.model()

    assert model["equal_weighted"] is True
    assert "sensitivity analysis" in model["weighting"]
    assert model["formula"] == (
        "Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk"
    )


def test_class_id_is_not_a_term_in_the_score() -> None:
    """Spec section 3.5(3): the taxonomy dimension must never re-amplify exposure.

    The S1-level form of that assertion - the rubric declares six factors and
    none of them is class-derived. The runtime form, asserted over a computed
    score, belongs to S3 where a scoring function exists.
    """
    assert "class" not in " ".join(rubric.FACTOR_KEYS)
    for factor in rubric.factors().values():
        assert "class_id" not in factor.name
