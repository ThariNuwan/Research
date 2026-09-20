"""The baseline is only comparable across scanners if the tokens normalize (PLAN Q7 #5).

The load-bearing case is `unknown`. Trivy's fifth level is UNKNOWN - severity
undetermined, NOT a benign informational band - and 489 of corpus v0's 1055 rows
carry no severity at all, every one of them Checkov. Both route to the explicit
unknown state and take the conservative default of 4. Neither is ever scored low:
that is the exact failure the phase0 review warned about.
"""

from __future__ import annotations

import pytest

from iacrisk import rubric

SCANNERS = ["checkov", "trivy", "tfsec"]


@pytest.mark.parametrize(
    ("token", "level"),
    [("CRITICAL", 5), ("HIGH", 4), ("MEDIUM", 3), ("LOW", 2), ("NONE", 1)],
)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_every_scale_token_maps_to_its_frozen_level(scanner: str, token: str, level: int) -> None:
    """Spec section 3.3: CRITICAL 5, HIGH 4, MEDIUM 3, LOW 2, CVSS None 1."""
    assert rubric.normalize_severity(scanner, token) == level


@pytest.mark.parametrize("raw", ["critical", " Critical ", "CrItIcAl"])
def test_token_matching_is_case_and_whitespace_insensitive(raw: str) -> None:
    """Scanners are not required to agree on casing; the table should not care."""
    assert rubric.normalize_severity("trivy", raw) == 5


def test_trivy_unknown_is_severity_undetermined_not_informational() -> None:
    """The grave correction from the verification pass (spec section 3.4).

    Trivy's fifth level is UNKNOWN. Reading it as the CVSS None band and scoring
    it 1 would treat a severity the scanner could not determine as nearly benign.
    """
    assert rubric.normalize_severity("trivy", "UNKNOWN") == rubric.UNKNOWN


def test_checkov_null_severity_routes_to_unknown() -> None:
    """46.4% of corpus v0. Severity reaches Checkov's JSON only via the API-key path."""
    assert rubric.normalize_severity("checkov", None) == rubric.UNKNOWN


@pytest.mark.parametrize("token", ["", "   ", "SEVERE", "P1", "informational"])
def test_an_unrecognised_token_is_unknown_never_a_guess(token: str) -> None:
    """Explicit-state discipline: a token the table does not know is named, not mapped."""
    assert rubric.normalize_severity("trivy", token) == rubric.UNKNOWN


def test_an_unrecognised_scanner_is_unknown_never_a_guess() -> None:
    """A scanner outside the pinned three cannot have a verified token vocabulary."""
    assert rubric.normalize_severity("snyk", "HIGH") == rubric.UNKNOWN


def test_unknown_resolves_to_the_severity_factor_default() -> None:
    """One source of truth: the table's routing and the factor's default must agree."""
    table = rubric.severity_normalization()

    assert table["unknown_resolves_to"] == rubric.unresolved_default("severity") == 4


def test_unknown_is_never_scored_below_an_observed_low() -> None:
    """PLAN Q9 at the severity seam, stated as a property.

    An undetermined severity must never rank below a scanner-asserted LOW; that
    is the false-reassurance failure mode the framework exists to prevent.
    """
    low = rubric.normalize_severity("trivy", "LOW")
    resolved_unknown = rubric.severity_normalization()["unknown_resolves_to"]

    assert isinstance(low, int)
    assert resolved_unknown > low


def test_the_reserved_none_band_is_recorded_as_unexercised() -> None:
    """Level 1 exists so the scale need not shift later; corpus v0 never hits it."""
    table = rubric.severity_normalization()

    assert table["reserved_unexercised"] == ["NONE"]


def test_the_recorded_corpus_measurement_matches_the_harvest() -> None:
    """Spec section 0: these are corpus v0 observations, and they must stay honest."""
    corpus = rubric.severity_normalization()["corpus_v0"]

    assert corpus["rows"] == 1055
    assert corpus["missing_severity_rows"] == 489
    assert corpus["all_missing_are_checkov"] is True


@pytest.mark.parametrize("scanner", SCANNERS)
def test_every_pinned_scanner_has_a_recorded_vocabulary(scanner: str) -> None:
    """The per-scanner block is what lets the unknown rate be reported per scanner."""
    per_scanner = rubric.severity_normalization()["per_scanner"]

    assert scanner in per_scanner
    assert "observed_in_corpus_v0" in per_scanner[scanner]
