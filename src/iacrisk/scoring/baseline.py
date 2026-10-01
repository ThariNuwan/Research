"""The severity-normalized baseline: raw scanner severity mapped into the same four bands.

PLAN Q7's baseline is raw scanner severity. Without the rubric's per-scanner normalization
table that comparison would measure tool convention as much as prioritization, because the
three scanners assign severity by different conventions and checkov assigns none at all in
this corpus.

**The baseline is a band assignment, not a score** (spec §6.1). A 1-5 severity cannot be
banded against the framework's 1-28 ceiling, and scaling it there would invent precision the
scanner never supplied - and would flatter the framework by comparison. This module therefore
exposes no score function, only a band.

`unknown` severity bands through the rubric's own `unknown_resolves_to` of 4, i.e. High, and
`baseline_coverage` reports that rate separately because **489 of 1,055 corpus findings reach
the baseline by that route**. A reader must know the baseline's own coverage before comparing
against it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache

from iacrisk import rubric
from iacrisk.finding import NormalizedFinding

__all__ = ["SEVERITY_BAND_MAP", "BaselineCoverage", "baseline_band", "baseline_coverage"]

SEVERITY_BAND_MAP: Mapping[int, str] = {
    5: "Critical",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Low",
}
"""Normalized severity level to band, committed and cited wherever a baseline figure appears.

Levels 1 and 2 both map to Low because the four bands are coarser than the five levels; that
is a property of the band structure, not a loss of information the baseline had.
"""


@dataclass(frozen=True, slots=True)
class BaselineCoverage:
    total: int
    from_unknown: int
    per_band: Mapping[str, int]


@lru_cache(maxsize=1)
def _unknown_level() -> int:
    return int(rubric.severity_normalization()["unknown_resolves_to"])


def baseline_band(finding: NormalizedFinding) -> str:
    """The baseline band for one finding. KeyError on a level outside 1-5.

    Raising rather than clamping is deliberate: a level outside the rubric's own scale means
    the normalization table and this map have drifted apart, which is a defect to surface
    rather than a value to guess at.
    """
    level = finding.severity_level
    if not isinstance(level, int) or isinstance(level, bool):
        level = _unknown_level()
    return SEVERITY_BAND_MAP[level]


def baseline_coverage(findings: Iterable[NormalizedFinding]) -> BaselineCoverage:
    """Band counts plus the share that reached a band through the `unknown` route."""
    per_band = {band.name: 0 for band in rubric.bands()}
    total = 0
    from_unknown = 0
    for finding in findings:
        total += 1
        level = finding.severity_level
        if not isinstance(level, int) or isinstance(level, bool):
            from_unknown += 1
        per_band[baseline_band(finding)] += 1
    return BaselineCoverage(total=total, from_unknown=from_unknown, per_band=per_band)
