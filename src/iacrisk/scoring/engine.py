"""The scoring engine: six factors to a score, a band, and an explanation.

What this module enforces rather than invents. `rubric.json` already carries the formula,
the frozen 1-28 bounds, the four bands with their remediation actions, and the per-scanner
severity table. `rubric.band_for` already validates and raises outside the bounds. The
engine applies them; it defines no threshold of its own.

Two traps the handoffs record and this module is where they would bite:

* `NormalizedFinding.severity_level` is `int | str`, where the string is the explicit
  `unknown` state (S1 handoff item 5, S3a handoff item 2). `severity_factor` converts it
  **once, at this boundary**, so the six addends are uniform `FactorValue`s and no call
  site can concatenate a string into a total. Note that `severity_level` is **already
  normalized by S3a** - measured over the committed fixtures, 566 integers over values
  2-5 and 489 `'unknown'`, with zero mismatches against `rubric.normalize_severity`. This
  module must not re-normalize it.
* Every addend is a `scored_level`, never a `FactorValue.level`. `level` is `int | None`
  and is public; `scored_level` is total.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache

from iacrisk import rubric
from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorState, FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.factor_map import is_factor_gap

__all__ = ["FACTOR_ORDER", "ScoredFinding", "score", "score_all", "severity_factor"]

FACTOR_ORDER = ("severity", "exposure", "privilege", "sensitivity", "criticality", "encryption")
"""The rubric's formula order, and the single source of factor order for every consumer."""

UNMAPPED_PREFIX = "unmapped:"


@lru_cache(maxsize=1)
def _band_actions() -> Mapping[str, str]:
    return {band.name: band.action for band in rubric.bands()}


def severity_factor(finding: NormalizedFinding) -> FactorValue:
    """`finding.severity_level` as a `FactorValue`, converted once at the boundary.

    An integer becomes a resolved value; the `unknown` string becomes an unresolved one,
    which scores the rubric's documented default of 4 rather than being dropped or read as
    safe.
    """
    level = finding.severity_level
    if isinstance(level, int) and not isinstance(level, bool):
        return FactorValue.resolved(
            "severity", level, f"{finding.scanner} severity normalized to {level}"
        )
    return FactorValue.unresolved(
        "severity",
        f"{finding.scanner} supplied no severity ({level!r}); scored at the rubric default",
    )


@dataclass(frozen=True, slots=True)
class ScoredFinding:
    contextualized: ContextualizedFinding
    severity: FactorValue
    contributions: Mapping[str, int]
    score: int
    band: str
    action: str
    factor_gap: bool
    unmapped: bool
    baseline_only_informational: bool
    weighted: bool
    explanation: tuple[str, ...]

    @property
    def finding(self) -> NormalizedFinding:
        return self.contextualized.finding

    @property
    def low_confidence(self) -> bool:
        """Carried from layer 3's frozen threshold of 3, not recomputed here."""
        return self.contextualized.low_confidence


def _explain(value: FactorValue) -> str:
    if value.state is FactorState.RESOLVED:
        return f"{value.key}: {value.scored_level} (resolved) - {value.evidence}"
    return (
        f"{value.key}: {value.scored_level} ({value.state.value}, the rubric default) "
        f"- {value.evidence}"
    )


def score(
    contextualized: ContextualizedFinding,
    weights: Mapping[str, int] | None = None,
) -> ScoredFinding:
    """Score one contextualized finding.

    `weights` exists so S5's sensitivity analysis need not fork this engine, which would
    risk the analysed model drifting from the scored one. It defaults to all ones - the
    frozen primary model - and anything else sets `weighted`, which every report-producing
    path rejects (spec section 4.4).
    """
    finding = contextualized.finding
    severity = severity_factor(finding)

    present: list[FactorValue] = [severity]
    if contextualized.factors:
        for key in FACTOR_ORDER[1:]:
            value = getattr(contextualized, key)
            assert value is not None, f"{key} missing on a context-eligible finding"
            present.append(value)

    effective = {key: 1 for key in FACTOR_ORDER}
    if weights:
        effective.update(weights)
    is_weighted = any(value != 1 for value in effective.values())

    contributions = {v.key: v.scored_level * effective[v.key] for v in present}
    total = sum(contributions.values())

    minimum, maximum = rubric.score_bounds()
    if not is_weighted and not minimum <= total <= maximum:
        # Six in-range factors cannot sum outside the bounds, so this means a factor was
        # out of range or a weight crept in. Asserted rather than trusted.
        raise AssertionError(
            f"unweighted score {total} is outside the frozen bounds {minimum}-{maximum} "
            f"for {finding.resource_identity}"
        )

    band = rubric.band_for(total)
    issue_class = finding.issue_class
    unmapped = issue_class.startswith(UNMAPPED_PREFIX)
    try:
        gap = is_factor_gap(issue_class)
    except KeyError:
        # An `unmapped:` class has no table entry by design. It is tracked by `unmapped`
        # instead: PLAN Q7 excludes those from prioritization-quality claims, while spec
        # section 2.3 deliberately does not exclude factor-gap findings.
        gap = False

    return ScoredFinding(
        contextualized=contextualized,
        severity=severity,
        contributions=contributions,
        score=total,
        band=band,
        action=_band_actions()[band],
        factor_gap=gap,
        unmapped=unmapped,
        baseline_only_informational=not contextualized.factors,
        weighted=is_weighted,
        explanation=tuple(_explain(v) for v in present),
    )


def score_all(
    contextualized: Iterable[ContextualizedFinding],
    weights: Mapping[str, int] | None = None,
) -> list[ScoredFinding]:
    return [score(c, weights) for c in contextualized]
