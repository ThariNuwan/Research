"""Band distributions and the per-factor contribution summary.

Spec §7.2 and §7.3. Three reporting rules here are structural rather than stylistic, and each
exists because the combined figure would mislead:

* **Four distributions, none combined.** Overall; split by count-of-defaulted-or-unresolved
  factors, which is the `unresolved_default_reporting` coherence rule's obligation; the
  factor-gap views; and a framework-band x baseline-band contingency table of **counts only**
  - any claim about which ranking is better is S5's.
* **Three gap views, not two.** All findings, excluding the substantive gap, and excluding
  every gap. Spec §1.4 measures 434 gap findings splitting 178 self-declared-minor and 256
  substantive; reporting one number would overstate the limitation by nearly double.
* **Every key present even at zero** - all four bands, all six defaulted counts. An absent
  key is indistinguishable from an unmeasured one.

`per_factor` is what makes spec §1.2 visible. Exposure is unresolved on 91.1% of eligible
findings and contributes a flat 3 there, so it shows up here as a near-constant column and a
reader can see which factors are actually doing the ranking work.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from iacrisk import rubric
from iacrisk.scoring.baseline import baseline_band
from iacrisk.scoring.engine import FACTOR_ORDER, ScoredFinding
from iacrisk.scoring.factor_map import is_substantive_gap

__all__ = ["FactorContribution", "PriorityReport", "build", "to_json"]

_MAX_MISSING = 5


@dataclass(frozen=True, slots=True)
class FactorContribution:
    resolved: int
    defaulted_or_unresolved: int
    distribution: dict[int, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PriorityReport:
    total: int
    overall: dict[str, int]
    by_defaulted_count: dict[int, dict[str, int]]
    including_factor_gap: dict[str, int]
    excluding_substantive_gap: dict[str, int]
    excluding_all_gap: dict[str, int]
    framework_vs_baseline: dict[tuple[str, str], int]
    per_factor: dict[str, FactorContribution]
    low_confidence_count: int
    factor_gap_count: int
    substantive_gap_count: int
    weighted_count: int


def _empty_bands() -> dict[str, int]:
    return {band.name: 0 for band in rubric.bands()}


def _substantive(scored: ScoredFinding) -> bool:
    if not scored.factor_gap:
        return False
    try:
        return is_substantive_gap(scored.finding.issue_class)
    except KeyError:  # pragma: no cover - factor_gap is False for unmapped classes
        return False


def build(scored: Iterable[ScoredFinding]) -> PriorityReport:
    items: Sequence[ScoredFinding] = list(scored)

    overall = _empty_bands()
    by_count = {n: _empty_bands() for n in range(_MAX_MISSING + 1)}
    including = _empty_bands()
    excluding_substantive = _empty_bands()
    excluding_all = _empty_bands()
    contingency: dict[tuple[str, str], int] = {}
    resolved_counts = dict.fromkeys(FACTOR_ORDER, 0)
    default_counts = dict.fromkeys(FACTOR_ORDER, 0)
    distributions: dict[str, dict[int, int]] = {key: {} for key in FACTOR_ORDER}

    low_confidence = 0
    gap_total = 0
    substantive_total = 0
    weighted_total = 0

    for item in items:
        overall[item.band] += 1
        including[item.band] += 1

        missing = len(item.contextualized.defaulted_factors) + len(
            item.contextualized.unresolved_factors
        )
        if item.severity.level is None:
            missing += 1
        by_count[min(missing, _MAX_MISSING)][item.band] += 1

        if item.low_confidence:
            low_confidence += 1
        if item.weighted:
            weighted_total += 1

        if item.factor_gap:
            gap_total += 1
            if _substantive(item):
                substantive_total += 1
            else:
                excluding_substantive[item.band] += 1
        else:
            excluding_substantive[item.band] += 1
            excluding_all[item.band] += 1

        key = (item.band, baseline_band(item.finding))
        contingency[key] = contingency.get(key, 0) + 1

        for factor_key, contribution in item.contributions.items():
            value = (
                item.severity
                if factor_key == "severity"
                else getattr(item.contextualized, factor_key)
            )
            assert value is not None
            if value.level is None:
                default_counts[factor_key] += 1
            else:
                resolved_counts[factor_key] += 1
            distributions[factor_key][contribution] = (
                distributions[factor_key].get(contribution, 0) + 1
            )

    return PriorityReport(
        total=len(items),
        overall=overall,
        by_defaulted_count=by_count,
        including_factor_gap=including,
        excluding_substantive_gap=excluding_substantive,
        excluding_all_gap=excluding_all,
        framework_vs_baseline=contingency,
        per_factor={
            key: FactorContribution(
                resolved=resolved_counts[key],
                defaulted_or_unresolved=default_counts[key],
                distribution=dict(sorted(distributions[key].items())),
            )
            for key in FACTOR_ORDER
        },
        low_confidence_count=low_confidence,
        factor_gap_count=gap_total,
        substantive_gap_count=substantive_total,
        weighted_count=weighted_total,
    )


def to_json(report: PriorityReport) -> dict[str, Any]:
    """A JSON-serialisable form. Integer and tuple keys become strings, as JSON requires."""
    return {
        "total": report.total,
        "overall": dict(report.overall),
        "by_defaulted_count": {
            str(count): dict(bands) for count, bands in sorted(report.by_defaulted_count.items())
        },
        "including_factor_gap": dict(report.including_factor_gap),
        "excluding_substantive_gap": dict(report.excluding_substantive_gap),
        "excluding_all_gap": dict(report.excluding_all_gap),
        "framework_vs_baseline": {
            f"{framework}|{base}": count
            for (framework, base), count in sorted(report.framework_vs_baseline.items())
        },
        "per_factor": {
            key: {
                "resolved": entry.resolved,
                "defaulted_or_unresolved": entry.defaulted_or_unresolved,
                "distribution": {str(k): v for k, v in sorted(entry.distribution.items())},
            }
            for key, entry in report.per_factor.items()
        },
        "low_confidence_count": report.low_confidence_count,
        "factor_gap_count": report.factor_gap_count,
        "substantive_gap_count": report.substantive_gap_count,
        "weighted_count": report.weighted_count,
    }
