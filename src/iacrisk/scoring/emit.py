"""JSON as the source of truth, and the human report as a view over it.

Spec §7.1 and §7.4. The ordering matters: S5's independent harness reads this JSON, so the
machine-readable form cannot be a lossy derivative of a document formatted for people.
`render_markdown` therefore takes **the payload**, not the dataclasses - which is what makes
the human report structurally incapable of disagreeing with the JSON.

Every explicit state survives into the payload: `low_confidence`, `factor_gap`,
`factor_gap_counted`, `unmapped`, `baseline_only_informational`, and a per-factor `state`
map. A consumer must be able to tell a resolved 3 from an unresolved one, because every S5
report depends on the difference.

**`factor_gap` and `factor_gap_counted` are both present on purpose, and summing the wrong
one is a reporting error.** `factor_gap` is a property of the issue class, so it is true even
for a context-ineligible finding that carries no context factors at all. `factor_gap_counted`
is membership of the population `report.build` counts, which excludes findings already
excluded as `baseline_only_informational`. Measured over corpus v0 the two differ: summing
`factor_gap` gives **446**, while the report's `factor_gap_count` is **434**. S5 should read
`factor_gap_counted`, or `report.factor_gap_count`, and not the raw flag.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from iacrisk.scoring.baseline import baseline_band
from iacrisk.scoring.engine import FACTOR_ORDER, ScoredFinding
from iacrisk.scoring.rank import RankedFinding
from iacrisk.scoring.report import PriorityReport
from iacrisk.scoring.report import to_json as report_to_json

__all__ = ["render_markdown", "to_json"]

_BAND_ORDER = ("Critical", "High", "Medium", "Low")


def _factor_states(scored: ScoredFinding) -> dict[str, str]:
    states: dict[str, str] = {"severity": scored.severity.state.value}
    for key in FACTOR_ORDER[1:]:
        value = getattr(scored.contextualized, key)
        if value is not None:
            states[key] = value.state.value
    return states


def _finding_entry(ranked: RankedFinding) -> dict[str, Any]:
    scored = ranked.scored
    finding = scored.finding
    return {
        "rank": ranked.rank,
        "resource_identity": finding.resource_identity,
        "issue_class": finding.issue_class,
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "score": scored.score,
        "band": scored.band,
        "action": scored.action,
        "contributions": dict(scored.contributions),
        "factor_states": _factor_states(scored),
        "explanation": list(scored.explanation),
        "baseline_band": baseline_band(finding),
        "low_confidence": scored.low_confidence,
        # Two fields, because they answer two different questions and summing the wrong one
        # reproduces the two-populations-conflated error. `factor_gap` is a property of the
        # CLASS and is true even for a context-ineligible finding; `factor_gap_counted` is
        # membership of the population the report counts, which excludes findings already
        # excluded as baseline_only_informational. Measured on corpus v0: 446 against 434.
        "factor_gap": scored.factor_gap,
        "factor_gap_counted": scored.factor_gap and not scored.baseline_only_informational,
        "unmapped": scored.unmapped,
        "baseline_only_informational": scored.baseline_only_informational,
        "weighted": scored.weighted,
    }


def to_json(ranked: Iterable[RankedFinding], report: PriorityReport) -> dict[str, Any]:
    """The source of truth: every ranked finding, plus the distributions.

    Raises if any finding was scored with a non-default weight map. Spec §4.4 keeps the
    frozen primary model unweighted, and a report path that accepted a weighted score would
    let the analysed model silently become the reported one.
    """
    items: Sequence[RankedFinding] = list(ranked)
    weighted = [r.scored.finding.resource_identity for r in items if r.scored.weighted]
    if weighted:
        raise ValueError(
            f"refusing to emit a report over weighted scores: {sorted(set(weighted))[:3]} "
            f"and {max(0, len(weighted) - 3)} more. The frozen primary model is unweighted; "
            f"weighting belongs to S5's sensitivity analysis."
        )
    return {
        "findings": [_finding_entry(r) for r in items],
        "report": report_to_json(report),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    """A human report rendered from the payload and nothing else.

    Grouped by band, Critical first, each finding showing its score decomposition and its
    explanation lines.
    """
    findings: list[dict[str, Any]] = list(payload["findings"])
    report: dict[str, Any] = payload["report"]

    lines: list[str] = ["# Remediation priorities", ""]
    overall = report["overall"]
    lines.append(
        "Band distribution: "
        + ", ".join(f"{band} {overall.get(band, 0)}" for band in _BAND_ORDER)
        + f" (total {report['total']})."
    )
    lines.append("")
    lines.append(
        f"{report['low_confidence_count']} finding(s) are low-confidence and are excluded "
        f"from prioritization-quality claims. {report['substantive_gap_count']} sit in a "
        f"class no contextual factor represents."
    )
    lines.append("")

    for band in _BAND_ORDER:
        in_band = [f for f in findings if f["band"] == band]
        if not in_band:
            continue
        lines.append(f"## {band}")
        lines.append("")
        action = in_band[0]["action"]
        lines.append(f"*{action}*")
        lines.append("")
        for entry in in_band:
            flags = [
                name
                for name, present in (
                    ("low-confidence", entry["low_confidence"]),
                    ("factor-gap", entry["factor_gap"]),
                    ("unmapped", entry["unmapped"]),
                    ("baseline-only", entry["baseline_only_informational"]),
                )
                if present
            ]
            suffix = f" [{', '.join(flags)}]" if flags else ""
            lines.append(
                f"### {entry['rank']}. {entry['resource_identity']} "
                f"- {entry['issue_class']} - score {entry['score']}{suffix}"
            )
            lines.append("")
            decomposition = " + ".join(
                f"{key} {entry['contributions'][key]}"
                for key in FACTOR_ORDER
                if key in entry["contributions"]
            )
            lines.append(f"`{decomposition} = {entry['score']}`")
            lines.append("")
            lines.append(f"Baseline band: {entry['baseline_band']}")
            lines.append("")
            for line in entry["explanation"]:
                lines.append(f"- {line}")
            lines.append("")

    return "\n".join(lines)
