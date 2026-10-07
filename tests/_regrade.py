"""A second implementation of the oracle's grading, for the gates to compare a record with.

The S5, S6 and S3c gates each check a committed record. A check that calls the function
which produced the record, or re-derives a figure from the record's own fields, confirms
only that the record is fresh. This module is what lets a gate do more: it grades pairs and
scenarios from scored findings with code that shares nothing with `eval.harness` and
imports nothing from `eval` or from `iacrisk`.

It is written to be obviously right rather than fast or general - a tiering by sorted
distinct scores, tau-b straight from its definition, plain counters - and it implements
only the registered rules: a case ranks at its highest counted finding, a pair passes on
strictly greater, a scenario is compared as tiers.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import Any

__all__ = [
    "CONTEXT",
    "RANK",
    "claimed",
    "failing_pairs",
    "grade_scenario",
    "tau_b",
    "tiers",
    "top_score",
]

RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CONTEXT = ("exposure", "privilege", "sensitivity", "criticality", "encryption")


def claimed(findings: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The findings that rank a case or enter a corpus figure: mapped, with a context block."""
    return [f for f in findings if not f["unmapped"] and not f["baseline_only_informational"]]


def top_score(findings: Sequence[Mapping[str, Any]]) -> int:
    scores = [f["score"] for f in claimed(findings)]
    assert scores, "a case with no counted finding has no rank"
    return int(max(scores))


def tiers(scores: Mapping[str, int]) -> list[list[str]]:
    levels = sorted(set(scores.values()), reverse=True)
    return [sorted(c for c, s in scores.items() if s == level) for level in levels]


def tau_b(xs: Sequence[int], ys: Sequence[int]) -> float | None:
    """Kendall's tau-b from its definition; `None` where one side is tied throughout."""
    concordant = discordant = tied_x = tied_y = 0
    for i, j in combinations(range(len(xs)), 2):
        a, b = xs[i] - xs[j], ys[i] - ys[j]
        tied_x += a == 0
        tied_y += b == 0
        if a * b > 0:
            concordant += 1
        elif a * b < 0:
            discordant += 1
    total = len(xs) * (len(xs) - 1) // 2
    denominator = ((total - tied_x) * (total - tied_y)) ** 0.5
    return None if denominator == 0 else (concordant - discordant) / denominator


def grade_scenario(expected: Sequence[Sequence[str]], scores: Mapping[str, int]) -> dict[str, Any]:
    """One system's scores against the expected tiers.

    `counts` holds `ordered`, `concordant`, `tied`, `discordant` for the case pairs the
    oracle orders, and `tied_expected`, `tied_as_expected` for those it ties. A missing key
    reads as zero.
    """
    tier_of = {case_id: index for index, tier in enumerate(expected) for case_id in tier}
    ids = sorted(tier_of)
    counts: Counter[str] = Counter()
    for first, second in combinations(ids, 2):
        if tier_of[first] == tier_of[second]:
            counts["tied_expected"] += 1
            counts["tied_as_expected"] += scores[first] == scores[second]
            continue
        upper, lower = (first, second) if tier_of[first] < tier_of[second] else (second, first)
        counts["ordered"] += 1
        if scores[upper] > scores[lower]:
            counts["concordant"] += 1
        elif scores[upper] == scores[lower]:
            counts["tied"] += 1
        else:
            counts["discordant"] += 1
    return {
        "ordering": tiers({c: scores[c] for c in ids}),
        "exact": tiers({c: scores[c] for c in ids}) == [sorted(tier) for tier in expected],
        "tau_b": tau_b([-tier_of[c] for c in ids], [scores[c] for c in ids]),
        "counts": counts,
    }


def failing_pairs(pairs: Sequence[Mapping[str, Any]], top: Mapping[str, int]) -> list[str]:
    """The pairs whose high case does not score strictly above its low case, in order."""
    return [p["pair_id"] for p in pairs if not top[p["case_high"]] > top[p["case_low"]]]
