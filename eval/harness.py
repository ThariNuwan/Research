"""The independent evaluation harness (PLAN Q7): every metric from JSON, none from the framework.

This module reads three documents and imports none of the code that produced them -
`tests/test_architecture.py` enforces that. The band order and factor keys are restated
here as literals for the same reason the ground-truth schema restates them: importing them
would couple the grader to the graded.

    artifacts/scored-corpus-v0.json   corpus v0, ranked            (tools.score.run corpus)
    artifacts/scored-cases-v1.json    each case, finding level     (tools.score.run cases)
    eval/ground_truth/corpus-v1.json  the pre-registered oracle

**The rules below were fixed and committed before `scored-cases-v1.json` existed and before
any case-level score had been looked at.** Git history carries that ordering, as it does for
the oracle itself. They are stated once, here, so the code and the registration are the
same text.

1. **A case ranks where its highest-scoring finding ranks** (`PRIMARY_RULE`). Ruled by the
   project author on 2026-10-06. The framework's output is a ranked list of findings, so a
   resource surfaces at its top finding; breadth of findings is not a rubric factor and does
   not count. `sum` and `mean` are computed beside it as an aggregation-sensitivity check and
   are never substituted for it.
2. **A finding counts toward a case only if the framework makes a quality claim about it.**
   `unmapped` and `baseline_only_informational` findings are set aside (PLAN Q7, Q8). A case
   left with nothing is `rankable: false` - an explicit state, never a zero - and any pair
   or scenario containing it is `evaluable: false` rather than failed.
3. **A contrastive pair passes when `case_high` scores strictly above `case_low`.** A tie is
   a failure: the oracle's expectation is an order.
4. **Isolation is checked, not assumed.** A pair is `isolated` when, of the five contextual
   contributions, exactly the factor under test differs between the two cases' top findings,
   and `mechanism` holds when that factor is strictly higher on the high side. Severity is
   reported as `severity_delta` and is not part of the isolation test, because it has no
   contrastive pair by measurement (S2 design spec section 1) and moves whenever the class
   set does.
5. **A scenario is compared as tiers.** `exact_tier_match` holds when the tiers the scores
   induce equal the expected tiers; Kendall's tau-b gives partial credit and is `None` when
   one side is entirely tied; the ordered and tied case pairs are counted separately.
6. **Nothing is excluded from the headline that the oracle's own rule does not exclude**
   (S2 design spec section 5): every pair contributes, and every scenario not marked
   `disagree`. The `clean` figures beside them - no ground-truth-excluded case and no
   low-confidence case - are a second number, never an average of the two.
7. **The baseline is graded by the same rules on the same findings**, ranking a case by its
   highest `baseline_band`. A framework figure without its baseline twin is not a comparison.
8. **Alert reduction is two numbers** - deduplication, and the Critical/High band count -
   and this module never adds them.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

__all__ = [
    "BANDS",
    "BAND_RANK",
    "CONTEXT_FACTORS",
    "PRIMARY_RULE",
    "RULES",
    "alert_reduction",
    "baseline_comparison",
    "case_score",
    "evaluate",
    "evaluate_pair",
    "evaluate_scenario",
    "kendall_tau_b",
    "retention",
    "tiers_from_scores",
]

BANDS = ("Critical", "High", "Medium", "Low")
BAND_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CONTEXT_FACTORS = ("exposure", "privilege", "sensitivity", "criticality", "encryption")

RULES = ("max", "sum", "mean")
PRIMARY_RULE = "max"

_ALERT_BANDS = ("Critical", "High")


# --- a case ---------------------------------------------------------------------------


def _counts(finding: Mapping[str, Any]) -> bool:
    return not finding["unmapped"] and not finding["baseline_only_informational"]


def _top(findings: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    """The highest-scoring finding; class, scanner and rule break a tie for determinism."""
    return min(
        findings,
        key=lambda f: (-f["score"], f["issue_class"], f["scanner"], f["rule_id"]),
    )


def _expectation_check(
    case: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Whether the scored output still shows what the ground truth recorded for the case.

    Classes are compared as `(identity, class)` sets. `unresolved_factors` and
    `defaulted_factors` are compared against every scored finding of that identity and
    class - the oracle recorded them as first-class expectations (S1 design spec 4.1), so a
    silent change of state in the framework is a mismatch here, not a pass.
    """
    expected = {(e["resource_identity"], e["issue_class"]) for e in case["expected"]["findings"]}
    scored = {(f["resource_identity"], f["issue_class"]) for f in findings}

    state_mismatches: list[dict[str, Any]] = []
    for entry in case["expected"]["findings"]:
        key = (entry["resource_identity"], entry["issue_class"])
        for field, state in (
            ("unresolved_factors", "unresolved"),
            ("defaulted_factors", "defaulted"),
        ):
            for factor in entry.get(field, []):
                for finding in findings:
                    if (finding["resource_identity"], finding["issue_class"]) != key:
                        continue
                    actual = finding["factor_states"].get(factor)
                    if actual != state:
                        state_mismatches.append(
                            {
                                "issue_class": entry["issue_class"],
                                "factor": factor,
                                "expected": state,
                                "scored": actual,
                            }
                        )
    return {
        "classes_match": expected == scored,
        "missing_from_scored": sorted(c for _, c in expected - scored),
        "not_in_ground_truth": sorted(c for _, c in scored - expected),
        "states_match": not state_mismatches,
        "state_mismatches": state_mismatches,
    }


def case_score(case: Mapping[str, Any], entry: Mapping[str, Any]) -> dict[str, Any]:
    """One case reduced to what pairs and scenarios compare (rules 1 and 2)."""
    findings: list[Mapping[str, Any]] = list(entry["findings"])
    counted = [f for f in findings if _counts(f)]
    summary: dict[str, Any] = {
        "case_id": case["case_id"],
        "domain": case["domain"],
        "hand_crafted": case["source"] == "hand-crafted",
        "ground_truth_excluded": any(
            e.get("excluded_from_quality_claims", False) for e in case["expected"]["findings"]
        ),
        "findings": len(findings),
        "counted": len(counted),
        "set_aside": len(findings) - len(counted),
        "rankable": bool(counted),
        "expectation": _expectation_check(case, findings),
    }
    if not counted:
        return {
            **summary,
            "scores": dict.fromkeys(RULES),
            "baseline": None,
            "band": None,
            "contributions": None,
            "low_confidence": None,
            "context_uniform": None,
        }

    scores = [f["score"] for f in counted]
    top = _top(counted)
    context = {tuple(f["contributions"].get(k) for k in CONTEXT_FACTORS) for f in counted}
    return {
        **summary,
        "scores": {"max": max(scores), "sum": sum(scores), "mean": sum(scores) / len(scores)},
        "baseline": max(BAND_RANK[f["baseline_band"]] for f in counted),
        "band": top["band"],
        "contributions": dict(top["contributions"]),
        "low_confidence": bool(top["low_confidence"]),
        # Every counted finding of one case sits on one resource under one declared context,
        # so their contextual contributions should agree. Reported rather than assumed: if
        # they do not, the top finding's vector is still what the max rule compares.
        "context_uniform": len(context) == 1,
    }


# --- contrastive pairs ----------------------------------------------------------------


def _compare(high: float | None, low: float | None) -> dict[str, Any]:
    if high is None or low is None:
        return {"high": high, "low": low, "delta": None, "passes": None}
    return {"high": high, "low": low, "delta": high - low, "passes": high > low}


def evaluate_pair(
    pair: Mapping[str, Any], cases: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """One mechanism test (rules 3, 4 and 7)."""
    high = cases[pair["case_high"]]
    low = cases[pair["case_low"]]
    factor = pair["factor_under_test"]
    evaluable = bool(high["rankable"] and low["rankable"])

    result: dict[str, Any] = {
        "pair_id": pair["pair_id"],
        "factor_under_test": factor,
        "case_high": pair["case_high"],
        "case_low": pair["case_low"],
        "evaluable": evaluable,
        "hand_crafted": bool(high["hand_crafted"] or low["hand_crafted"]),
        "ground_truth_excluded": bool(
            high["ground_truth_excluded"] or low["ground_truth_excluded"]
        ),
        "framework": {rule: _compare(high["scores"][rule], low["scores"][rule]) for rule in RULES},
        "baseline": _compare(high["baseline"], low["baseline"]),
    }
    if not evaluable:
        return {
            **result,
            "low_confidence": None,
            "context_delta": None,
            "severity_delta": None,
            "mechanism": None,
            "isolated": None,
        }

    delta = {
        key: high["contributions"].get(key, 0) - low["contributions"].get(key, 0)
        for key in CONTEXT_FACTORS
    }
    moved = {key for key, value in delta.items() if value != 0}
    return {
        **result,
        "low_confidence": bool(high["low_confidence"] or low["low_confidence"]),
        "context_delta": delta,
        "severity_delta": high["contributions"]["severity"] - low["contributions"]["severity"],
        "mechanism": factor in delta and delta[factor] > 0,
        "isolated": moved == {factor},
    }


def _is_clean(result: Mapping[str, Any]) -> bool:
    return bool(
        result["evaluable"] and not result["ground_truth_excluded"] and not result["low_confidence"]
    )


def _pair_tally(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    evaluable = [p for p in pairs if p["evaluable"]]
    return {
        "pairs": len(pairs),
        "evaluable": len(evaluable),
        "framework_passes": {
            rule: sum(1 for p in evaluable if p["framework"][rule]["passes"]) for rule in RULES
        },
        "baseline_passes": sum(1 for p in evaluable if p["baseline"]["passes"]),
        "mechanism": sum(1 for p in evaluable if p["mechanism"]),
        "isolated": sum(1 for p in evaluable if p["isolated"]),
        "severity_also_moved": sum(1 for p in evaluable if p["severity_delta"] != 0),
    }


def _summarise_pairs(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    factors = sorted({p["factor_under_test"] for p in pairs})
    return {
        "primary_rule": PRIMARY_RULE,
        "authored": _pair_tally(pairs),
        "clean": _pair_tally([p for p in pairs if _is_clean(p)]),
        "by_factor": {
            factor: _pair_tally([p for p in pairs if p["factor_under_test"] == factor])
            for factor in factors
        },
        "by_source": {
            "mined": _pair_tally([p for p in pairs if not p["hand_crafted"]]),
            "hand_crafted": _pair_tally([p for p in pairs if p["hand_crafted"]]),
        },
    }


# --- scenarios ------------------------------------------------------------------------


def kendall_tau_b(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    """Kendall's tau-b over paired observations, or None where it is undefined.

    Tau-b rather than tau-a because both sides carry ties by design: the oracle's tiers tie
    cases on purpose, and equal scores tie them in the output. It is undefined when either
    side is tied throughout - there is no order to correlate with - and that is returned as
    `None` rather than as 0, which would read as "no agreement" instead of "nothing to say".
    """
    if len(xs) != len(ys):
        raise ValueError(f"paired observations differ in length: {len(xs)} against {len(ys)}")
    concordant = discordant = tied_x = tied_y = 0
    pairs = 0
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            pairs += 1
            dx = (xs[i] > xs[j]) - (xs[i] < xs[j])
            dy = (ys[i] > ys[j]) - (ys[i] < ys[j])
            if dx == 0:
                tied_x += 1
            if dy == 0:
                tied_y += 1
            if dx and dy:
                if dx == dy:
                    concordant += 1
                else:
                    discordant += 1
    denominator = math.sqrt((pairs - tied_x) * (pairs - tied_y))
    if denominator == 0:
        return None
    return (concordant - discordant) / denominator


def tiers_from_scores(scores: Mapping[str, float]) -> list[list[str]]:
    """Cases grouped into tiers by equal score, highest first; ids sorted within a tier."""
    by_score: dict[float, list[str]] = {}
    for case_id, score in scores.items():
        by_score.setdefault(score, []).append(case_id)
    return [sorted(by_score[score]) for score in sorted(by_score, reverse=True)]


def _order_against(
    expected: Sequence[Sequence[str]], scores: Mapping[str, float]
) -> dict[str, Any]:
    """One system's scores against the expected tiers (rule 5)."""
    tier_of = {case_id: index for index, tier in enumerate(expected) for case_id in tier}
    case_ids = sorted(tier_of)
    induced = tiers_from_scores(scores)

    ordered = concordant = tied = discordant = 0
    tied_expected = tied_as_expected = 0
    for i, first in enumerate(case_ids):
        for second in case_ids[i + 1 :]:
            if tier_of[first] == tier_of[second]:
                tied_expected += 1
                tied_as_expected += scores[first] == scores[second]
                continue
            ordered += 1
            upper, lower = (first, second) if tier_of[first] < tier_of[second] else (second, first)
            if scores[upper] > scores[lower]:
                concordant += 1
            elif scores[upper] == scores[lower]:
                tied += 1
            else:
                discordant += 1

    return {
        "scores": {case_id: scores[case_id] for case_id in case_ids},
        "ordering": induced,
        "exact_tier_match": induced == [sorted(tier) for tier in expected],
        # Tier index rises as priority falls, so it is negated to correlate with score.
        "kendall_tau_b": kendall_tau_b(
            [-tier_of[c] for c in case_ids], [scores[c] for c in case_ids]
        ),
        "ordered_pairs": {
            "expected": ordered,
            "concordant": concordant,
            "tied": tied,
            "discordant": discordant,
        },
        "tied_pairs": {"expected": tied_expected, "tied_as_expected": tied_as_expected},
    }


def evaluate_scenario(
    scenario: Mapping[str, Any], cases: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """One realistic test: the expected tiers against the framework and the baseline."""
    expected = [list(tier) for tier in scenario["expected_ordering"]]
    members = [cases[case_id] for tier in expected for case_id in tier]
    evaluable = all(m["rankable"] for m in members)

    result: dict[str, Any] = {
        "scenario_id": scenario["scenario_id"],
        "domain": scenario["domain"],
        "reviewer_verdict": scenario["oracle"]["reviewer_verdict"],
        "contributes_to_headline": scenario["oracle"]["reviewer_verdict"] != "disagree",
        "expected_ordering": expected,
        "evaluable": evaluable,
        "ground_truth_excluded": any(m["ground_truth_excluded"] for m in members),
        "low_confidence": any(m["low_confidence"] for m in members) if evaluable else None,
    }
    if not evaluable:
        return {**result, "framework": None, "baseline": None}
    return {
        **result,
        "framework": {
            rule: _order_against(expected, {m["case_id"]: m["scores"][rule] for m in members})
            for rule in RULES
        },
        "baseline": _order_against(expected, {m["case_id"]: m["baseline"] for m in members}),
    }


def _scenario_tally(scenarios: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    evaluable = [s for s in scenarios if s["evaluable"]]

    def tally(pick: Any) -> dict[str, Any]:
        graded = [pick(s) for s in evaluable]
        return {
            "exact_tier_matches": sum(1 for g in graded if g["exact_tier_match"]),
            "ordered_pairs_expected": sum(g["ordered_pairs"]["expected"] for g in graded),
            "ordered_pairs_concordant": sum(g["ordered_pairs"]["concordant"] for g in graded),
            "ordered_pairs_tied": sum(g["ordered_pairs"]["tied"] for g in graded),
            "ordered_pairs_discordant": sum(g["ordered_pairs"]["discordant"] for g in graded),
            "tied_pairs_expected": sum(g["tied_pairs"]["expected"] for g in graded),
            "tied_pairs_as_expected": sum(g["tied_pairs"]["tied_as_expected"] for g in graded),
        }

    return {
        "scenarios": len(scenarios),
        "evaluable": len(evaluable),
        "framework": {rule: tally(lambda s, r=rule: s["framework"][r]) for rule in RULES},
        "baseline": tally(lambda s: s["baseline"]),
    }


def _summarise_scenarios(scenarios: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    headline = [s for s in scenarios if s["contributes_to_headline"]]
    return {
        "primary_rule": PRIMARY_RULE,
        "authored": len(scenarios),
        "excluded_as_disagree": len(scenarios) - len(headline),
        "headline": _scenario_tally(headline),
        "clean": _scenario_tally([s for s in headline if _is_clean(s)]),
    }


# --- the corpus-level metrics ---------------------------------------------------------


def retention(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """Normalization and retention coverage, summed over the adapter runs (PLAN Q7).

    Not detection accuracy, which is delegated to the scanners. `findings_in` is derived
    upstream as `findings_out + dropped` (S3a handoff): this figure shows that nothing was
    lost between an adapter's output and the ranked list, not that the adapter read every
    raw record - the S3a retention tests establish that separately, from the captures.
    """
    runs: Mapping[str, Mapping[str, Any]] = corpus["retention"]["scanners"]
    total = {
        key: sum(run[key] for run in runs.values())
        for key in (
            "findings_in",
            "findings_out",
            "identity_unresolved",
            "unmapped",
            "unknown_severity",
            "context_ineligible",
        )
    }
    dropped = sum(len(run["dropped"]) for run in runs.values())
    findings_in = total["findings_in"]

    def rate(count: int) -> float | None:
        return count / findings_in if findings_in else None

    return {
        "runs": len(runs),
        **total,
        "dropped": dropped,
        "retention_rate": rate(total["findings_out"]),
        "identity_unresolved_rate": rate(total["identity_unresolved"]),
        "unmapped_rate": rate(total["unmapped"]),
        "unknown_severity_rate": rate(total["unknown_severity"]),
        "context_ineligible_rate": rate(total["context_ineligible"]),
        "per_run": {
            name: {
                "findings_in": run["findings_in"],
                "findings_out": run["findings_out"],
                "dropped": len(run["dropped"]),
                "unknown_severity": run["unknown_severity"],
                "unmapped": run["unmapped"],
            }
            for name, run in sorted(runs.items())
        },
    }


def _band_counts(findings: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts = dict.fromkeys(BANDS, 0)
    for finding in findings:
        counts[finding[key]] += 1
    return counts


def _band_reduction(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    baseline = _band_counts(findings, "baseline_band")
    framework = _band_counts(findings, "band")
    before = sum(baseline[band] for band in _ALERT_BANDS)
    after = sum(framework[band] for band in _ALERT_BANDS)
    unknown = [f for f in findings if f["factor_states"]["severity"] == "unresolved"]
    return {
        "findings": len(findings),
        "baseline": baseline,
        "framework": framework,
        "baseline_critical_or_high": before,
        "framework_critical_or_high": after,
        "reduction": before - after,
        "reduction_rate": (before - after) / before if before else None,
        # The baseline's own coverage, which has to travel with the comparison: a finding
        # with no scanner severity reaches its baseline band through the rubric's default.
        "baseline_from_unknown_severity": len(unknown),
        "baseline_critical_or_high_from_unknown_severity": sum(
            1 for f in unknown if f["baseline_band"] in _ALERT_BANDS
        ),
    }


def alert_reduction(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """Two numbers, never one (rule 8).

    `deduplication` is Tier 1 alone. The Tier-2 candidates are carried beside it because
    they are evidence about scanner overlap and about the fingerprint's limits, and they
    are not part of the reduction: a candidate is surfaced, never merged.

    `priority_band` is counted over the ranked list - after the collapse - so the two
    reductions are measured on disjoint steps and neither inflates the other.
    """
    population = corpus["population"]
    retention_block = corpus["retention"]
    findings: list[Mapping[str, Any]] = list(corpus["findings"])
    eligible = [f for f in findings if _counts(f)]
    findings_in = population["findings_in"]
    return {
        "deduplication": {
            "findings_in": findings_in,
            "tier1_collapsed": population["tier1_collapsed"],
            "ranked": population["ranked"],
            "reduction_rate": population["tier1_collapsed"] / findings_in if findings_in else None,
            "tier2_candidates_not_merged": {
                "cross_scanner": retention_block["tier2_cross_scanner"],
                "same_scanner": retention_block["tier2_same_scanner"],
            },
        },
        "priority_band": {
            "all_ranked": _band_reduction(findings),
            "quality_claim_population": _band_reduction(eligible),
        },
    }


def _movement_cell(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    count = len(findings)
    return {
        "count": count,
        "low_confidence": sum(1 for f in findings if f["low_confidence"]),
        "baseline_from_unknown_severity": sum(
            1 for f in findings if f["factor_states"]["severity"] == "unresolved"
        ),
        # What "justified by named factors" rests on: per factor, how much it contributed
        # on average in this cell and how often that contribution was resolved from
        # evidence rather than taken from a default.
        "mean_contribution": {
            key: sum(f["contributions"][key] for f in findings) / count for key in CONTEXT_FACTORS
        },
        "resolved_share": {
            key: sum(1 for f in findings if f["factor_states"][key] == "resolved") / count
            for key in CONTEXT_FACTORS
        },
    }


def baseline_comparison(corpus: Mapping[str, Any]) -> dict[str, Any]:
    """The rank-change table against the severity baseline (PLAN Q7).

    Over the findings the framework makes a quality claim about. A cell is a
    `baseline band -> framework band` movement; each carries the per-factor profile that
    explains it and how much of it rests on defaults, so a movement driven by unresolved
    factors cannot be read as one driven by evidence.
    """
    findings = [f for f in corpus["findings"] if _counts(f)]
    cells: dict[str, list[Mapping[str, Any]]] = {}
    for finding in findings:
        cells.setdefault(f"{finding['baseline_band']}->{finding['band']}", []).append(finding)

    def moved(direction: int) -> list[Mapping[str, Any]]:
        return [
            f
            for f in findings
            if (BAND_RANK[f["band"]] > BAND_RANK[f["baseline_band"]])
            - (BAND_RANK[f["band"]] < BAND_RANK[f["baseline_band"]])
            == direction
        ]

    def direction_summary(members: Sequence[Mapping[str, Any]]) -> dict[str, int]:
        return {
            "count": len(members),
            "low_confidence": sum(1 for f in members if f["low_confidence"]),
            "baseline_from_unknown_severity": sum(
                1 for f in members if f["factor_states"]["severity"] == "unresolved"
            ),
        }

    return {
        "findings": len(findings),
        "promoted": direction_summary(moved(1)),
        "demoted": direction_summary(moved(-1)),
        "unchanged": direction_summary(moved(0)),
        "cells": {key: _movement_cell(members) for key, members in sorted(cells.items())},
    }


# --- everything -----------------------------------------------------------------------


def evaluate(
    ground_truth: Mapping[str, Any],
    corpus: Mapping[str, Any],
    scored_cases: Mapping[str, Any],
) -> dict[str, Any]:
    """Every metric the three documents support.

    A ground-truth case with no scored entry raises: the harness rejects a case it cannot
    grade rather than skipping it (PLAN, pre-implementation deliverable 4).
    """
    entries: Mapping[str, Mapping[str, Any]] = scored_cases["cases"]
    missing = sorted(c["case_id"] for c in ground_truth["cases"] if c["case_id"] not in entries)
    if missing:
        raise ValueError(f"ground-truth cases with no scored entry: {missing}")

    cases = {
        case["case_id"]: case_score(case, entries[case["case_id"]])
        for case in ground_truth["cases"]
    }
    pairs = [evaluate_pair(pair, cases) for pair in ground_truth["contrastive_pairs"]]
    scenarios = [evaluate_scenario(s, cases) for s in ground_truth["scenarios"]]

    return {
        "registered_rules": {
            "primary_case_rule": PRIMARY_RULE,
            "sensitivity_case_rules": [rule for rule in RULES if rule != PRIMARY_RULE],
            "pair_passes_when": "case_high scores strictly above case_low",
            "set_aside_findings": ["unmapped", "baseline_only_informational"],
            "headline_excludes": "scenarios the reviewer marked disagree, and nothing else",
        },
        "retention": retention(corpus),
        "alert_reduction": alert_reduction(corpus),
        "baseline_comparison": baseline_comparison(corpus),
        "cases": cases,
        "contrastive_pairs": {"summary": _summarise_pairs(pairs), "pairs": pairs},
        "scenarios": {"summary": _summarise_scenarios(scenarios), "scenarios": scenarios},
        # Both halves of this metric are experiments with their own registration and their
        # own record. This one says where they are rather than restating either.
        "ranking_consistency": {
            "auto_inference_agreement": {
                "state": "reported-separately",
                "record": "artifacts/auto-inference-agreement-v1.json",
            },
            "model_sensitivity": {
                "state": "reported-separately",
                "record": "artifacts/sensitivity-v1.json",
            },
        },
    }
