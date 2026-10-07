"""Guard the guards: corrupt one figure in a record, and require its gate to fail.

The S5, S6 and S3c gates claim to recompute the figures in the committed records by a
second route. A pre-merge code review found that several of them did not: they re-derived
a value from the record's own fields, so no wrong figure could have failed them, and they
passed for as long as the record was fresh. The gates were rewritten, and this file is what
keeps the rewrite honest.

Each case below edits one figure in the in-memory copy of a committed record - nothing on
disk is touched - and calls the gate that owns that figure, which must raise. A gate that
still passes cannot see the number it is named for. The same gates pass untouched in their
own files, so a failure here is caused by the corruption and by nothing else.

This does not show the gates are complete. It shows that, for each figure listed, a wrong
value is noticed.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

import pytest

import test_s3c_gates as s3c
import test_s5_gates as s5
import test_s6_gates as s6

Document = dict[str, Any]
Mutation = Callable[[Document], object]


def _bump(*path: Any) -> Mutation:
    """Add one to the number at `path`."""

    def mutate(document: Document) -> None:
        node: Any = document
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] += 1

    return mutate


def _set(*path: Any, value: Any) -> Mutation:
    def mutate(document: Document) -> None:
        node: Any = document
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value

    return mutate


def _flip(*path: Any) -> Mutation:
    """Negate the boolean at `path`."""

    def mutate(document: Document) -> None:
        node: Any = document
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = not node[path[-1]]

    return mutate


def _variant(document: Document, variant_id: str) -> Document:
    return next(
        v for block in document["experiments"].values() for v in block if v["id"] == variant_id
    )


def _in_variant(variant_id: str, mutation: Mutation) -> Mutation:
    return lambda document: mutation(_variant(document, variant_id))


def _drop_an_unlisted_factor(document: Document) -> None:
    for case in document["cases"].values():
        if case["expectation"]["unlisted_non_resolved"]:
            case["expectation"]["unlisted_non_resolved"].pop()
            return
    raise AssertionError("no case reports an unlisted factor; nothing to corrupt")


def _reverse_first_ordering(variant: Document) -> None:
    first = next(iter(variant["scenarios"]["by_scenario"].values()))
    first["ordering"].reverse()


_BANDS = ("alert_reduction", "priority_band")
_PAIRS = ("contrastive_pairs", "pairs")
_PAIR_SUMMARY = ("contrastive_pairs", "summary")
_HEADLINE = ("scenarios", "summary", "headline", "framework", "max")

EVALUATION: list[tuple[str, Mutation, Callable[..., None]]] = [
    (
        "a scenario's tau-b",
        _set("scenarios", "scenarios", 3, "framework", "max", "kendall_tau_b", value=0.9),
        s5.test_gate_4_every_scenario_figure_is_recomputed_for_the_framework_and_the_baseline,
    ),
    (
        "the baseline's concordant count in a scenario",
        _bump("scenarios", "scenarios", 0, "baseline", "ordered_pairs", "concordant"),
        s5.test_gate_4_every_scenario_figure_is_recomputed_for_the_framework_and_the_baseline,
    ),
    (
        "the headline count of correctly ordered case pairs",
        _bump(*_HEADLINE, "ordered_pairs_concordant"),
        s5.test_gate_4_the_headline_and_clean_tallies_are_recounted,
    ),
    (
        "the number of clean scenarios",
        _bump("scenarios", "summary", "clean", "scenarios"),
        s5.test_gate_4_the_headline_and_clean_tallies_are_recounted,
    ),
    (
        "Critical/High after, over the context-eligible findings",
        _bump(*_BANDS, "context_eligible", "framework_critical_or_high"),
        s5.test_gate_5_every_band_figure_is_recounted_from_the_ranked_findings,
    ),
    (
        "Critical/High before, without the low-confidence findings",
        _bump(*_BANDS, "excluding_low_confidence", "baseline_critical_or_high"),
        s5.test_gate_5_every_band_figure_is_recounted_from_the_ranked_findings,
    ),
    (
        "the promoted count",
        _bump("baseline_comparison", "promoted", "count"),
        s5.test_gate_6_the_rank_change_table_is_recounted_for_both_populations,
    ),
    (
        "the demoted count without the low-confidence findings",
        _bump("baseline_comparison", "excluding_low_confidence", "demoted", "count"),
        s5.test_gate_6_the_rank_change_table_is_recounted_for_both_populations,
    ),
    (
        "a pair's isolated flag",
        _flip(*_PAIRS, 0, "isolated"),
        s5.test_gate_3_isolation_and_mechanism_are_recomputed_from_the_scored_cases,
    ),
    (
        "a pair's context delta",
        _bump(*_PAIRS, 2, "context_delta", "exposure"),
        s5.test_gate_3_isolation_and_mechanism_are_recomputed_from_the_scored_cases,
    ),
    (
        "a pair's verdict",
        _flip(*_PAIRS, 1, "framework", "max", "passes"),
        s5.test_gate_3_every_pair_verdict_is_strictly_greater_than_on_top_scores,
    ),
    (
        "the number of pairs passed",
        _bump(*_PAIR_SUMMARY, "authored", "framework_passes", "max"),
        s5.test_gate_3_the_pair_summary_is_recounted,
    ),
    (
        "the isolated count for one factor",
        _bump(*_PAIR_SUMMARY, "by_factor", "encryption", "isolated"),
        s5.test_gate_3_the_pair_summary_is_recounted,
    ),
    (
        "the count of pairs isolated without a shared default",
        _bump(*_PAIR_SUMMARY, "authored", "isolated_without_a_shared_default"),
        s5.test_gate_3_the_pair_summary_is_recounted,
    ),
    (
        "an unlisted non-resolved factor, dropped",
        _drop_an_unlisted_factor,
        s5.test_gate_2_non_resolved_factors_the_oracle_does_not_list_are_reported,
    ),
    (
        "retention's findings_out",
        _bump("retention", "findings_out"),
        s5.test_gate_7_retention_is_the_sum_of_the_adapter_runs,
    ),
]

SENSITIVITY: list[tuple[str, Mutation, Callable[..., None]]] = [
    (
        "a default variant's High count",
        _in_variant("default:exposure=2", _bump("corpus", "bands", "High")),
        s6.test_gate_3_every_score_moving_variant_is_reproduced_by_the_scoring_engine,
    ),
    (
        "a weight variant's count of changed scores",
        _in_variant("weight:double-privilege", _bump("corpus", "score_changed")),
        s6.test_gate_3_every_score_moving_variant_is_reproduced_by_the_scoring_engine,
    ),
    (
        "a weight variant's failed pairs",
        _in_variant("weight:drop-sensitivity", lambda v: v["pairs"]["failed"].pop()),
        s6.test_gate_3_pairs_and_scenarios_under_each_variant_follow_from_the_engines_scores,
    ),
    (
        "a default variant's scenario ordering",
        _in_variant("default:exposure=5", _reverse_first_ordering),
        s6.test_gate_3_pairs_and_scenarios_under_each_variant_follow_from_the_engines_scores,
    ),
    (
        "a boundary variant's High count",
        _in_variant("boundary:High+1", _bump("corpus", "bands", "High")),
        s6.test_gate_4_every_boundary_variant_is_recounted_from_the_committed_scores,
    ),
    (
        "a threshold variant's low-confidence count",
        _in_variant("low-confidence:4", _bump("corpus", "low_confidence")),
        s6.test_gate_4_every_threshold_variant_is_recounted_from_the_committed_states,
    ),
    (
        "a registered variant, removed from the record",
        lambda document: document["experiments"]["weights"].pop(),
        s6.test_gate_2_every_registered_variant_is_reported_exactly_once,
    ),
]

_RANKING = ("ranking_agreement", "all_context_eligible_findings")
_LEVELS = ("level_agreement", "by_factor")

AGREEMENT: list[tuple[str, Mutation, Callable[..., None]]] = [
    (
        "the count of findings the inferred run scores higher",
        _bump(*_RANKING, "inferred_higher"),
        s3c.test_gate_4_ranking_agreement_is_recounted_with_no_matching_order,
    ),
    (
        "tau-b on the declared resources",
        _set("ranking_agreement", "on_declared_resources", "kendall_tau_b", value=0.5),
        s3c.test_gate_4_ranking_agreement_is_recounted_with_no_matching_order,
    ),
    (
        "the inferred run's tied case pairs",
        _bump("oracle", "inferred", "ordered_pairs_tied"),
        s3c.test_gate_4_both_columns_of_the_oracle_are_regraded_from_the_scored_cases,
    ),
    (
        "the declared run's pairs passed",
        _bump("oracle", "declared", "pairs_passed"),
        s3c.test_gate_4_both_columns_of_the_oracle_are_regraded_from_the_scored_cases,
    ),
    (
        "a pair, moved out of not-applicable",
        lambda document: document["oracle"]["pairs_not_applicable"].pop(),
        s3c.test_gate_4_a_pair_is_not_applicable_exactly_when_the_run_scores_its_cases_as_one,
    ),
    (
        "findings inferred, against the table",
        _bump("coverage", "findings_inferred", "sensitivity"),
        s3c.test_gate_4_coverage_is_recounted_from_the_table_of_inferred_values,
    ),
    (
        "findings inferred, against the scored states",
        _bump("coverage", "findings_inferred", "sensitivity"),
        s3c.test_gate_3_a_finding_is_resolved_exactly_where_the_table_holds_a_value,
    ),
    (
        "level agreement, inferred equal to declared",
        _bump(*_LEVELS, "criticality", "inferred", "exact"),
        s3c.test_gate_4_level_agreement_is_recounted_from_the_ground_truth_and_every_case,
    ),
    (
        "level agreement, the all-default strawman",
        _bump(*_LEVELS, "sensitivity", "all_default", "exact"),
        s3c.test_gate_4_level_agreement_is_recounted_from_the_ground_truth_and_every_case,
    ),
]

CASES = [
    pytest.param(cached, mutation, gate, id=f"{record}: {label}")
    for record, cached, group in (
        ("evaluation", s5._evaluation, EVALUATION),
        ("sensitivity", s6._record, SENSITIVITY),
        ("agreement", s3c._record, AGREEMENT),
    )
    for label, mutation, gate in group
]


@pytest.mark.parametrize(("cached", "mutation", "gate"), CASES)
def test_a_corrupted_figure_fails_the_gate_that_owns_it(
    cached: Any,
    mutation: Mutation,
    gate: Callable[..., None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached.cache_clear()
    try:
        mutation(cached())
        with pytest.raises(AssertionError):
            if "monkeypatch" in inspect.signature(gate).parameters:
                gate(monkeypatch)
            else:
                gate()
    finally:
        # The record is cached per process: without this every later test would read the
        # corrupted copy.
        cached.cache_clear()
