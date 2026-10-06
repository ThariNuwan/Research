"""S5 acceptance gates: the evaluation record, checked against the documents it was built from.

`tests/eval/test_harness.py` pins the harness's rules on constructed inputs and was committed
before any case-level score existed. These gates are the other half: they run over the real
committed artifacts. None restates a headline figure - each recomputes it by a second route,
so a gate stays meaningful when a figure legitimately moves and fails when the record and
its inputs disagree.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from eval import harness
from eval import run as eval_run
from eval.ground_truth import load_and_validate
from tools.harvest.provenance import hash_file
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent
BAND_ORDER = ("Critical", "High", "Medium", "Low")


@lru_cache(maxsize=1)
def _ground_truth() -> dict[str, Any]:
    return load_and_validate(eval_run.GROUND_TRUTH)


@lru_cache(maxsize=1)
def _evaluation() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(eval_run.OUTPUT.read_bytes())
    return document


@lru_cache(maxsize=1)
def _corpus() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(eval_run.SCORED_CORPUS.read_bytes())
    return document


@lru_cache(maxsize=1)
def _cases() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(eval_run.SCORED_CASES.read_bytes())
    return document


def _without_provenance(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "provenance"}


def _top_score(case_id: str) -> int:
    """A case's rank by the registered rule, recomputed here from the scored document
    rather than read back from the harness's own output."""
    counted = [
        f["score"]
        for f in _cases()["cases"][case_id]["findings"]
        if not f["unmapped"] and not f["baseline_only_informational"]
    ]
    assert counted, f"{case_id} has no finding that counts"
    return int(max(counted))


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


# --- gate 1: the record is the harness's verdict on the committed inputs ---------------


def test_gate_1_the_committed_record_matches_a_fresh_run_over_the_committed_inputs() -> None:
    assert _without_provenance(_evaluation()) == _without_provenance(eval_run.evaluation_document())


def test_gate_1_the_record_names_the_inputs_it_was_computed_from() -> None:
    """A digest that no longer matches means an input was regenerated and the harness was
    not re-run - the record would be describing a document that no longer exists."""
    recorded = _evaluation()["provenance"]["inputs"]
    assert recorded == {
        path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in eval_run.INPUTS
    }


def test_gate_1_the_committed_case_scores_match_a_fresh_replay() -> None:
    assert _without_provenance(_cases()) == _without_provenance(score_run.cases_document())


# --- gate 2: every case is graded, and still shows what the oracle recorded -------------


def test_gate_2_every_ground_truth_case_is_graded_and_rankable() -> None:
    cases = _evaluation()["cases"]
    assert set(cases) == {case["case_id"] for case in _ground_truth()["cases"]}
    assert all(case["rankable"] for case in cases.values())


def test_gate_2_the_scored_output_still_shows_every_expected_class_and_state() -> None:
    """The oracle's `expected.findings` were measured from adapter output when it was
    authored. If the framework stops emitting one, or changes a recorded `unresolved` or
    `defaulted` state, the pair or scenario built on it is no longer testing what its
    rationale says."""
    for case_id, case in _evaluation()["cases"].items():
        check = case["expectation"]
        assert check["classes_match"], (case_id, check)
        assert check["states_match"], (case_id, check)


def test_gate_2_one_resource_under_one_declaration_has_one_contextual_vector() -> None:
    """What lets a case be compared by a single factor vector at all."""
    assert all(case["context_uniform"] for case in _evaluation()["cases"].values())


# --- gate 3: the pair verdicts follow from the registered rule -------------------------


def test_gate_3_every_pair_is_evaluable_and_its_verdict_is_strictly_greater_than() -> None:
    pairs = _evaluation()["contrastive_pairs"]["pairs"]
    assert len(pairs) == len(_ground_truth()["contrastive_pairs"])
    for pair in pairs:
        assert pair["evaluable"]
        high, low = _top_score(pair["case_high"]), _top_score(pair["case_low"])
        assert pair["framework"]["max"]["passes"] is (high > low), pair["pair_id"]
        assert pair["framework"]["max"]["delta"] == high - low


def test_gate_3_the_summary_counts_are_the_pairs_counted() -> None:
    record = _evaluation()["contrastive_pairs"]
    pairs = record["pairs"]
    authored = record["summary"]["authored"]

    assert authored["pairs"] == len(pairs)
    assert authored["framework_passes"]["max"] == sum(
        1 for p in pairs if _top_score(p["case_high"]) > _top_score(p["case_low"])
    )
    assert authored["baseline_passes"] == sum(1 for p in pairs if p["baseline"]["passes"])
    by_source = record["summary"]["by_source"]
    assert by_source["mined"]["pairs"] + by_source["hand_crafted"]["pairs"] == len(pairs)
    assert sum(f["pairs"] for f in record["summary"]["by_factor"].values()) == len(pairs)


def test_gate_3_a_pair_that_passes_without_its_factor_moving_would_be_visible() -> None:
    """`mechanism` and `isolated` are reported per pair, so a pass that owes nothing to the
    factor under test cannot hide inside the pass count. Asserted as the relation the
    record must satisfy: an isolated pair is one whose only contextual movement is its own
    factor, in the right direction."""
    for pair in _evaluation()["contrastive_pairs"]["pairs"]:
        moved = {k for k, v in pair["context_delta"].items() if v != 0}
        assert pair["isolated"] is (moved == {pair["factor_under_test"]})
        if pair["isolated"]:
            assert pair["mechanism"] is (pair["context_delta"][pair["factor_under_test"]] > 0)


# --- gate 4: the scenario verdicts follow from the registered rule ---------------------


def test_gate_4_every_scenario_is_graded_against_its_own_expected_tiers() -> None:
    graded = {s["scenario_id"]: s for s in _evaluation()["scenarios"]["scenarios"]}
    for scenario in _ground_truth()["scenarios"]:
        record = graded[scenario["scenario_id"]]
        assert record["evaluable"]
        assert record["expected_ordering"] == scenario["expected_ordering"]

        scores = {c: _top_score(c) for tier in scenario["expected_ordering"] for c in tier}
        induced = harness.tiers_from_scores(scores)
        framework = record["framework"]["max"]
        assert framework["ordering"] == induced
        assert framework["exact_tier_match"] is (
            induced == [sorted(tier) for tier in scenario["expected_ordering"]]
        )


def test_gate_4_the_headline_excludes_only_what_the_oracle_rule_excludes() -> None:
    summary = _evaluation()["scenarios"]["summary"]
    disagree = sum(
        1 for s in _ground_truth()["scenarios"] if s["oracle"]["reviewer_verdict"] == "disagree"
    )
    assert summary["excluded_as_disagree"] == disagree
    assert summary["headline"]["scenarios"] == summary["authored"] - disagree
    assert summary["clean"]["scenarios"] <= summary["headline"]["scenarios"]


def test_gate_4_the_baseline_is_graded_on_every_pair_and_scenario_the_framework_is() -> None:
    record = _evaluation()
    assert all(p["baseline"]["passes"] is not None for p in record["contrastive_pairs"]["pairs"])
    assert all(s["baseline"] is not None for s in record["scenarios"]["scenarios"])


# --- gate 5: alert reduction is two numbers --------------------------------------------


def test_gate_5_alert_reduction_is_two_numbers_and_no_field_combines_them() -> None:
    reduction = _evaluation()["alert_reduction"]
    assert set(reduction) == {"deduplication", "priority_band"}

    population = _corpus()["population"]
    dedup = reduction["deduplication"]
    assert dedup["tier1_collapsed"] == population["tier1_collapsed"]
    assert dedup["ranked"] == population["findings_in"] - population["tier1_collapsed"]
    assert reduction["priority_band"]["all_ranked"]["findings"] == population["ranked"]


def test_gate_5_the_band_counts_are_the_corpus_reports_own() -> None:
    """The harness counts bands from the per-finding list; the framework's report counted
    them independently when it scored. They must agree."""
    bands = _evaluation()["alert_reduction"]["priority_band"]
    report = _corpus()["report"]

    assert bands["all_ranked"]["framework"] == {b: report["overall"][b] for b in BAND_ORDER}
    assert bands["quality_claim_population"]["framework"] == {
        b: report["eligible_only"][b] for b in BAND_ORDER
    }
    baseline = dict.fromkeys(BAND_ORDER, 0)
    for key, count in report["framework_vs_baseline"].items():
        baseline[key.split("|")[1]] += count
    assert bands["all_ranked"]["baseline"] == baseline


def test_gate_5_the_baselines_own_coverage_travels_with_the_band_figures() -> None:
    for block in _evaluation()["alert_reduction"]["priority_band"].values():
        assert block["baseline_from_unknown_severity"] >= 0
        assert (
            block["baseline_critical_or_high_from_unknown_severity"]
            <= block["baseline_critical_or_high"]
        )


# --- gate 6: the rank-change table accounts for every finding it claims ----------------


def test_gate_6_every_quality_claim_finding_is_in_exactly_one_movement_cell() -> None:
    table = _evaluation()["baseline_comparison"]
    eligible = [
        f
        for f in _corpus()["findings"]
        if not f["unmapped"] and not f["baseline_only_informational"]
    ]
    assert table["findings"] == len(eligible)
    assert sum(cell["count"] for cell in table["cells"].values()) == len(eligible)
    moved = table["promoted"]["count"] + table["demoted"]["count"] + table["unchanged"]["count"]
    assert moved == len(eligible)


def test_gate_6_each_cell_says_how_much_of_its_movement_rests_on_defaults() -> None:
    for name, cell in _evaluation()["baseline_comparison"]["cells"].items():
        assert 0 <= cell["low_confidence"] <= cell["count"], name
        assert set(cell["mean_contribution"]) == set(harness.CONTEXT_FACTORS)
        assert all(0.0 <= share <= 1.0 for share in cell["resolved_share"].values())


# --- gate 7: retention --------------------------------------------------------------------


def test_gate_7_retention_accounts_for_every_finding_the_adapters_emitted() -> None:
    retention = _evaluation()["retention"]
    assert retention["findings_in"] == retention["findings_out"] + retention["dropped"]
    assert retention["findings_in"] == _corpus()["population"]["findings_in"]
    assert retention["retention_rate"] == retention["findings_out"] / retention["findings_in"]


# --- gate 8: the rules were registered before the scores existed -----------------------


def test_gate_8_the_harness_was_committed_before_the_case_scores_it_grades() -> None:
    """Pre-registration, checked against git rather than asserted in prose: the commit that
    first added `eval/harness.py` must be a strict ancestor of the commit that first added
    `artifacts/scored-cases-v1.json`."""
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")

    def first_commit(path: str) -> str:
        added = _git("log", "--diff-filter=A", "--format=%H", "--", path)
        assert added, f"{path} has no adding commit in history"
        return added.splitlines()[-1]

    rules = first_commit("eval/harness.py")
    scores = first_commit("artifacts/scored-cases-v1.json")
    assert rules != scores, "the rules and the scores arrived in one commit"
    assert _git("merge-base", "--is-ancestor", rules, scores) is not None, (
        f"{rules[:7]} (rules) is not an ancestor of {scores[:7]} (scores)"
    )


def test_gate_8_the_record_states_the_rule_it_was_graded_by() -> None:
    rules = _evaluation()["registered_rules"]
    assert rules["primary_case_rule"] == harness.PRIMARY_RULE == "max"
    assert set(rules["sensitivity_case_rules"]) == set(harness.RULES) - {harness.PRIMARY_RULE}
