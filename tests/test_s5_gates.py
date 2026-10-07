"""S5 acceptance gates: the evaluation record, checked against the documents it was built from.

`tests/eval/test_harness.py` pins the harness's rules on constructed inputs and was committed
with them. These gates are the other half: they run over the real committed artifacts.

**What "checked" means here, stated because an earlier version of this docstring overstated
it.** That version said each gate recomputed a figure by a second route. Several did not:
they re-derived a value from the record's own fields, or called the harness function under
test to produce the expectation. A pre-merge code review found that, and found that no gate
recomputed the tau-b values, the ordered-pair counts, the Critical/High counts or the
rank-change totals at all.

Every headline figure is now recomputed here, from the scored documents and the ground
truth, by code that takes nothing from `eval.harness` except the name of the registered
rule. `tests/_regrade.py` holds the grading - deliberately a second implementation: tau-b
from its definition, a tiering by sorted distinct scores, plain counters - and the helpers
below hold the counting. Where a gate checks something other than a figure - provenance
digests, commit ancestry, that the rule text is unchanged - it says so.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from _regrade import CONTEXT, RANK, claimed, grade_scenario, top_score
from eval import harness
from eval import run as eval_run
from eval.ground_truth import load_and_validate
from tools.harvest.provenance import hash_file
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent
BAND_ORDER = ("Critical", "High", "Medium", "Low")
ALERT = ("Critical", "High")


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


# --- the second implementation --------------------------------------------------------


def _case_findings(case_id: str) -> list[Mapping[str, Any]]:
    return claimed(_cases()["cases"][case_id]["findings"])


def _top_score(case_id: str) -> int:
    return top_score(_cases()["cases"][case_id]["findings"])


def _top_vector(case_id: str) -> tuple[dict[str, int], dict[str, str]]:
    """Contributions and states of a case's top finding.

    Does not reproduce the harness's tie-break. It requires instead that every finding at
    the top score carries one vector, which is what makes a tie-break immaterial.
    """
    top = _top_score(case_id)
    leaders = [f for f in _case_findings(case_id) if f["score"] == top]
    vectors = {
        json.dumps(
            [f["contributions"], {key: f["factor_states"][key] for key in CONTEXT}], sort_keys=True
        )
        for f in leaders
    }
    assert len(vectors) == 1, f"{case_id}: findings tied at the top score differ in their factors"
    return dict(leaders[0]["contributions"]), dict(leaders[0]["factor_states"])


def _baseline_rank(case_id: str) -> int:
    return max(RANK[f["baseline_band"]] for f in _case_findings(case_id))


def _low_confidence(case_id: str) -> bool:
    top = _top_score(case_id)
    flags = {f["low_confidence"] for f in _case_findings(case_id) if f["score"] == top}
    assert len(flags) == 1
    return bool(flags.pop())


def _ground_truth_excluded(case: dict[str, Any]) -> bool:
    return any(e.get("excluded_from_quality_claims", False) for e in case["expected"]["findings"])


def _bands(findings: list[Mapping[str, Any]], key: str) -> dict[str, int]:
    counted = Counter(f[key] for f in findings)
    return {band: counted.get(band, 0) for band in BAND_ORDER}


def _direction(finding: Mapping[str, Any]) -> int:
    after, before = RANK[finding["band"]], RANK[finding["baseline_band"]]
    return (after > before) - (after < before)


def _populations() -> dict[str, list[Mapping[str, Any]]]:
    ranked: list[Mapping[str, Any]] = list(_corpus()["findings"])
    eligible = claimed(ranked)
    return {
        "all_ranked": ranked,
        "context_eligible": eligible,
        "excluding_low_confidence": [f for f in eligible if not f["low_confidence"]],
    }


# --- gate 1: the record is the harness's verdict on the committed inputs ---------------
# Not a second route: these check freshness and provenance.


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


# --- gate 2: every case is graded, and shows what the oracle listed --------------------


def test_gate_2_every_ground_truth_case_is_graded_and_rankable() -> None:
    cases = _evaluation()["cases"]
    assert set(cases) == {case["case_id"] for case in _ground_truth()["cases"]}
    for case_id, graded in cases.items():
        assert graded["rankable"] is bool(_case_findings(case_id)), case_id
        assert graded["scores"]["max"] == _top_score(case_id), case_id
        assert graded["baseline"] == _baseline_rank(case_id), case_id


def test_gate_2_the_scored_output_shows_every_expected_class_and_every_listed_state() -> None:
    """Classes are compared both ways. States are compared ONE way: a state the oracle lists
    must be the state scored. The name of this test used to promise more than that, and with
    the body-index defect present the check passed on a case whose three parsed factors had
    all silently become unresolved. `unlisted_non_resolved` is what now makes that visible,
    and the next test recomputes it."""
    graded = _evaluation()["cases"]
    for case in _ground_truth()["cases"]:
        findings: list[dict[str, Any]] = list(_cases()["cases"][case["case_id"]]["findings"])
        expected = {
            (e["resource_identity"], e["issue_class"]) for e in case["expected"]["findings"]
        }
        scored = {(f["resource_identity"], f["issue_class"]) for f in findings}
        check = graded[case["case_id"]]["expectation"]
        assert check["classes_match"] is (expected == scored), case["case_id"]
        assert expected == scored, (case["case_id"], expected ^ scored)

        for entry in case["expected"]["findings"]:
            key = (entry["resource_identity"], entry["issue_class"])
            for field, state in (
                ("unresolved_factors", "unresolved"),
                ("defaulted_factors", "defaulted"),
            ):
                for factor in entry.get(field, []):
                    for finding in findings:
                        if (finding["resource_identity"], finding["issue_class"]) == key:
                            assert finding["factor_states"][factor] == state, (key, factor)
        assert check["states_match"] is True, case["case_id"]


def test_gate_2_non_resolved_factors_the_oracle_does_not_list_are_reported() -> None:
    reported_anything = False
    for case in _ground_truth()["cases"]:
        listed: dict[tuple[str, str], set[str]] = {}
        for entry in case["expected"]["findings"]:
            listed.setdefault((entry["resource_identity"], entry["issue_class"]), set()).update(
                entry.get("unresolved_factors", []), entry.get("defaulted_factors", [])
            )
        unlisted = set()
        for finding in _cases()["cases"][case["case_id"]]["findings"]:
            named = listed.get((finding["resource_identity"], finding["issue_class"]), set())
            for factor in CONTEXT:
                state = finding["factor_states"].get(factor)
                if state not in (None, "resolved") and factor not in named:
                    unlisted.add((factor, state))
        recorded = _evaluation()["cases"][case["case_id"]]["expectation"]["unlisted_non_resolved"]
        assert [(r["factor"], r["state"]) for r in recorded] == sorted(unlisted), case["case_id"]
        reported_anything = reported_anything or bool(unlisted)
    assert reported_anything, "nothing was unlisted anywhere; the report would be untested"


def test_gate_2_one_resource_under_one_declaration_has_one_contextual_vector() -> None:
    """What lets a case be compared by a single factor vector at all."""
    for case_id, graded in _evaluation()["cases"].items():
        vectors = {tuple(f["contributions"][k] for k in CONTEXT) for f in _case_findings(case_id)}
        assert graded["context_uniform"] is (len(vectors) == 1), case_id
        assert len(vectors) == 1, case_id


# --- gate 3: the pair verdicts follow from the registered rule -------------------------


def test_gate_3_every_pair_verdict_is_strictly_greater_than_on_top_scores() -> None:
    pairs = _evaluation()["contrastive_pairs"]["pairs"]
    assert len(pairs) == len(_ground_truth()["contrastive_pairs"])
    for pair in pairs:
        assert pair["evaluable"]
        high, low = _top_score(pair["case_high"]), _top_score(pair["case_low"])
        assert pair["framework"]["max"]["passes"] is (high > low), pair["pair_id"]
        assert pair["framework"]["max"]["delta"] == high - low

        base_high, base_low = _baseline_rank(pair["case_high"]), _baseline_rank(pair["case_low"])
        assert pair["baseline"]["passes"] is (base_high > base_low), pair["pair_id"]


def test_gate_3_isolation_and_mechanism_are_recomputed_from_the_scored_cases() -> None:
    """From the two cases' top findings in the scored document, not from the record's own
    `context_delta` - the earlier form of this gate derived the verdict from the field it
    was meant to check."""
    for pair in _evaluation()["contrastive_pairs"]["pairs"]:
        factor = pair["factor_under_test"]
        high, high_states = _top_vector(pair["case_high"])
        low, low_states = _top_vector(pair["case_low"])
        delta = {key: high[key] - low[key] for key in CONTEXT}

        assert pair["context_delta"] == delta, pair["pair_id"]
        assert pair["severity_delta"] == high["severity"] - low["severity"], pair["pair_id"]
        assert pair["isolated"] is ({k for k, v in delta.items() if v} == {factor}), pair["pair_id"]
        assert pair["mechanism"] is (delta.get(factor, 0) > 0), pair["pair_id"]
        assert pair["non_resolved_on_both_sides"] == [
            key
            for key in CONTEXT
            if key != factor and high_states[key] != "resolved" and low_states[key] != "resolved"
        ], pair["pair_id"]


def test_gate_3_the_pair_summary_is_recounted() -> None:
    by_case = {case["case_id"]: case for case in _ground_truth()["cases"]}
    rows = []
    for pair in _ground_truth()["contrastive_pairs"]:
        sides = (pair["case_high"], pair["case_low"])
        high, high_states = _top_vector(pair["case_high"])
        low, low_states = _top_vector(pair["case_low"])
        moved = {k for k in CONTEXT if high[k] != low[k]}
        rows.append(
            {
                "factor": pair["factor_under_test"],
                "shared_default": any(
                    high_states[k] != "resolved" and low_states[k] != "resolved"
                    for k in CONTEXT
                    if k != pair["factor_under_test"]
                ),
                "passes": _top_score(sides[0]) > _top_score(sides[1]),
                "baseline": _baseline_rank(sides[0]) > _baseline_rank(sides[1]),
                "isolated": moved == {pair["factor_under_test"]},
                "hand_crafted": any(by_case[c]["source"] == "hand-crafted" for c in sides),
                "clean": not any(
                    _ground_truth_excluded(by_case[c]) or _low_confidence(c) for c in sides
                ),
            }
        )
    summary = _evaluation()["contrastive_pairs"]["summary"]

    def check(block: dict[str, Any], subset: list[dict[str, Any]]) -> None:
        assert block["pairs"] == len(subset)
        assert block["framework_passes"]["max"] == sum(r["passes"] for r in subset)
        assert block["baseline_passes"] == sum(r["baseline"] for r in subset)
        assert block["isolated"] == sum(r["isolated"] for r in subset)
        assert block["isolated_without_a_shared_default"] == sum(
            r["isolated"] and not r["shared_default"] for r in subset
        )

    check(summary["authored"], rows)
    check(summary["clean"], [r for r in rows if r["clean"]])
    check(summary["by_source"]["mined"], [r for r in rows if not r["hand_crafted"]])
    check(summary["by_source"]["hand_crafted"], [r for r in rows if r["hand_crafted"]])
    for factor, block in summary["by_factor"].items():
        check(block, [r for r in rows if r["factor"] == factor])
    assert set(summary["by_factor"]) == {r["factor"] for r in rows}


# --- gate 4: the scenario verdicts follow from the registered rule ---------------------


def test_gate_4_every_scenario_figure_is_recomputed_for_the_framework_and_the_baseline() -> None:
    graded = {s["scenario_id"]: s for s in _evaluation()["scenarios"]["scenarios"]}
    for scenario in _ground_truth()["scenarios"]:
        record = graded[scenario["scenario_id"]]
        tiers = scenario["expected_ordering"]
        ids = [case_id for tier in tiers for case_id in tier]
        assert record["evaluable"]
        assert record["expected_ordering"] == tiers

        systems = (
            (record["framework"]["max"], {c: _top_score(c) for c in ids}),
            (record["baseline"], {c: _baseline_rank(c) for c in ids}),
        )
        for block, scores in systems:
            mine = grade_scenario(tiers, scores)
            assert block["ordering"] == mine["ordering"], scenario["scenario_id"]
            assert block["exact_tier_match"] is mine["exact"], scenario["scenario_id"]
            if mine["tau_b"] is None:
                assert block["kendall_tau_b"] is None, scenario["scenario_id"]
            else:
                assert block["kendall_tau_b"] == pytest.approx(mine["tau_b"])
            assert block["ordered_pairs"] == {
                "expected": mine["counts"]["ordered"],
                "concordant": mine["counts"]["concordant"],
                "tied": mine["counts"]["tied"],
                "discordant": mine["counts"]["discordant"],
            }, scenario["scenario_id"]
            assert block["tied_pairs"] == {
                "expected": mine["counts"]["tied_expected"],
                "tied_as_expected": mine["counts"]["tied_as_expected"],
            }, scenario["scenario_id"]


def test_gate_4_the_headline_and_clean_tallies_are_recounted() -> None:
    by_case = {case["case_id"]: case for case in _ground_truth()["cases"]}
    summary = _evaluation()["scenarios"]["summary"]
    scenarios = _ground_truth()["scenarios"]
    headline = [s for s in scenarios if s["oracle"]["reviewer_verdict"] != "disagree"]
    assert summary["authored"] == len(scenarios)
    assert summary["excluded_as_disagree"] == len(scenarios) - len(headline)

    def clean(scenario: dict[str, Any]) -> bool:
        ids = [c for tier in scenario["expected_ordering"] for c in tier]
        return not any(_ground_truth_excluded(by_case[c]) or _low_confidence(c) for c in ids)

    def tally(subset: list[dict[str, Any]], score: Any) -> Counter[str]:
        total: Counter[str] = Counter()
        for scenario in subset:
            ids = [c for tier in scenario["expected_ordering"] for c in tier]
            mine = grade_scenario(scenario["expected_ordering"], {c: score(c) for c in ids})
            total["exact"] += mine["exact"]
            total.update(mine["counts"])
        return total

    for name, subset in (("headline", headline), ("clean", [s for s in headline if clean(s)])):
        block = summary[name]
        assert block["scenarios"] == len(subset), name
        for recorded, score in (
            (block["framework"]["max"], _top_score),
            (block["baseline"], _baseline_rank),
        ):
            mine = tally(subset, score)
            assert recorded["exact_tier_matches"] == mine["exact"], name
            assert recorded["ordered_pairs_expected"] == mine["ordered"], name
            assert recorded["ordered_pairs_concordant"] == mine["concordant"], name
            assert recorded["ordered_pairs_tied"] == mine["tied"], name
            assert recorded["ordered_pairs_discordant"] == mine["discordant"], name
            assert recorded["tied_pairs_as_expected"] == mine["tied_as_expected"], name


# --- gate 5: alert reduction is two numbers --------------------------------------------


def test_gate_5_alert_reduction_is_two_numbers_and_no_field_combines_them() -> None:
    reduction = _evaluation()["alert_reduction"]
    assert set(reduction) == {"deduplication", "priority_band"}

    population = _corpus()["population"]
    retention = _corpus()["retention"]
    dedup = reduction["deduplication"]
    assert dedup["findings_in"] == population["findings_in"]
    assert dedup["tier1_collapsed"] == retention["tier1_collapsed"]
    assert dedup["ranked"] == len(_corpus()["findings"])
    assert dedup["ranked"] == dedup["findings_in"] - dedup["tier1_collapsed"]
    assert dedup["reduction_rate"] == dedup["tier1_collapsed"] / dedup["findings_in"]
    assert dedup["tier2_candidates_not_merged"] == {
        "cross_scanner": retention["tier2_cross_scanner"],
        "same_scanner": retention["tier2_same_scanner"],
    }


def test_gate_5_every_band_figure_is_recounted_from_the_ranked_findings() -> None:
    """Three populations, each counted here from the per-finding list: everything ranked,
    the context-eligible findings, and those of them the rubric's reporting rule admits to
    a prioritization-quality claim."""
    recorded = _evaluation()["alert_reduction"]["priority_band"]
    populations = _populations()
    assert set(recorded) == set(populations)
    for name, findings in populations.items():
        block = recorded[name]
        baseline, framework = _bands(findings, "baseline_band"), _bands(findings, "band")
        before = sum(baseline[band] for band in ALERT)
        after = sum(framework[band] for band in ALERT)
        unknown = [f for f in findings if f["factor_states"]["severity"] != "resolved"]

        assert block["findings"] == len(findings), name
        assert block["baseline"] == baseline, name
        assert block["framework"] == framework, name
        assert block["baseline_critical_or_high"] == before, name
        assert block["framework_critical_or_high"] == after, name
        assert block["reduction"] == before - after, name
        assert block["reduction_rate"] == pytest.approx((before - after) / before), name
        assert block["baseline_from_unknown_severity"] == len(unknown), name
        assert block["baseline_critical_or_high_from_unknown_severity"] == sum(
            1 for f in unknown if f["baseline_band"] in ALERT
        ), name
    assert len(populations["excluding_low_confidence"]) < len(populations["context_eligible"])


def test_gate_5_the_harness_and_the_framework_count_the_same_bands() -> None:
    """The framework's own report counted bands when it scored; the harness counted them
    again from the list. Two programs, one answer."""
    bands = _evaluation()["alert_reduction"]["priority_band"]
    report = _corpus()["report"]
    assert bands["all_ranked"]["framework"] == {b: report["overall"][b] for b in BAND_ORDER}
    assert bands["context_eligible"]["framework"] == {
        b: report["eligible_only"][b] for b in BAND_ORDER
    }


# --- gate 6: the rank-change table accounts for every finding it claims ----------------


def test_gate_6_the_rank_change_table_is_recounted_for_both_populations() -> None:
    table = _evaluation()["baseline_comparison"]
    populations = _populations()
    for recorded, findings in (
        (table, populations["context_eligible"]),
        (table["excluding_low_confidence"], populations["excluding_low_confidence"]),
    ):
        assert recorded["findings"] == len(findings)
        for name, direction in (("promoted", 1), ("demoted", -1), ("unchanged", 0)):
            moved = [f for f in findings if _direction(f) == direction]
            assert recorded[name] == {
                "count": len(moved),
                "low_confidence": sum(1 for f in moved if f["low_confidence"]),
                "baseline_from_unknown_severity": sum(
                    1 for f in moved if f["factor_states"]["severity"] != "resolved"
                ),
            }, name

        cells: dict[str, list[Mapping[str, Any]]] = {}
        for finding in findings:
            cells.setdefault(f"{finding['baseline_band']}->{finding['band']}", []).append(finding)
        assert set(recorded["cells"]) == set(cells)
        for key, members in cells.items():
            cell = recorded["cells"][key]
            assert cell["count"] == len(members), key
            assert cell["low_confidence"] == sum(1 for f in members if f["low_confidence"]), key
            for factor in CONTEXT:
                mean = sum(f["contributions"][factor] for f in members) / len(members)
                share = sum(1 for f in members if f["factor_states"][factor] == "resolved") / len(
                    members
                )
                assert cell["mean_contribution"][factor] == pytest.approx(mean), (key, factor)
                assert cell["resolved_share"][factor] == pytest.approx(share), (key, factor)
        assert sum(cell["count"] for cell in recorded["cells"].values()) == len(findings)


# --- gate 7: retention --------------------------------------------------------------------


def test_gate_7_retention_is_the_sum_of_the_adapter_runs() -> None:
    """`findings_in` is derived upstream as out plus dropped, so that identity is not
    asserted here as if it were a finding. What is checked: the totals are the sum of the
    per-run figures the corpus document carries, and `findings_out` equals an independent
    count - the number of findings the pipeline scored before the collapse."""
    retention = _evaluation()["retention"]
    runs = _corpus()["retention"]["scanners"]

    assert retention["runs"] == len(runs)
    for key in (
        "findings_in",
        "findings_out",
        "unknown_severity",
        "unmapped",
        "context_ineligible",
    ):
        assert retention[key] == sum(run[key] for run in runs.values()), key
    assert retention["dropped"] == sum(len(run["dropped"]) for run in runs.values())
    assert retention["findings_out"] == _corpus()["before_dedupe"]["population"]["ranked"]
    assert retention["retention_rate"] == retention["findings_out"] / retention["findings_in"]
    assert retention["unknown_severity_rate"] == pytest.approx(
        retention["unknown_severity"] / retention["findings_in"]
    )


# --- gate 8: the rules were registered before the case artifact, and have not moved ----
# Not a second route: these check the repository's history.


def _first_commit(path: str) -> str:
    added = _git("log", "--diff-filter=A", "--format=%H", "--", path)
    assert added, f"{path} has no adding commit in history"
    return added.splitlines()[-1]


def _rules_text(source: str) -> str:
    """The eight numbered rules of the harness docstring, from rule 1 to the end of rule 8."""
    start = source.index("1. **A case ranks")
    end = source.index("and this module never adds them.") + len("and this module never adds them.")
    return source[start:end]


def test_gate_8_the_harness_was_committed_before_the_case_artifact_it_grades() -> None:
    """What this establishes is commit order, and only that: the commit that first added
    `eval/harness.py` is a strict ancestor of the one that first added
    `artifacts/scored-cases-v1.json`. It cannot see a score computed and never committed,
    and the harness's own docstring states what was computed before the rules were."""
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")
    rules = _first_commit("eval/harness.py")
    scores = _first_commit("artifacts/scored-cases-v1.json")
    assert rules != scores, "the rules and the scores arrived in one commit"
    assert _git("merge-base", "--is-ancestor", rules, scores) is not None, (
        f"{rules[:7]} (rules) is not an ancestor of {scores[:7]} (scores)"
    )


def test_gate_8_the_registered_rules_are_word_for_word_what_was_registered() -> None:
    """The module has changed since registration, and says how. The eight rules have not:
    their text at HEAD is compared with their text in the commit that registered them."""
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")
    registered = _git("show", f"{_first_commit('eval/harness.py')}:eval/harness.py")
    assert registered is not None
    current = (REPO_ROOT / "eval" / "harness.py").read_text(encoding="utf-8")
    assert _rules_text(current) == _rules_text(registered.replace("\r\n", "\n"))


def test_gate_8_the_record_states_the_rule_it_was_graded_by() -> None:
    rules = _evaluation()["registered_rules"]
    assert rules["primary_case_rule"] == harness.PRIMARY_RULE == "max"
    assert set(rules["sensitivity_case_rules"]) == set(harness.RULES) - {harness.PRIMARY_RULE}
