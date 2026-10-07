"""`eval.harness` on constructed documents only.

Every input here is hand-built, and that is deliberate rather than a shortcut: these tests
were written and committed before `artifacts/scored-cases-v1.json` existed, so the harness's
rules could be pinned without any real case-level score having been seen. The gates over the
real artifacts live in `tests/test_s5_gates.py`, added afterwards.

That holds for the tests of the eight rules. The tests of what the harness only *reports* -
unlisted non-resolved factors, a case's factor states, the factors a pair leaves to a
default on both sides, and the figures without low-confidence findings - were added on
2026-10-07 with those fields, after a pre-merge code review and after the results were known.
"""

from __future__ import annotations

from typing import Any

import pytest

from eval import harness

CONTEXT = {"exposure": 3, "privilege": 4, "sensitivity": 3, "criticality": 3, "encryption": 2}


def _finding(
    score_severity: int = 3,
    *,
    issue_class: str = "storage-encryption-at-rest",
    identity: str = "aws_s3_bucket.a",
    baseline_band: str = "Medium",
    unmapped: bool = False,
    baseline_only: bool = False,
    low_confidence: bool = False,
    severity_state: str = "resolved",
    states: dict[str, str] | None = None,
    **context: int,
) -> dict[str, Any]:
    contributions = {"severity": score_severity, **CONTEXT, **context}
    factor_states = {"severity": severity_state, **dict.fromkeys(CONTEXT, "resolved")}
    factor_states.update(states or {})
    score = sum(contributions.values())
    band = (
        "Critical" if score >= 22 else "High" if score >= 16 else "Medium" if score >= 9 else "Low"
    )
    return {
        "resource_identity": identity,
        "issue_class": issue_class,
        "scanner": "trivy",
        "rule_id": "AVD-X",
        "score": score,
        "band": band,
        "baseline_band": baseline_band,
        "contributions": contributions,
        "factor_states": factor_states,
        "low_confidence": low_confidence,
        "unmapped": unmapped,
        "baseline_only_informational": baseline_only,
    }


def _case(case_id: str, findings: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    expected = [
        {"resource_identity": f["resource_identity"], "issue_class": f["issue_class"]}
        for f in findings
    ]
    return {
        "case_id": case_id,
        "domain": "storage",
        "source": {"repo": "r", "commit": "abcdef0", "path": "p"},
        "expected": {"findings": expected},
        **overrides,
    }


def _scored(case_id: str, findings: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    return harness.case_score(_case(case_id, findings, **overrides), {"findings": findings})


# --- Kendall's tau-b ------------------------------------------------------------------


def test_tau_b_reproduces_the_two_partial_agreements_the_s2_handoff_records() -> None:
    """The S2 handoff reports the blinded reviewer's agreement as tau-b 0.333 on the compute
    scenario and 0.500 on containers, and both orderings are written out in corpus v1's
    disagreement notes. Recomputing them here ties this implementation to the statistic the
    project already published, rather than to a definition of its own.
    """
    # compute: author web > db > ebs; reviewer db > web > ebs.
    assert harness.kendall_tau_b([3, 2, 1], [2, 3, 1]) == pytest.approx(1 / 3)
    # containers: author goat > (kube-bench = proxy); reviewer (goat = proxy) > kube-bench.
    assert harness.kendall_tau_b([2, 1, 1], [2, 1, 2]) == pytest.approx(0.5)


def test_tau_b_is_one_for_agreement_and_minus_one_for_reversal() -> None:
    assert harness.kendall_tau_b([1, 2, 3, 4], [10, 20, 30, 40]) == pytest.approx(1.0)
    assert harness.kendall_tau_b([1, 2, 3, 4], [40, 30, 20, 10]) == pytest.approx(-1.0)


def test_tau_b_is_none_not_zero_when_one_side_is_tied_throughout() -> None:
    assert harness.kendall_tau_b([1, 2, 3], [5, 5, 5]) is None
    assert harness.kendall_tau_b([7, 7], [1, 2]) is None


def test_tau_b_rejects_unpaired_observations() -> None:
    with pytest.raises(ValueError, match="differ in length"):
        harness.kendall_tau_b([1, 2], [1])


def test_tiers_group_equal_scores_highest_first() -> None:
    assert harness.tiers_from_scores({"a": 20, "b": 17, "c": 20, "d": 9}) == [
        ["a", "c"],
        ["b"],
        ["d"],
    ]


# --- a case ---------------------------------------------------------------------------


def test_a_case_ranks_at_its_highest_finding_and_reports_sum_and_mean_beside_it() -> None:
    low, high = _finding(2), _finding(5, issue_class="storage-public-accessibility")
    scored = _scored("c", [low, high])

    assert scored["scores"] == {
        "max": high["score"],
        "sum": low["score"] + high["score"],
        "mean": (low["score"] + high["score"]) / 2,
    }
    assert scored["contributions"] == high["contributions"]
    assert scored["rankable"] is True
    assert harness.PRIMARY_RULE == "max"


def test_unmapped_and_baseline_only_findings_do_not_rank_a_case() -> None:
    counted = _finding(2)
    unmapped = _finding(5, issue_class="unmapped:checkov:CKV_X", unmapped=True)
    informational = _finding(5, issue_class="iam-hardcoded-secrets", baseline_only=True)
    scored = _scored("c", [counted, unmapped, informational])

    assert scored["scores"]["max"] == counted["score"]
    assert (scored["findings"], scored["counted"], scored["set_aside"]) == (3, 1, 2)


def test_a_case_with_nothing_to_count_is_unrankable_not_zero() -> None:
    scored = _scored("c", [_finding(5, issue_class="unmapped:checkov:CKV_X", unmapped=True)])

    assert scored["rankable"] is False
    assert scored["scores"] == {"max": None, "sum": None, "mean": None}
    assert scored["baseline"] is None
    assert scored["low_confidence"] is None


def test_the_baseline_ranks_a_case_by_its_highest_baseline_band() -> None:
    scored = _scored("c", [_finding(2, baseline_band="Low"), _finding(4, baseline_band="High")])
    assert scored["baseline"] == harness.BAND_RANK["High"]


def test_contextual_contributions_that_disagree_within_a_case_are_reported() -> None:
    assert _scored("c", [_finding(2), _finding(3)])["context_uniform"] is True
    assert _scored("c", [_finding(2), _finding(3, exposure=5)])["context_uniform"] is False


def test_the_expectation_check_names_classes_the_scored_output_lacks_or_adds() -> None:
    findings = [_finding(2, issue_class="storage-logging-audit")]
    case = _case("c", findings)
    case["expected"]["findings"].append(
        {"resource_identity": "aws_s3_bucket.a", "issue_class": "storage-encryption-at-rest"}
    )
    findings.append(_finding(2, issue_class="storage-data-recoverability"))
    check = harness.case_score(case, {"findings": findings})["expectation"]

    assert check["classes_match"] is False
    assert check["missing_from_scored"] == ["storage-encryption-at-rest"]
    assert check["not_in_ground_truth"] == ["storage-data-recoverability"]


def test_the_expectation_check_holds_a_recorded_state_against_the_scored_one() -> None:
    finding = _finding(2, states={"exposure": "unresolved"})
    case = _case("c", [finding])
    case["expected"]["findings"][0]["unresolved_factors"] = ["exposure"]
    case["expected"]["findings"][0]["defaulted_factors"] = ["sensitivity"]
    check = harness.case_score(case, {"findings": [finding]})["expectation"]

    assert check["states_match"] is False
    assert check["state_mismatches"] == [
        {
            "issue_class": finding["issue_class"],
            "factor": "sensitivity",
            "expected": "defaulted",
            "scored": "resolved",
        }
    ]


def test_a_listed_state_that_matches_is_not_a_mismatch_and_is_not_reported_as_unlisted() -> None:
    finding = _finding(2, states={"exposure": "unresolved"})
    case = _case("c", [finding])
    case["expected"]["findings"][0]["unresolved_factors"] = ["exposure"]
    check = harness.case_score(case, {"findings": [finding]})["expectation"]

    assert check["states_match"] is True
    assert check["unlisted_non_resolved"] == []


def test_a_non_resolved_factor_the_oracle_does_not_list_is_reported_and_not_judged() -> None:
    """The state check runs one way. A factor the framework left unresolved and the ground
    truth never mentions is not a mismatch - but it is no longer invisible either."""
    finding = _finding(2, states={"privilege": "unresolved", "sensitivity": "defaulted"})
    check = _scored("c", [finding])["expectation"]

    assert check["states_match"] is True
    assert check["unlisted_non_resolved"] == [
        {"factor": "privilege", "state": "unresolved"},
        {"factor": "sensitivity", "state": "defaulted"},
    ]


def test_a_case_reports_the_factor_states_of_its_top_finding() -> None:
    low = _finding(2)
    high = _finding(
        5, issue_class="storage-public-accessibility", states={"exposure": "unresolved"}
    )
    scored = _scored("c", [low, high])

    assert scored["factor_states"] == high["factor_states"]
    unrankable = _scored("u", [_finding(5, issue_class="unmapped:checkov:CKV_X", unmapped=True)])
    assert unrankable["factor_states"] is None


def test_a_ground_truth_exclusion_flag_reaches_the_case() -> None:
    finding = _finding(2)
    case = _case("c", [finding])
    assert harness.case_score(case, {"findings": [finding]})["ground_truth_excluded"] is False
    case["expected"]["findings"][0]["excluded_from_quality_claims"] = True
    assert harness.case_score(case, {"findings": [finding]})["ground_truth_excluded"] is True


# --- contrastive pairs ----------------------------------------------------------------


def _pair(factor: str = "sensitivity") -> dict[str, Any]:
    return {"pair_id": "p", "factor_under_test": factor, "case_high": "hi", "case_low": "lo"}


def test_a_pair_passes_only_when_the_high_case_scores_strictly_higher() -> None:
    cases = {"hi": _scored("hi", [_finding(3, sensitivity=5)]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["framework"]["max"] == {
        "high": cases["hi"]["scores"]["max"],
        "low": cases["lo"]["scores"]["max"],
        "delta": 2,
        "passes": True,
    }
    assert result["mechanism"] is True
    assert result["isolated"] is True
    assert result["severity_delta"] == 0


def test_a_tie_is_a_failure_not_a_pass() -> None:
    cases = {"hi": _scored("hi", [_finding(3)]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["framework"]["max"]["passes"] is False
    assert result["mechanism"] is False
    assert result["isolated"] is False, "nothing moved, so the factor under test did not either"


def test_a_pair_can_pass_while_a_second_contextual_factor_moves_with_it() -> None:
    cases = {
        "hi": _scored("hi", [_finding(3, sensitivity=5, exposure=4)]),
        "lo": _scored("lo", [_finding(3)]),
    }
    result = harness.evaluate_pair(_pair(), cases)

    assert result["framework"]["max"]["passes"] is True
    assert result["mechanism"] is True
    assert result["isolated"] is False
    assert result["context_delta"]["exposure"] == 1


def test_a_pair_can_pass_on_another_factor_while_the_one_under_test_does_not_move() -> None:
    """The confound the isolation check exists for: the score delta is positive and the
    named factor contributed nothing to it."""
    cases = {"hi": _scored("hi", [_finding(3, exposure=5)]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["framework"]["max"]["passes"] is True
    assert result["mechanism"] is False
    assert result["isolated"] is False


def test_severity_moving_is_reported_and_does_not_break_isolation() -> None:
    cases = {"hi": _scored("hi", [_finding(5, sensitivity=5)]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["isolated"] is True
    assert result["severity_delta"] == 2
    assert result["framework"]["max"]["delta"] == 4


def test_a_pair_names_the_other_factors_both_sides_left_to_a_default() -> None:
    """Isolation is tested on contributions, so two cases that agree on a factor because
    both took its default are isolated by that default. The pair says which factors those
    are; the factor under test is never among them, and a factor one side resolved is not."""
    both = {"exposure": "unresolved", "encryption": "unresolved", "sensitivity": "defaulted"}
    cases = {
        "hi": _scored("hi", [_finding(3, sensitivity=5, states=both)]),
        "lo": _scored("lo", [_finding(3, states={**both, "exposure": "resolved"})]),
    }
    result = harness.evaluate_pair(_pair(), cases)

    assert result["isolated"] is True
    assert result["non_resolved_on_both_sides"] == ["encryption"]


def test_a_pair_with_an_unrankable_side_is_not_evaluable_rather_than_failed() -> None:
    unmapped = _finding(5, issue_class="unmapped:checkov:CKV_X", unmapped=True)
    cases = {"hi": _scored("hi", [unmapped]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["evaluable"] is False
    assert result["framework"]["max"]["passes"] is None
    assert result["baseline"]["passes"] is None
    assert result["isolated"] is None
    assert result["non_resolved_on_both_sides"] is None


def test_the_baseline_cannot_pass_a_pair_that_differs_only_in_declared_context() -> None:
    cases = {"hi": _scored("hi", [_finding(3, sensitivity=5)]), "lo": _scored("lo", [_finding(3)])}
    result = harness.evaluate_pair(_pair(), cases)

    assert result["baseline"] == {"high": 2, "low": 2, "delta": 0, "passes": False}


def test_the_rules_can_disagree_and_each_is_reported_under_its_own_name() -> None:
    """One strong finding against three weaker ones: `max` and `mean` favour the first,
    `sum` the second. The primary rule's verdict is not overwritten by either."""
    cases = {
        "hi": _scored("hi", [_finding(5)]),
        "lo": _scored("lo", [_finding(3), _finding(3), _finding(3)]),
    }
    result = harness.evaluate_pair(_pair("severity"), cases)

    assert result["framework"]["max"]["passes"] is True
    assert result["framework"]["mean"]["passes"] is True
    assert result["framework"]["sum"]["passes"] is False


def test_the_pair_summary_counts_clean_and_hand_crafted_pairs_separately() -> None:
    cases = {
        "hi": _scored("hi", [_finding(3, sensitivity=5)]),
        "lo": _scored("lo", [_finding(3)]),
        "weak": _scored("weak", [_finding(3, low_confidence=True)]),
        "crafted": _scored("crafted", [_finding(3, sensitivity=4)], source="hand-crafted"),
    }
    pairs = [
        harness.evaluate_pair({**_pair(), "pair_id": "clean"}, cases),
        harness.evaluate_pair({**_pair(), "pair_id": "lc", "case_low": "weak"}, cases),
        harness.evaluate_pair({**_pair(), "pair_id": "hc", "case_high": "crafted"}, cases),
    ]
    summary = harness._summarise_pairs(pairs)

    assert summary["authored"]["pairs"] == 3
    assert summary["authored"]["framework_passes"]["max"] == 3
    assert summary["clean"]["pairs"] == 2, "the low-confidence pair is not clean"
    assert summary["by_source"]["hand_crafted"]["pairs"] == 1
    assert summary["by_source"]["mined"]["pairs"] == 2
    assert summary["by_factor"]["sensitivity"]["baseline_passes"] == 0


def test_the_pair_summary_counts_isolation_that_owes_nothing_to_a_shared_default() -> None:
    shared = {"encryption": "unresolved"}
    cases = {
        "hi": _scored("hi", [_finding(3, sensitivity=5)]),
        "lo": _scored("lo", [_finding(3)]),
        "hi2": _scored("hi2", [_finding(3, sensitivity=5, states=shared)]),
        "lo2": _scored("lo2", [_finding(3, states=shared)]),
    }
    pairs = [
        harness.evaluate_pair({**_pair(), "pair_id": "read"}, cases),
        harness.evaluate_pair(
            {**_pair(), "pair_id": "defaulted", "case_high": "hi2", "case_low": "lo2"}, cases
        ),
    ]
    tally = harness._summarise_pairs(pairs)["authored"]

    assert tally["isolated"] == 2
    assert tally["isolated_without_a_shared_default"] == 1


# --- scenarios ------------------------------------------------------------------------


def _scenario(tiers: list[list[str]], verdict: str = "agree") -> dict[str, Any]:
    return {
        "scenario_id": "s",
        "domain": "storage",
        "expected_ordering": tiers,
        "oracle": {"reviewer_verdict": verdict},
    }


def _three() -> dict[str, dict[str, Any]]:
    return {
        "a": _scored("a", [_finding(3, sensitivity=5)]),
        "b": _scored("b", [_finding(3, sensitivity=4)]),
        "c": _scored("c", [_finding(3)]),
        "c2": _scored("c2", [_finding(3)]),
    }


def test_a_scenario_matches_when_the_scores_induce_exactly_the_expected_tiers() -> None:
    result = harness.evaluate_scenario(_scenario([["a"], ["b"], ["c", "c2"]]), _three())
    graded = result["framework"]["max"]

    assert graded["exact_tier_match"] is True
    assert graded["ordering"] == [["a"], ["b"], ["c", "c2"]]
    assert graded["ordered_pairs"] == {"expected": 5, "concordant": 5, "tied": 0, "discordant": 0}
    assert graded["tied_pairs"] == {"expected": 1, "tied_as_expected": 1}
    assert graded["kendall_tau_b"] == pytest.approx(1.0)


def test_an_inverted_tier_is_discordant_and_breaks_the_exact_match() -> None:
    graded = harness.evaluate_scenario(_scenario([["b"], ["a"], ["c"]]), _three())["framework"][
        "max"
    ]

    assert graded["exact_tier_match"] is False
    assert graded["ordered_pairs"] == {"expected": 3, "concordant": 2, "tied": 0, "discordant": 1}
    assert graded["kendall_tau_b"] == pytest.approx(1 / 3)


def test_scoring_an_expected_tie_apart_or_an_expected_order_level_is_counted() -> None:
    split = harness.evaluate_scenario(_scenario([["a", "b"], ["c"]]), _three())["framework"]["max"]
    assert split["tied_pairs"] == {"expected": 1, "tied_as_expected": 0}
    assert split["exact_tier_match"] is False

    level = harness.evaluate_scenario(_scenario([["c"], ["c2"]]), _three())["framework"]["max"]
    assert level["ordered_pairs"] == {"expected": 1, "concordant": 0, "tied": 1, "discordant": 0}
    assert level["kendall_tau_b"] is None


def test_the_baseline_is_graded_on_the_same_scenario_by_the_same_rules() -> None:
    result = harness.evaluate_scenario(_scenario([["a"], ["b"], ["c"]]), _three())

    assert result["baseline"]["exact_tier_match"] is False
    assert result["baseline"]["ordering"] == [["a", "b", "c"]]
    assert result["baseline"]["kendall_tau_b"] is None


def test_a_scenario_with_an_unrankable_case_is_not_evaluable() -> None:
    cases = _three()
    cases["x"] = _scored("x", [_finding(5, issue_class="unmapped:checkov:CKV_X", unmapped=True)])
    result = harness.evaluate_scenario(_scenario([["a"], ["x"]]), cases)

    assert result["evaluable"] is False
    assert result["framework"] is None


def test_only_a_disagree_verdict_removes_a_scenario_from_the_headline() -> None:
    cases = _three()
    scenarios = [
        harness.evaluate_scenario(_scenario([["a"], ["b"]], verdict), cases)
        for verdict in ("agree", "partial", "disagree")
    ]
    summary = harness._summarise_scenarios(scenarios)

    assert summary["authored"] == 3
    assert summary["excluded_as_disagree"] == 1
    assert summary["headline"]["scenarios"] == 2
    assert summary["headline"]["framework"]["max"]["exact_tier_matches"] == 2
    assert summary["headline"]["baseline"]["exact_tier_matches"] == 0


def test_a_scenario_holding_a_low_confidence_or_excluded_case_is_not_clean() -> None:
    cases = _three()
    cases["weak"] = _scored("weak", [_finding(2, low_confidence=True)])
    scenarios = [
        harness.evaluate_scenario(_scenario([["a"], ["b"]]), cases),
        harness.evaluate_scenario(_scenario([["a"], ["weak"]]), cases),
    ]
    summary = harness._summarise_scenarios(scenarios)

    assert summary["headline"]["scenarios"] == 2
    assert summary["clean"]["scenarios"] == 1


# --- the corpus-level metrics ---------------------------------------------------------


def _corpus() -> dict[str, Any]:
    findings = [
        _finding(4, baseline_band="High"),  # 19, High -> High
        _finding(4, baseline_band="High", privilege=0, encryption=0),  # 13, High -> Medium
        _finding(  # 17, Low -> High, and low-confidence
            2, baseline_band="Low", severity_state="unresolved", low_confidence=True
        ),
        _finding(5, baseline_band="Critical", baseline_only=True),
    ]
    run = {
        "findings_in": 5,
        "findings_out": 5,
        "dropped": [],
        "identity_unresolved": 1,
        "unmapped": 0,
        "unknown_severity": 1,
        "context_ineligible": 1,
    }
    return {
        "population": {"findings_in": 5, "tier1_collapsed": 1, "ranked": 4},
        "retention": {
            "scanners": {"trivy/terraform": run},
            "tier1_collapsed": 1,
            "tier2_cross_scanner": 2,
            "tier2_same_scanner": 3,
        },
        "findings": findings,
    }


def test_alert_reduction_reports_two_numbers_and_never_their_sum() -> None:
    result = harness.alert_reduction(_corpus())

    assert set(result) == {"deduplication", "priority_band"}
    assert result["deduplication"]["reduction_rate"] == pytest.approx(1 / 5)
    assert result["deduplication"]["tier2_candidates_not_merged"] == {
        "cross_scanner": 2,
        "same_scanner": 3,
    }


def test_band_reduction_is_counted_with_and_without_the_set_aside_findings() -> None:
    bands = harness.alert_reduction(_corpus())["priority_band"]

    assert bands["all_ranked"]["findings"] == 4
    assert bands["context_eligible"]["findings"] == 3
    assert bands["context_eligible"]["baseline_critical_or_high"] == 2
    assert bands["context_eligible"]["framework_critical_or_high"] == 2
    assert bands["context_eligible"]["reduction"] == 0
    assert bands["all_ranked"]["baseline_critical_or_high"] == 3


def test_band_reduction_is_counted_again_without_the_low_confidence_findings() -> None:
    """The rubric's reporting rule excludes a low-confidence finding from a
    prioritization-quality claim, which is a narrower population than context-eligible.
    Here the one low-confidence finding is the one that was promoted into High, so the two
    populations give different reductions: none, and one of two."""
    bands = harness.alert_reduction(_corpus())["priority_band"]

    assert set(bands) == {"all_ranked", "context_eligible", "excluding_low_confidence"}
    confident = bands["excluding_low_confidence"]
    assert confident["findings"] == 2
    assert confident["baseline_critical_or_high"] == 2
    assert confident["framework_critical_or_high"] == 1
    assert confident["reduction_rate"] == pytest.approx(1 / 2)
    assert confident["baseline_from_unknown_severity"] == 0


def test_the_baselines_unknown_severity_share_travels_with_the_band_figures() -> None:
    eligible = harness.alert_reduction(_corpus())["priority_band"]["context_eligible"]

    assert eligible["baseline_from_unknown_severity"] == 1
    assert eligible["baseline_critical_or_high_from_unknown_severity"] == 0


def test_the_rank_change_table_splits_movement_and_profiles_each_cell() -> None:
    table = harness.baseline_comparison(_corpus())

    assert table["findings"] == 3
    assert (table["promoted"]["count"], table["demoted"]["count"], table["unchanged"]["count"]) == (
        1,
        1,
        1,
    )
    assert set(table["cells"]) == {"High->High", "High->Medium", "Low->High"}
    demoted = table["cells"]["High->Medium"]
    assert demoted["mean_contribution"]["privilege"] == 0
    assert demoted["resolved_share"]["privilege"] == 1.0
    assert table["promoted"]["baseline_from_unknown_severity"] == 1
    assert table["promoted"]["low_confidence"] == 1


def test_the_rank_change_table_is_repeated_without_the_low_confidence_findings() -> None:
    confident = harness.baseline_comparison(_corpus())["excluding_low_confidence"]

    assert confident["findings"] == 2
    assert (
        confident["promoted"]["count"],
        confident["demoted"]["count"],
        confident["unchanged"]["count"],
    ) == (0, 1, 1)
    assert set(confident["cells"]) == {"High->High", "High->Medium"}
    assert "excluding_low_confidence" not in confident, "the twin does not nest"


def test_retention_sums_the_runs_and_derives_its_rates_from_findings_in() -> None:
    result = harness.retention(_corpus())

    assert result["runs"] == 1
    assert result["findings_in"] == result["findings_out"] == 5
    assert result["dropped"] == 0
    assert result["retention_rate"] == 1.0
    assert result["unknown_severity_rate"] == pytest.approx(1 / 5)


# --- everything -----------------------------------------------------------------------


def test_a_ground_truth_case_with_no_scored_entry_is_rejected_not_skipped() -> None:
    ground_truth = {"cases": [_case("present", []), _case("absent", [])]}
    with pytest.raises(ValueError, match="absent"):
        harness.evaluate(ground_truth, _corpus(), {"cases": {"present": {"findings": []}}})


def test_evaluate_points_at_the_two_records_it_does_not_restate() -> None:
    finding = _finding(3)
    ground_truth = {
        "cases": [_case("hi", [finding]), _case("lo", [finding])],
        "contrastive_pairs": [_pair()],
        "scenarios": [_scenario([["hi"], ["lo"]])],
    }
    scored = {"cases": {"hi": {"findings": [finding]}, "lo": {"findings": [finding]}}}
    result = harness.evaluate(ground_truth, _corpus(), scored)

    assert result["registered_rules"]["primary_case_rule"] == "max"
    consistency = result["ranking_consistency"]
    assert consistency["auto_inference_agreement"] == {
        "state": "reported-separately",
        "record": "artifacts/auto-inference-agreement-v1.json",
    }
    assert consistency["model_sensitivity"] == {
        "state": "reported-separately",
        "record": "artifacts/sensitivity-v1.json",
    }
    assert result["contrastive_pairs"]["summary"]["authored"]["pairs"] == 1
