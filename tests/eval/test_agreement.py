"""`eval.agreement` on constructed documents only.

Committed with the conventions and before any inferred run over the real corpus existed,
for the reason `test_harness.py` and `test_sensitivity.py` give for themselves.
"""

from __future__ import annotations

from typing import Any

import pytest

from eval import agreement

DEFAULTS = {"sensitivity": 3, "criticality": 4}


def _finding(
    identity: str = "r.a",
    *,
    sensitivity: int = 3,
    criticality: int = 4,
    declared: tuple[str, ...] = (),
    rule_id: str = "AVD-X",
    severity: int = 3,
    baseline_only: bool = False,
) -> dict[str, Any]:
    """`declared` names the factors whose value came from evidence rather than a default."""
    contributions = {
        "severity": severity,
        "exposure": 3,
        "privilege": 0,
        "sensitivity": sensitivity,
        "criticality": criticality,
        "encryption": 0,
    }
    states = dict.fromkeys(contributions, "resolved")
    for factor in ("sensitivity", "criticality"):
        if factor not in declared:
            states[factor] = "defaulted"
    score = sum(contributions.values())
    return {
        "resource_identity": identity,
        "issue_class": "storage-encryption-at-rest",
        "scanner": "trivy",
        "rule_id": rule_id,
        "file_path": "main.tf",
        "flagged_by": [{"scanner": "trivy", "rule_id": rule_id}],
        "score": score,
        "band": "High" if score >= 16 else "Medium" if score >= 9 else "Low",
        "baseline_band": "Medium",
        "contributions": contributions,
        "factor_states": states,
        "low_confidence": False,
        "unmapped": False,
        "baseline_only_informational": baseline_only,
    }


def _case(case_id: str, identity: str, sensitivity: int | None, criticality: int | None) -> Any:
    return {
        "case_id": case_id,
        "domain": "storage",
        "source": {"repo": "r", "commit": "abcdef0", "path": "p"},
        "declared_context": {identity: {"sensitivity": sensitivity, "criticality": criticality}},
        "expected": {
            "findings": [
                {"resource_identity": identity, "issue_class": "storage-encryption-at-rest"}
            ]
        },
    }


def _cases(**by_case: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "context_mode": "auto-inference",
        "cases": {case_id: {"findings": findings} for case_id, findings in by_case.items()},
    }


# --- pairing --------------------------------------------------------------------------


def test_findings_are_paired_across_the_two_runs_by_what_identifies_them() -> None:
    declared = [_finding("r.a", sensitivity=5, declared=("sensitivity",)), _finding("r.b")]
    inferred = [_finding("r.b"), _finding("r.a")]
    pairs = agreement.pair_findings(declared, inferred)

    assert len(pairs) == 2
    assert all(d["resource_identity"] == i["resource_identity"] for d, i in pairs)


def test_one_rule_firing_twice_on_a_resource_pairs_without_loss() -> None:
    declared = [_finding(severity=2), _finding(severity=4)]
    inferred = [_finding(severity=4), _finding(severity=2)]
    pairs = agreement.pair_findings(declared, inferred)

    assert sorted((d["score"], i["score"]) for d, i in pairs) == [(12, 12), (14, 14)]


def test_two_runs_that_do_not_hold_the_same_findings_are_rejected() -> None:
    with pytest.raises(ValueError, match="no finding matching"):
        agreement.pair_findings([_finding("r.a")], [_finding("r.b")])
    with pytest.raises(ValueError, match="holds 1 finding"):
        agreement.pair_findings([_finding("r.a")], [_finding("r.a"), _finding("r.b")])


# --- coverage -------------------------------------------------------------------------


def test_coverage_counts_findings_and_resources_that_took_an_inferred_value() -> None:
    corpus = {
        "findings": [
            _finding("r.a", criticality=1, declared=("criticality",)),
            _finding("r.a", criticality=1, declared=("criticality",), rule_id="AVD-Y"),
            _finding("r.b"),
            _finding("r.c", baseline_only=True),
        ],
        "inference": {
            "values": {
                "r.a": {"criticality": {"level": 1, "source": "tag", "evidence": "e"}},
                "r.z": {"sensitivity": {"level": 5, "source": "name", "evidence": "e"}},
            }
        },
    }
    result = agreement.coverage(corpus)

    assert (result["findings"], result["resources"]) == (3, 2)
    assert result["findings_inferred"] == {"sensitivity": 0, "criticality": 2}
    assert result["resources_inferred"] == {"sensitivity": 0, "criticality": 1}
    assert result["indexed_resources_with_any_inferred_value"] == 2
    assert result["inferred_values_by_factor_and_source"] == {
        "criticality:tag": 1,
        "sensitivity:name": 1,
    }


# --- level agreement ------------------------------------------------------------------


def test_level_agreement_compares_the_inferred_level_with_the_one_declared_level() -> None:
    ground_truth = {"cases": [_case("exact", "r.a", 3, 1), _case("off", "r.b", 5, 2)]}
    inferred = _cases(
        exact=[_finding("r.a", criticality=1, declared=("criticality",))],
        off=[_finding("r.b")],
    )
    result = agreement.level_agreement(ground_truth, inferred, DEFAULTS)
    criticality = result["by_factor"]["criticality"]
    sensitivity = result["by_factor"]["sensitivity"]

    assert criticality["resources"] == 2
    assert criticality["resolved_by_a_convention"] == 1
    assert criticality["inferred"] == {
        "exact": 1,
        "under": 0,
        "over": 1,
        "mean_absolute_difference": 1.0,
    }
    assert sensitivity["inferred"]["under"] == 1, "the default 3 sits below a declared 5"


def test_the_all_default_strawman_is_reported_beside_the_inferred_figure() -> None:
    """A convention that agrees where the default would not is the only thing that should
    read as the conventions' doing."""
    ground_truth = {"cases": [_case("c", "r.a", 3, 1)]}
    inferred = _cases(c=[_finding("r.a", criticality=1, declared=("criticality",))])
    criticality = agreement.level_agreement(ground_truth, inferred, DEFAULTS)["by_factor"][
        "criticality"
    ]

    assert criticality["inferred"]["exact"] == 1
    assert criticality["all_default"]["exact"] == 0
    assert criticality["all_default"]["over"] == 1
    assert criticality["all_default"]["mean_absolute_difference"] == 3.0


def test_a_resource_the_cases_declare_differently_has_no_reference_and_is_excluded() -> None:
    ground_truth = {
        "cases": [
            _case("high", "r.a", 5, 3),
            _case("low", "r.a", 1, 3),
            _case("plain", "r.b", 3, 3),
        ]
    }
    inferred = _cases(high=[_finding("r.a")], low=[_finding("r.a")], plain=[_finding("r.b")])
    result = agreement.level_agreement(ground_truth, inferred, DEFAULTS)

    assert result["declared_resources"] == 2
    assert result["excluded_as_conflicting"] == ["r.a"]
    assert result["by_factor"]["sensitivity"]["resources"] == 1


def test_a_factor_a_case_leaves_undeclared_is_excluded_and_counted() -> None:
    ground_truth = {"cases": [_case("c", "r.a", None, 2)]}
    result = agreement.level_agreement(ground_truth, _cases(c=[_finding("r.a")]), DEFAULTS)

    assert result["by_factor"]["sensitivity"]["resources"] == 0
    assert result["by_factor"]["sensitivity"]["excluded_as_undeclared"] == 1
    assert result["by_factor"]["sensitivity"]["inferred"]["mean_absolute_difference"] is None
    assert result["by_factor"]["criticality"]["resources"] == 1


# --- ranking agreement ----------------------------------------------------------------


def test_ranking_agreement_separates_declared_resources_from_the_rest() -> None:
    """Undeclared resources take the defaults in both runs and agree trivially; reporting
    one population would let that agreement hide what happens where the modes can differ."""
    declared = {
        "findings": [
            _finding("r.a", sensitivity=5, declared=("sensitivity",)),
            _finding("r.b"),
            _finding("r.c"),
        ]
    }
    inferred = {"findings": [_finding("r.a"), _finding("r.b"), _finding("r.c")]}
    result = agreement.ranking_agreement(declared, inferred)

    everything = result["all_quality_claim_findings"]
    assert everything["findings"] == 3
    assert everything["same_score"] == 2
    assert everything["inferred_lower"] == 1

    on_declared = result["on_declared_resources"]
    assert on_declared["findings"] == 1
    assert on_declared["same_score"] == 0
    assert on_declared["mean_absolute_score_difference"] == 2.0


def test_ranking_agreement_leaves_out_findings_the_framework_makes_no_claim_about() -> None:
    declared = {"findings": [_finding("r.a"), _finding("r.x", baseline_only=True)]}
    inferred = {"findings": [_finding("r.a"), _finding("r.x", baseline_only=True)]}
    assert agreement.ranking_agreement(declared, inferred)["all_quality_claim_findings"][
        "findings"
    ] == (1)


# --- the oracle -----------------------------------------------------------------------


def _oracle_ground_truth() -> dict[str, Any]:
    return {
        "cases": [
            _case("hi", "r.a", 5, 3),
            _case("lo", "r.a", 1, 3),
            _case("other", "r.b", 3, 3),
        ],
        "contrastive_pairs": [
            {
                "pair_id": "same",
                "factor_under_test": "sensitivity",
                "case_high": "hi",
                "case_low": "lo",
            },
            {
                "pair_id": "two",
                "factor_under_test": "exposure",
                "case_high": "hi",
                "case_low": "other",
            },
        ],
        "scenarios": [
            {
                "scenario_id": "s",
                "domain": "storage",
                "expected_ordering": [["hi"], ["lo"]],
                "oracle": {"reviewer_verdict": "agree"},
            }
        ],
    }


def test_a_pair_on_one_resource_is_not_applicable_rather_than_failed() -> None:
    ground_truth = _oracle_ground_truth()
    declared = _cases(
        hi=[_finding("r.a", sensitivity=5, declared=("sensitivity",))],
        lo=[_finding("r.a", sensitivity=1, declared=("sensitivity",))],
        other=[_finding("r.b", severity=2)],
    )
    inferred = _cases(
        hi=[_finding("r.a")], lo=[_finding("r.a")], other=[_finding("r.b", severity=2)]
    )
    result = agreement.oracle(ground_truth, declared, inferred)

    assert result["pairs_authored"] == 2
    assert result["pairs_not_applicable"] == ["same"]
    assert result["pairs_applicable"] == 1
    assert result["declared"]["pairs_passed"] == result["inferred"]["pairs_passed"] == 1


def test_the_scenarios_are_graded_in_both_modes_by_the_same_rules() -> None:
    ground_truth = _oracle_ground_truth()
    declared = _cases(
        hi=[_finding("r.a", sensitivity=5, declared=("sensitivity",))],
        lo=[_finding("r.a", sensitivity=1, declared=("sensitivity",))],
        other=[_finding("r.b")],
    )
    inferred = _cases(hi=[_finding("r.a")], lo=[_finding("r.a")], other=[_finding("r.b")])
    result = agreement.oracle(ground_truth, declared, inferred)

    assert result["declared"]["scenarios_exact"] == 1
    assert result["inferred"]["scenarios_exact"] == 0
    assert result["inferred"]["ordered_pairs_tied"] == 1


# --- everything -----------------------------------------------------------------------


def test_an_inferred_document_that_is_not_marked_as_one_is_refused() -> None:
    corpus = {"findings": [], "inference": {"values": {}}}
    with pytest.raises(ValueError, match="not marked auto-inference"):
        agreement.agreement({"cases": []}, DEFAULTS, corpus, {"cases": {}}, corpus, {"cases": {}})
