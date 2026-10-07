"""`eval.sensitivity` on constructed documents, and the registered plan against the rubric.

Like `test_harness.py`, every scored input here is hand-built: this file was committed with
the plan, before any variant had been computed over the real artifacts. The plan itself is
read - it is the registration, not a result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eval import harness, sensitivity
from iacrisk.context.extract import LOW_CONFIDENCE_THRESHOLD

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUBRIC = REPO_ROOT / "src" / "iacrisk" / "data" / "rubric.json"

FROZEN_DEFAULTS = {
    "severity": 4,
    "exposure": 3,
    "privilege": 4,
    "sensitivity": 3,
    "criticality": 4,
    "encryption": 2,
}


def _plan() -> dict[str, Any]:
    plan: dict[str, Any] = json.loads(sensitivity.PLAN.read_bytes())
    return plan


def _frozen() -> sensitivity.Variant:
    return sensitivity._frozen(_plan())


def _variant(variant_id: str) -> sensitivity.Variant:
    return next(v for v in sensitivity.variants(_plan()) if v.id == variant_id)


def _finding(
    *,
    identity: str = "aws_s3_bucket.a",
    issue_class: str = "storage-encryption-at-rest",
    unresolved: tuple[str, ...] = (),
    baseline_band: str = "Medium",
    **levels: int,
) -> dict[str, Any]:
    """A finding consistent with the frozen model: an unresolved factor sits on its default."""
    resolved = {
        "severity": 3,
        "exposure": 1,
        "privilege": 0,
        "sensitivity": 3,
        "criticality": 3,
        "encryption": 0,
    }
    resolved.update(levels)
    contributions = {
        factor: FROZEN_DEFAULTS[factor] if factor in unresolved else level
        for factor, level in resolved.items()
    }
    states = {f: "unresolved" if f in unresolved else "resolved" for f in contributions}
    score = sum(contributions.values())
    band = (
        "Critical" if score >= 22 else "High" if score >= 16 else "Medium" if score >= 9 else "Low"
    )
    missing = sum(1 for f in harness.CONTEXT_FACTORS if states[f] != "resolved")
    return {
        "resource_identity": identity,
        "issue_class": issue_class,
        "scanner": "trivy",
        "rule_id": "AVD-X",
        "score": score,
        "band": band,
        "baseline_band": baseline_band,
        "contributions": contributions,
        "factor_states": states,
        "low_confidence": missing >= 3,
        "unmapped": False,
        "baseline_only_informational": False,
    }


# --- the registered plan --------------------------------------------------------------


def test_the_plan_registers_sixty_three_variants_in_four_experiments() -> None:
    registered = sensitivity.variants(_plan())
    by_experiment: dict[str, int] = {}
    for variant in registered:
        by_experiment[variant.experiment] = by_experiment.get(variant.experiment, 0) + 1

    assert by_experiment == {
        "unresolved_defaults": 29,
        "band_boundaries": 16,
        "weights": 14,
        "low_confidence_threshold": 4,
    }
    assert len({v.id for v in registered}) == len(registered) == 63


def test_no_registered_variant_is_the_frozen_model() -> None:
    frozen = _frozen()
    for variant in sensitivity.variants(_plan()):
        assert (
            variant.defaults,
            variant.weights,
            variant.band_minimums,
            variant.low_confidence_threshold,
        ) != (
            frozen.defaults,
            frozen.weights,
            frozen.band_minimums,
            frozen.low_confidence_threshold,
        ), variant.id


def test_each_variant_moves_only_the_thing_its_experiment_names() -> None:
    frozen = _frozen()
    moves = {
        "unresolved_defaults": "defaults",
        "band_boundaries": "band_minimums",
        "weights": "weights",
        "low_confidence_threshold": "low_confidence_threshold",
    }
    for variant in sensitivity.variants(_plan()):
        for field in moves.values():
            same = getattr(variant, field) == getattr(frozen, field)
            assert same is (field != moves[variant.experiment]), (variant.id, field)


def test_every_default_sweep_covers_its_factors_whole_range() -> None:
    """No value is selected: each list is the factor's full range, read from the rubric."""
    rubric = json.loads(RUBRIC.read_bytes())
    swept = _plan()["experiments"]["unresolved_defaults"]["one_at_a_time"]
    for factor in rubric["factors"]:
        levels = sorted(level["score"] for level in factor["levels"])
        assert swept[factor["key"]] == list(range(levels[0], levels[-1] + 1)), factor["key"]


def test_the_plans_frozen_block_is_the_rubrics_own() -> None:
    """`eval/` restates the frozen values rather than importing them. This is what stops the
    restatement drifting from the rubric it describes."""
    rubric = json.loads(RUBRIC.read_bytes())
    frozen = _plan()["frozen"]

    assert frozen["unresolved_defaults"] == {
        factor["key"]: factor["unresolved_default"] for factor in rubric["factors"]
    }
    assert frozen["band_minimums"] == {
        band["name"]: band["minimum"] for band in rubric["bands"] if band["name"] != "Low"
    }
    assert rubric["model"]["equal_weighted"] is True
    assert set(frozen["weights"].values()) == {1}
    assert frozen["low_confidence_threshold"] == LOW_CONFIDENCE_THRESHOLD


# --- rescoring one finding ------------------------------------------------------------


def test_the_frozen_settings_reproduce_a_finding_exactly() -> None:
    finding = _finding(unresolved=("exposure", "privilege", "encryption"))
    again = sensitivity.rescore(finding, _frozen())
    assert {k: again[k] for k in ("score", "band", "low_confidence", "contributions")} == {
        k: finding[k] for k in ("score", "band", "low_confidence", "contributions")
    }


def test_a_changed_default_moves_only_the_contributions_that_were_defaults() -> None:
    resolved = _finding(privilege=2)
    unresolved = _finding(unresolved=("privilege",))
    variant = _variant("default:privilege=0")

    assert sensitivity.rescore(resolved, variant)["score"] == resolved["score"]
    moved = sensitivity.rescore(unresolved, variant)
    assert moved["contributions"]["privilege"] == 0
    assert moved["score"] == unresolved["score"] - FROZEN_DEFAULTS["privilege"]


def test_a_changed_boundary_moves_the_band_and_never_the_score() -> None:
    thirteen = _finding(severity=5, exposure=2)  # 5+2+0+3+3+0
    fourteen = _finding(severity=5, exposure=3)
    high_from_fourteen = _variant("boundary:High-2")

    assert (thirteen["score"], thirteen["band"]) == (13, "Medium")
    assert (fourteen["score"], fourteen["band"]) == (14, "Medium")
    below = sensitivity.rescore(thirteen, high_from_fourteen)
    at = sensitivity.rescore(fourteen, high_from_fourteen)
    assert (below["score"], below["band"]) == (13, "Medium")
    assert (at["score"], at["band"]) == (14, "High")


def test_a_weighted_variant_scales_contributions_and_reports_no_band() -> None:
    finding = _finding(exposure=2, privilege=3)
    weighted = sensitivity.rescore(finding, _variant("weight:likelihood_weighted"))
    dropped = sensitivity.rescore(finding, _variant("weight:drop-exposure"))

    assert weighted["contributions"]["exposure"] == 4
    assert weighted["contributions"]["privilege"] == 6
    assert weighted["score"] == finding["score"] + 2 + 3
    assert weighted["band"] is None
    assert dropped["contributions"]["exposure"] == 0
    assert dropped["score"] == finding["score"] - 2


def test_the_low_confidence_threshold_recounts_the_flag_without_touching_the_score() -> None:
    finding = _finding(unresolved=("exposure", "privilege"))
    assert finding["low_confidence"] is False

    stricter = sensitivity.rescore(finding, _variant("low-confidence:2"))
    assert stricter["low_confidence"] is True
    assert stricter["score"] == finding["score"]
    assert sensitivity.rescore(finding, _variant("low-confidence:4"))["low_confidence"] is False


def test_a_finding_with_no_context_block_is_never_low_confidence() -> None:
    finding = {
        **_finding(),
        "contributions": {"severity": 4},
        "factor_states": {"severity": "unresolved"},
        "score": 4,
        "band": "Low",
        "low_confidence": False,
        "baseline_only_informational": True,
    }
    assert sensitivity.rescore(finding, _variant("low-confidence:1"))["low_confidence"] is False
    assert sensitivity.rescore(finding, _variant("default:severity=1"))["score"] == 1


# --- the identity check ---------------------------------------------------------------


def test_the_identity_check_counts_what_it_reproduced() -> None:
    findings = [_finding(), _finding(unresolved=("exposure",)), _finding(severity=5)]
    assert sensitivity.check_identity(findings, _frozen()) == 3


@pytest.mark.parametrize(
    ("field", "wrong"), [("score", 99), ("band", "Critical"), ("low_confidence", True)]
)
def test_the_identity_check_refuses_a_document_the_model_does_not_reproduce(
    field: str, wrong: Any
) -> None:
    finding = {**_finding(), field: wrong}
    with pytest.raises(ValueError, match=f"do not reproduce the committed {field}"):
        sensitivity.check_identity([finding], _frozen())


def test_the_identity_check_catches_an_unresolved_contribution_off_its_default() -> None:
    """The case the check exists for: a factor marked unresolved whose committed
    contribution is not the frozen default. Recomputing would silently change the score."""
    finding = _finding(unresolved=("privilege",))
    finding["contributions"]["privilege"] = 1
    finding["score"] -= 3
    with pytest.raises(ValueError, match="contributions"):
        sensitivity.check_identity([finding], _frozen())


def test_the_identity_check_catches_two_wrong_contributions_whose_sum_is_right() -> None:
    """Found by a pre-merge code review. Exposure and encryption are both unresolved, and are
    committed at 4 and 1 where the defaults are 3 and 2. The total, the band and the
    low-confidence flag are all exactly what the frozen model gives, so a check on those
    three passed - and every default variant would then have replaced a 4 and a 1 that were
    never the defaults. Comparing the contributions themselves is what refuses it."""
    finding = _finding(unresolved=("exposure", "encryption"))
    honest = dict(finding)
    finding["contributions"] = {**finding["contributions"], "exposure": 4, "encryption": 1}

    assert sum(finding["contributions"].values()) == honest["score"]
    assert sensitivity.check_identity([honest], _frozen()) == 1
    with pytest.raises(ValueError, match="do not reproduce the committed contributions"):
        sensitivity.check_identity([finding], _frozen())


# --- rank agreement -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("xs", "ys"),
    [
        ([1, 2, 3, 4], [1, 2, 3, 4]),
        ([1, 2, 3, 4], [4, 3, 2, 1]),
        ([3, 2, 1], [2, 3, 1]),
        ([2, 1, 1], [2, 1, 2]),
        ([5, 5, 7, 7, 9, 3, 3], [1, 2, 2, 8, 8, 0, 4]),
        ([1, 1, 1, 2], [3, 3, 4, 4]),
    ],
)
def test_the_grouped_tau_b_is_the_harnesss_tau_b(xs: list[int], ys: list[int]) -> None:
    grouped = sensitivity.kendall_tau_b_grouped(zip(xs, ys, strict=True))
    assert grouped == pytest.approx(harness.kendall_tau_b(xs, ys))


def test_the_grouped_tau_b_is_none_where_tau_b_is_undefined() -> None:
    assert sensitivity.kendall_tau_b_grouped([(1, 5), (2, 5), (3, 5)]) is None
    assert sensitivity.kendall_tau_b_grouped([(1, 1)]) is None
    assert sensitivity.kendall_tau_b_grouped([]) is None


# --- the whole analysis ---------------------------------------------------------------


def _documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Two cases on a privilege pair, where the low side's privilege is unresolved."""
    high = _finding(identity="r.high", privilege=5)
    low = _finding(identity="r.low", unresolved=("privilege",))

    def case(case_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "case_id": case_id,
            "domain": "iam",
            "source": {"repo": "r", "commit": "abcdef0", "path": "p"},
            "expected": {
                "findings": [
                    {
                        "resource_identity": finding["resource_identity"],
                        "issue_class": finding["issue_class"],
                    }
                ]
            },
        }

    ground_truth = {
        "cases": [case("hi", high), case("lo", low)],
        "contrastive_pairs": [
            {"pair_id": "p", "factor_under_test": "privilege", "case_high": "hi", "case_low": "lo"}
        ],
        "scenarios": [
            {
                "scenario_id": "s",
                "domain": "iam",
                "expected_ordering": [["hi"], ["lo"]],
                "oracle": {"reviewer_verdict": "agree"},
            }
        ],
    }
    corpus = {"findings": [high, low]}
    cases = {"cases": {"hi": {"findings": [high]}, "lo": {"findings": [low]}}}
    return ground_truth, corpus, cases


def _by_id(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["id"]: v for block in result["experiments"].values() for v in block}


def test_the_analysis_reports_every_registered_variant_and_the_frozen_model_beside_them() -> None:
    result = sensitivity.analyse(_plan(), *_documents())

    assert result["variants_registered"] == 63
    assert result["identity"] == {"findings_checked": 4, "reproduces_committed_values": True}
    assert result["frozen"]["pairs"]["passes"] == 1
    assert result["frozen"]["corpus"]["rank_agreement_tau_b"] == pytest.approx(1.0)
    assert set(_by_id(result)) == {v.id for v in sensitivity.variants(_plan())}


def test_a_default_can_decide_a_pair_and_the_variant_shows_it() -> None:
    """hi resolves privilege at 5; lo is unresolved and frozen at 4. At a default of 5 they
    tie, which fails; at 0 the gap widens. The frozen verdict is not overwritten by either."""
    result = sensitivity.analyse(_plan(), *_documents())
    variants = _by_id(result)

    assert variants["default:privilege=5"]["pairs"]["passes"] == 0
    assert variants["default:privilege=5"]["pairs"]["failed"] == ["p"]
    assert variants["default:privilege=0"]["pairs"]["passes"] == 1
    assert result["frozen"]["pairs"]["passes"] == 1


def test_dropping_the_factor_under_test_fails_the_pair_built_on_it() -> None:
    variants = _by_id(sensitivity.analyse(_plan(), *_documents()))

    assert variants["weight:drop-privilege"]["pairs"]["passes"] == 0
    assert variants["weight:drop-severity"]["pairs"]["passes"] == 1
    assert variants["weight:drop-privilege"]["corpus"]["bands"] is None


def test_boundary_and_threshold_variants_cannot_move_an_ordering_metric() -> None:
    result = sensitivity.analyse(_plan(), *_documents())
    frozen = result["frozen"]
    for name in ("band_boundaries", "low_confidence_threshold"):
        for variant in result["experiments"][name]:
            assert variant["corpus"]["score_changed"] == 0, variant["id"]
            assert variant["corpus"]["rank_agreement_tau_b"] == pytest.approx(1.0)
            assert variant["pairs"]["passes"] == frozen["pairs"]["passes"]
            assert variant["scenarios"]["by_scenario"] == frozen["scenarios"]["by_scenario"]


def test_the_analysis_refuses_to_run_on_a_document_it_cannot_reproduce() -> None:
    ground_truth, corpus, cases = _documents()
    corpus["findings"][0] = {**corpus["findings"][0], "score": 1}
    with pytest.raises(ValueError, match="do not reproduce"):
        sensitivity.analyse(_plan(), ground_truth, corpus, cases)
