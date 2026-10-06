"""S6 acceptance gates: the sensitivity record against its plan and its inputs.

`tests/eval/test_sensitivity.py` pins the analysis on constructed findings and was committed
with the plan, before any variant was computed. These gates run over the real committed
record. As in `test_s5_gates.py`, none restates a result: each checks the record against the
plan, the inputs, or the evaluation record it has to agree with.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from eval import harness, sensitivity
from eval import run as eval_run
from tools.harvest.provenance import hash_file

REPO_ROOT = Path(__file__).resolve().parent.parent
ORDERING_FREE = ("band_boundaries", "low_confidence_threshold")
"""Experiments that change no score, so cannot change a rank."""


@lru_cache(maxsize=1)
def _record() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(sensitivity.OUTPUT.read_bytes())
    return document


@lru_cache(maxsize=1)
def _plan() -> dict[str, Any]:
    plan: dict[str, Any] = json.loads(sensitivity.PLAN.read_bytes())
    return plan


@lru_cache(maxsize=1)
def _evaluation() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(eval_run.OUTPUT.read_bytes())
    return document


@lru_cache(maxsize=1)
def _corpus() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(sensitivity.SCORED_CORPUS.read_bytes())
    return document


@lru_cache(maxsize=1)
def _cases() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(sensitivity.SCORED_CASES.read_bytes())
    return document


def _all_variants() -> list[dict[str, Any]]:
    return [v for block in _record()["experiments"].values() for v in block]


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


# --- gate 1: the record is the analysis of the committed inputs under the committed plan


def test_gate_1_the_committed_record_matches_a_fresh_run() -> None:
    fresh = sensitivity.sensitivity_document()
    assert _without_provenance(_record()) == _without_provenance(fresh)


def test_gate_1_the_record_names_the_inputs_and_carries_the_plan_verbatim() -> None:
    record = _record()
    assert record["provenance"]["inputs"] == {
        path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in sensitivity.INPUTS
    }
    assert record["plan"] == _plan()


# --- gate 2: every registered variant, and only those ----------------------------------


def test_gate_2_every_registered_variant_is_reported_exactly_once() -> None:
    """No filtering step: what the plan registers is what the record holds."""
    registered = [v.id for v in sensitivity.variants(_plan())]
    reported = [v["id"] for v in _all_variants()]

    assert sorted(reported) == sorted(registered)
    assert len(set(reported)) == len(reported) == _record()["variants_registered"]
    for name, block in _record()["experiments"].items():
        expected = [v.id for v in sensitivity.variants(_plan()) if v.experiment == name]
        assert [v["id"] for v in block] == expected, name


def test_gate_2_the_frozen_model_is_reported_beside_the_variants_and_is_not_one() -> None:
    assert _record()["frozen"]["id"] == "frozen"
    assert "frozen" not in {v["id"] for v in _all_variants()}


# --- gate 3: the analysed model is the scored model ------------------------------------


def test_gate_3_the_frozen_settings_reproduce_every_committed_finding() -> None:
    frozen = sensitivity._frozen(_plan())
    corpus = _corpus()["findings"]
    cases = [f for entry in _cases()["cases"].values() for f in entry["findings"]]

    checked = sensitivity.check_identity(corpus, frozen) + sensitivity.check_identity(cases, frozen)
    assert checked == len(corpus) + len(cases)
    assert _record()["identity"] == {
        "findings_checked": checked,
        "reproduces_committed_values": True,
    }


def test_gate_3_the_frozen_result_is_the_evaluation_records_own_verdict() -> None:
    """Two modules graded the frozen model independently. They must agree, or one of the
    two records is describing a different model."""
    frozen = _record()["frozen"]
    evaluation = _evaluation()
    rule = harness.PRIMARY_RULE

    pairs = evaluation["contrastive_pairs"]["summary"]["authored"]
    assert frozen["pairs"]["passes"] == pairs["framework_passes"][rule]
    assert frozen["pairs"]["isolated"] == pairs["isolated"]

    headline = evaluation["scenarios"]["summary"]["headline"]["framework"][rule]
    for key in (
        "exact_tier_matches",
        "ordered_pairs_concordant",
        "ordered_pairs_tied",
        "ordered_pairs_discordant",
    ):
        assert frozen["scenarios"]["headline"][key] == headline[key], key

    bands = evaluation["alert_reduction"]["priority_band"]["quality_claim_population"]
    assert frozen["corpus"]["bands"] == bands["framework"]
    assert frozen["corpus"]["critical_or_high"] == bands["framework_critical_or_high"]
    assert frozen["corpus"]["findings"] == bands["findings"]


# --- gate 4: a variant says only what its experiment can -------------------------------


def test_gate_4_boundary_and_threshold_variants_change_no_score_and_no_ordering() -> None:
    frozen = _record()["frozen"]
    for name in ORDERING_FREE:
        for variant in _record()["experiments"][name]:
            assert variant["corpus"]["score_changed"] == 0, variant["id"]
            assert variant["pairs"]["passes"] == frozen["pairs"]["passes"], variant["id"]
            assert variant["pairs"]["failed"] == frozen["pairs"]["failed"], variant["id"]
            assert variant["scenarios"]["by_scenario"] == frozen["scenarios"]["by_scenario"], (
                variant["id"]
            )


def test_gate_4_a_weighted_variant_reports_no_bands_and_every_other_variant_does() -> None:
    for variant in _all_variants():
        corpus = variant["corpus"]
        if variant["weighted"]:
            assert corpus["bands"] is None and corpus["critical_or_high"] is None, variant["id"]
        else:
            assert sum(corpus["bands"].values()) == corpus["findings"], variant["id"]
    weighted = {v["id"] for v in _all_variants() if v["weighted"]}
    assert weighted == {v["id"] for v in _record()["experiments"]["weights"]}


def test_gate_4_every_variant_is_over_the_same_findings_and_the_same_oracle() -> None:
    frozen = _record()["frozen"]
    for variant in _all_variants():
        assert variant["corpus"]["findings"] == frozen["corpus"]["findings"], variant["id"]
        assert variant["pairs"]["evaluable"] == frozen["pairs"]["evaluable"], variant["id"]
        assert set(variant["scenarios"]["by_scenario"]) == set(frozen["scenarios"]["by_scenario"])


def test_gate_4_dropping_a_factor_fails_every_pair_isolated_on_it() -> None:
    """A mechanism check on the analysis itself. A pair the evaluation found `isolated` moves
    on its factor alone, so with that factor weighted to zero its two cases must tie."""
    isolated: dict[str, list[str]] = {}
    for pair in _evaluation()["contrastive_pairs"]["pairs"]:
        if pair["isolated"] and pair["severity_delta"] == 0:
            isolated.setdefault(pair["factor_under_test"], []).append(pair["pair_id"])
    assert isolated, "no isolated pair to check; the gate would be vacuous"

    by_id = {v["id"]: v for v in _all_variants()}
    for factor, pair_ids in isolated.items():
        failed = set(by_id[f"weight:drop-{factor}"]["pairs"]["failed"])
        assert set(pair_ids) <= failed, (factor, pair_ids, failed)


# --- gate 5: the plan was registered before the record existed -------------------------


def test_gate_5_the_plan_was_committed_before_the_record_computed_from_it() -> None:
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")

    def first_commit(path: str) -> str:
        added = _git("log", "--diff-filter=A", "--format=%H", "--", path)
        assert added, f"{path} has no adding commit in history"
        return added.splitlines()[-1]

    plan = first_commit("eval/sensitivity_plan.json")
    record = first_commit("artifacts/sensitivity-v1.json")
    assert plan != record, "the plan and the record arrived in one commit"
    assert _git("merge-base", "--is-ancestor", plan, record) is not None, (
        f"{plan[:7]} (plan) is not an ancestor of {record[:7]} (record)"
    )


def test_gate_5_the_plan_has_not_changed_since_it_was_registered() -> None:
    """The file is the registration. An edit after the fact - a value added, a variant
    removed - would make the record an analysis of a plan nobody approved."""
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")
    commits = _git("log", "--format=%H", "--", "eval/sensitivity_plan.json")
    assert commits is not None and len(commits.splitlines()) == 1, (
        "eval/sensitivity_plan.json has been modified since it was registered; a changed "
        "plan is a second registered round and needs its own file"
    )
