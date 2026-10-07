"""S6 acceptance gates: the sensitivity record against its plan, its inputs and the engine.

`tests/eval/test_sensitivity.py` pins the analysis on constructed findings and was committed
with the plan, before any variant was computed. These gates run over the real committed
record.

**What is recomputed here by a second route, and what is not.** An earlier version of this
docstring said no gate restated a result. A pre-merge code review found two that did: the
variant list was checked against the function that had produced it, and the frozen result
was checked against an evaluation record graded by the same harness functions. Now:

- the variant ids are enumerated from the plan's JSON by code in this file;
- every one of the variants that moves a score is recomputed by the framework's own
  scoring engine - `iacrisk.scoring.engine.score` over the replayed captures, with the
  rubric's defaults replaced - and compared with the analysis finding by finding; pairs and
  scenarios are then regraded from the engine's scores by a rule written out here;
- the boundary and threshold variants, which move no score, are recounted from the
  committed scores and factor states.

Gates 1 and 5 are not second routes. They check freshness, provenance and commit order.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from eval import harness, sensitivity
from eval import run as eval_run
from eval.ground_truth import load_and_validate
from iacrisk import pipeline, rubric
from iacrisk.context.extract import ContextualizedFinding, contextualize
from iacrisk.dedupe import deduplicate
from iacrisk.scoring import engine
from tools.harvest.provenance import hash_file
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent
BAND_ORDER = ("Critical", "High", "Medium", "Low")
CONTEXT = ("exposure", "privilege", "sensitivity", "criticality", "encryption")
SCORE_MOVING = ("unresolved_defaults", "weights")
ORDERING_FREE = ("band_boundaries", "low_confidence_threshold")
"""Experiments that change no score, so cannot change a rank."""

RUBRIC = rubric.factors()
"""The frozen factors, read once before any test replaces a default."""


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


@lru_cache(maxsize=1)
def _ground_truth() -> dict[str, Any]:
    return load_and_validate(sensitivity.GROUND_TRUTH)


def _all_variants() -> list[dict[str, Any]]:
    return [v for block in _record()["experiments"].values() for v in block]


def _score_moving() -> list[dict[str, Any]]:
    return [v for name in SCORE_MOVING for v in _record()["experiments"][name]]


def _eligible_committed() -> list[dict[str, Any]]:
    """The committed corpus findings every variant is computed over."""
    return [
        f
        for f in _corpus()["findings"]
        if not f["unmapped"] and not f["baseline_only_informational"]
    ]


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


# --- the second route: the plan read here, and the framework's engine ------------------


def _registered_ids() -> dict[str, list[str]]:
    """Every variant id the plan registers, enumerated from its JSON by this file."""
    plan = _plan()
    frozen = plan["frozen"]["unresolved_defaults"]
    experiments = plan["experiments"]
    defaults = experiments["unresolved_defaults"]
    boundaries = experiments["band_boundaries"]
    weights = experiments["weights"]
    assert boundaries["each_alone"] is True and boundaries["all_together"] is True
    return {
        "unresolved_defaults": [
            f"default:{factor}={value}"
            for factor, values in defaults["one_at_a_time"].items()
            for value in values
            if value != frozen[factor]
        ]
        + [f"default:{name}" for name in defaults["joint"]],
        "band_boundaries": [
            f"boundary:{band}{shift:+d}"
            for band in boundaries["boundaries"]
            for shift in boundaries["shifts"]
        ]
        + [f"boundary:all{shift:+d}" for shift in boundaries["shifts"]],
        "weights": [f"weight:drop-{factor}" for factor in weights["drop_one"]]
        + [f"weight:double-{factor}" for factor in weights["double_one"]]
        + [f"weight:{name}" for name in weights["named"]],
        "low_confidence_threshold": [
            f"low-confidence:{value}" for value in experiments["low_confidence_threshold"]["values"]
        ],
    }


def _settings(variant: Mapping[str, Any]) -> tuple[dict[str, int], dict[str, int]]:
    """A variant's defaults and weights, from its recorded `change` and the plan's JSON."""
    plan = _plan()
    defaults = dict(plan["frozen"]["unresolved_defaults"])
    weights = dict(plan["frozen"]["weights"])
    change = variant["change"]
    if "factor" in change:
        defaults[change["factor"]] = change["value"]
    elif "joint" in change:
        defaults = dict(plan["experiments"]["unresolved_defaults"]["joint"][change["joint"]])
    elif "drop" in change:
        weights[change["drop"]] = 0
    elif "double" in change:
        weights[change["double"]] = 2
    elif "named" in change:
        weights.update(plan["experiments"]["weights"]["named"][change["named"]]["weights"])
    else:
        assert not change, f"{variant['id']} records a change this gate cannot read: {change}"
    return defaults, weights


def _eligible(contextualized: Sequence[ContextualizedFinding]) -> tuple[ContextualizedFinding, ...]:
    return tuple(
        c
        for c in contextualized
        if c.factors and not c.finding.issue_class.startswith(engine.UNMAPPED_PREFIX)
    )


@lru_cache(maxsize=1)
def _replayed() -> dict[str, score_run.Replayed]:
    return {name: score_run.replay(root) for name, root in score_run.ROOTS.items()}


@lru_cache(maxsize=1)
def _replayed_corpus() -> tuple[ContextualizedFinding, ...]:
    """Corpus v0 up to the engine's input: replayed, collapsed and contextualized.

    Contextualized once and scored under each variant. That is sound because the framework
    reads an unresolved default in exactly one place and lazily - `FactorValue.scored_level`
    - so nothing layer 3 produces depends on the value of a default.
    """
    declared, _ = score_run.merged_declared(_ground_truth())
    corpus = score_run.merge([_replayed()[name] for name in score_run.CORPUS_V0])
    findings = corpus.findings
    survivors = pipeline.tier1_survivors(findings, deduplicate(findings))
    return _eligible(
        contextualize([s.finding for s in survivors], declared, corpus.tf_index, corpus.k8s_index)
    )


@lru_cache(maxsize=1)
def _replayed_cases() -> dict[str, tuple[ContextualizedFinding, ...]]:
    """Each case up to the engine's input, under that case's own declared context."""
    cases: dict[str, tuple[ContextualizedFinding, ...]] = {}
    for case in _ground_truth()["cases"]:
        part = _replayed()[score_run._root_for(case)]
        declared = case["declared_context"]
        findings = [f for f in part.findings if f.resource_identity in declared]
        survivors = pipeline.tier1_survivors(findings, deduplicate(findings))
        cases[case["case_id"]] = _eligible(
            contextualize([s.finding for s in survivors], declared, part.tf_index, part.k8s_index)
        )
    return cases


def _engine(
    monkeypatch: pytest.MonkeyPatch,
    contextualized: Sequence[ContextualizedFinding],
    defaults: Mapping[str, int],
    weights: Mapping[str, int],
) -> list[engine.ScoredFinding]:
    """`contextualized` scored by the framework's engine under a variant's settings."""
    patched = MappingProxyType(
        {
            key: dataclasses.replace(factor, unresolved_default=defaults[key])
            for key, factor in RUBRIC.items()
        }
    )
    monkeypatch.setattr(rubric, "factors", lambda: patched)
    return [engine.score(c, weights) for c in contextualized]


Row = tuple[str, str, str, str, tuple[tuple[str, int], ...], int]


def _row(
    identity: str,
    issue_class: str,
    scanner: str,
    rule_id: str,
    contributions: Mapping[str, int],
    score: int,
) -> Row:
    return (identity, issue_class, scanner, rule_id, tuple(sorted(contributions.items())), score)


def _engine_rows(scored: Sequence[engine.ScoredFinding]) -> Counter[Row]:
    return Counter(
        _row(
            s.finding.resource_identity,
            s.finding.issue_class,
            s.finding.scanner,
            s.finding.rule_id,
            s.contributions,
            s.score,
        )
        for s in scored
    )


def _json_rows(findings: Sequence[Mapping[str, Any]]) -> Counter[Row]:
    return Counter(
        _row(
            f["resource_identity"],
            f["issue_class"],
            f["scanner"],
            f["rule_id"],
            f["contributions"],
            f["score"],
        )
        for f in findings
    )


def _tiers(scores: Mapping[str, int]) -> list[list[str]]:
    levels = sorted(set(scores.values()), reverse=True)
    return [sorted(c for c, s in scores.items() if s == level) for level in levels]


# --- gate 1: the record is the analysis of the committed inputs under the committed plan
# Not a second route: freshness and provenance.


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
    """No filtering step: what the plan registers is what the record holds. The expected
    ids come from this file's own reading of the plan, not from `sensitivity.variants`."""
    registered = _registered_ids()
    experiments = _record()["experiments"]

    assert list(experiments) == list(_plan()["experiments"])
    for name, block in experiments.items():
        assert [v["id"] for v in block] == registered[name], name
    reported = [v["id"] for v in _all_variants()]
    assert len(set(reported)) == len(reported) == _record()["variants_registered"]
    assert len(reported) == sum(len(ids) for ids in registered.values())


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


def test_gate_3_every_score_moving_variant_is_reproduced_by_the_scoring_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The analysis recomputes scores from JSON, with its own arithmetic, so that `eval/`
    need not import the framework. This is what holds that arithmetic to the framework's:
    each variant is scored again by `engine.score`, and the two must agree on every
    finding's six contributions and total, and on every corpus figure the record states.
    """
    committed = _eligible_committed()
    replayed = _replayed_corpus()
    frozen_defaults, frozen_weights = _settings({"id": "frozen", "change": {}})
    frozen = _engine(monkeypatch, replayed, frozen_defaults, frozen_weights)
    assert _engine_rows(frozen) == _json_rows(committed), (
        "the replay is not the committed corpus, so nothing below would compare like with like"
    )

    module = {variant.id: variant for variant in sensitivity.variants(_plan())}
    checked = 0
    for variant in _score_moving():
        defaults, weights = _settings(variant)
        scored = _engine(monkeypatch, replayed, defaults, weights)

        analysed = [sensitivity.rescore(f, module[variant["id"]]) for f in committed]
        assert _engine_rows(scored) == _json_rows(analysed), variant["id"]

        corpus = variant["corpus"]
        assert corpus["findings"] == len(scored), variant["id"]
        assert corpus["score_changed"] == sum(
            1 for before, after in zip(frozen, scored, strict=True) if before.score != after.score
        ), variant["id"]
        if variant["weighted"]:
            assert corpus["bands"] is None, variant["id"]
        else:
            bands = Counter(s.band for s in scored)
            assert corpus["bands"] == {band: bands.get(band, 0) for band in BAND_ORDER}, variant[
                "id"
            ]
            assert corpus["critical_or_high"] == bands["Critical"] + bands["High"], variant["id"]
            assert corpus["band_changed"] == sum(
                1 for before, after in zip(frozen, scored, strict=True) if before.band != after.band
            ), variant["id"]
        checked += 1
    assert checked == sum(len(_registered_ids()[name]) for name in SCORE_MOVING)


def test_gate_3_pairs_and_scenarios_under_each_variant_follow_from_the_engines_scores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The record's ordering results, by a route that shares nothing with the harness: the
    engine scores each case's findings, a case takes its highest, a pair passes on strictly
    greater, and a scenario's tiers are its distinct scores in descending order."""
    truth = _ground_truth()
    replayed = _replayed_cases()
    for variant in (_record()["frozen"], *_score_moving()):
        defaults, weights = _settings(variant)
        top = {
            case_id: max(s.score for s in _engine(monkeypatch, members, defaults, weights))
            for case_id, members in replayed.items()
        }

        failed = [
            pair["pair_id"]
            for pair in truth["contrastive_pairs"]
            if not top[pair["case_high"]] > top[pair["case_low"]]
        ]
        assert variant["pairs"]["failed"] == failed, variant["id"]
        assert variant["pairs"]["passes"] == len(truth["contrastive_pairs"]) - len(failed)

        exact = 0
        for scenario in truth["scenarios"]:
            expected = scenario["expected_ordering"]
            ordering = _tiers({c: top[c] for tier in expected for c in tier})
            matches = ordering == [sorted(tier) for tier in expected]
            block = variant["scenarios"]["by_scenario"][scenario["scenario_id"]]
            assert block["ordering"] == ordering, (variant["id"], scenario["scenario_id"])
            assert block["exact_tier_match"] is matches, (variant["id"], scenario["scenario_id"])
            exact += matches and scenario["oracle"]["reviewer_verdict"] != "disagree"
        assert variant["scenarios"]["headline"]["exact_tier_matches"] == exact, variant["id"]


def test_gate_3_the_frozen_result_agrees_with_the_evaluation_record() -> None:
    """A consistency check between two records, not an independent one: the analysis grades
    pairs and scenarios with the harness's own functions, so agreement there shows only
    that neither record is stale. The band counts are the exception - the analysis bands a
    score with its own function and the evaluation record counts the framework's."""
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

    bands = evaluation["alert_reduction"]["priority_band"]["context_eligible"]
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


def test_gate_4_every_boundary_variant_is_recounted_from_the_committed_scores() -> None:
    frozen = _plan()["frozen"]["band_minimums"]
    every = _plan()["experiments"]["band_boundaries"]["boundaries"]
    scores = [f["score"] for f in _eligible_committed()]

    def band(score: int, minimums: Mapping[str, int]) -> str:
        return next((name for name in BAND_ORDER[:3] if score >= minimums[name]), "Low")

    for variant in _record()["experiments"]["band_boundaries"]:
        change = variant["change"]
        moved = every if change["boundary"] == "all" else [change["boundary"]]
        minimums = {
            name: value + (change["shift"] if name in moved else 0)
            for name, value in frozen.items()
        }
        counted = Counter(band(score, minimums) for score in scores)
        corpus = variant["corpus"]
        assert corpus["bands"] == {name: counted.get(name, 0) for name in BAND_ORDER}, variant["id"]
        assert corpus["critical_or_high"] == counted["Critical"] + counted["High"], variant["id"]
        assert corpus["band_changed"] == sum(
            1 for score in scores if band(score, minimums) != band(score, frozen)
        ), variant["id"]


def test_gate_4_every_threshold_variant_is_recounted_from_the_committed_states() -> None:
    committed = _eligible_committed()
    missing = [
        sum(1 for key in CONTEXT if f["factor_states"][key] != "resolved") for f in committed
    ]

    for variant in _record()["experiments"]["low_confidence_threshold"]:
        threshold = variant["change"]["threshold"]
        assert variant["corpus"]["low_confidence"] == sum(1 for m in missing if m >= threshold), (
            variant["id"]
        )
    frozen = _plan()["frozen"]["low_confidence_threshold"]
    flagged = sum(1 for f in committed if f["low_confidence"])
    assert _record()["frozen"]["corpus"]["low_confidence"] == flagged
    assert flagged == sum(1 for m in missing if m >= frozen)


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
    assert frozen["corpus"]["findings"] == len(_eligible_committed())
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
# Not a second route: the repository's history.


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
