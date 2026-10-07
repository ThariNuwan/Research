"""S3c acceptance gates: the auto-inference run and its agreement record.

`tests/context/test_inferred.py` and `tests/eval/test_agreement.py` pin the conventions and
the agreement rules on constructed inputs and were committed with them, before the mode had
been run. These gates run over the real committed artifacts.

**What is recomputed here by a second route, and what is not.** An earlier version of this
docstring said no gate restated a result. A pre-merge code review found three that did, or
that could not fail: one bounded a count by a sum it could never exceed, one recounted
coverage with the module's own expression, and one derived the not-applicable pairs the way
the module derives them. Now:

- which findings took an inferred value is read from the framework's table of inferred
  values, and held against the per-finding states in both directions;
- level agreement is recounted from the ground truth and every inferred case, against the
  rubric's defaults rather than the plan's copy of them;
- finding-level ranking agreement is recounted by a pairing that needs no matching order,
  after the property that makes the order immaterial has itself been checked;
- a pair is called not applicable from its outcome - the inferred run scores its two cases
  identically - and both columns of the oracle are regraded by `tests/_regrade.py`.

Gates 1 and 5 are not second routes. They check freshness, provenance and commit order.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from _regrade import claimed, failing_pairs, grade_scenario, tau_b, top_score
from eval import agreement
from eval.ground_truth import load_and_validate
from iacrisk import rubric
from iacrisk.context.inferred import ORIGIN, conventions
from tools.harvest.provenance import hash_file
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent
CONVENTIONS = "src/iacrisk/data/inference_conventions.json"
INFERRED_FACTORS = ("sensitivity", "criticality")
UNCHANGED_FACTORS = ("severity", "exposure", "privilege", "encryption")
CONTAINER_SUFFIX = " [container="

Key = tuple[str, str, str, str, str, str]


def _load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_bytes())
    return document


@lru_cache(maxsize=1)
def _record() -> dict[str, Any]:
    return _load(agreement.OUTPUT)


@lru_cache(maxsize=1)
def _declared_corpus() -> dict[str, Any]:
    return _load(agreement.DECLARED_CORPUS)


@lru_cache(maxsize=1)
def _declared_cases() -> dict[str, Any]:
    return _load(agreement.DECLARED_CASES)


@lru_cache(maxsize=1)
def _inferred_corpus() -> dict[str, Any]:
    return _load(agreement.INFERRED_CORPUS)


@lru_cache(maxsize=1)
def _inferred_cases() -> dict[str, Any]:
    return _load(agreement.INFERRED_CASES)


@lru_cache(maxsize=1)
def _ground_truth() -> dict[str, Any]:
    return load_and_validate(agreement.GROUND_TRUTH)


def _without_provenance(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "provenance"}


def _inferred_findings() -> list[dict[str, Any]]:
    corpus: list[dict[str, Any]] = list(_inferred_corpus()["findings"])
    cases = [f for entry in _inferred_cases()["cases"].values() for f in entry["findings"]]
    return corpus + cases


def _by_key(findings: Sequence[Mapping[str, Any]]) -> dict[Key, list[Mapping[str, Any]]]:
    """Findings grouped by everything that identifies one, since the JSON carries no id."""
    groups: dict[Key, list[Mapping[str, Any]]] = {}
    for f in findings:
        key = (
            f["resource_identity"],
            f["issue_class"],
            f["scanner"],
            f["rule_id"],
            f["file_path"],
            json.dumps(f["flagged_by"], sort_keys=True),
        )
        groups.setdefault(key, []).append(f)
    return groups


def _inferred_entry(identity: str) -> Mapping[str, Any]:
    """The table's entry for a finding's resource; a container reads its workload's."""
    values: Mapping[str, Mapping[str, Any]] = _inferred_corpus()["inference"]["values"]
    return values.get(identity) or values.get(identity.split(CONTAINER_SUFFIX)[0]) or {}


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


# --- gate 1: the records are what the committed code makes of the committed inputs -----
# Not a second route: freshness and provenance.


def test_gate_1_the_committed_inferred_runs_match_a_fresh_replay() -> None:
    assert _without_provenance(_inferred_corpus()) == _without_provenance(
        score_run.inferred_corpus_document()
    )
    assert _without_provenance(_inferred_cases()) == _without_provenance(
        score_run.inferred_cases_document()
    )


def test_gate_1_the_agreement_record_matches_a_fresh_run_and_names_its_inputs() -> None:
    record = _record()
    assert _without_provenance(record) == _without_provenance(agreement.agreement_document())
    assert record["provenance"]["inputs"] == {
        path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in agreement.INPUTS
    }


# --- gate 2: the two modes differ in the two factors and in nothing else ---------------


def test_gate_2_the_two_runs_hold_the_same_findings_and_differ_only_in_two_factors() -> None:
    """What makes the comparison a comparison of modes. Key by key the two runs hold the
    same number of findings, and what the mode does not touch - four contributions, their
    states and the baseline band - is the same multiset on both sides."""

    def untouched(finding: Mapping[str, Any]) -> str:
        return json.dumps(
            [
                {k: finding["contributions"].get(k) for k in UNCHANGED_FACTORS},
                {k: finding["factor_states"].get(k) for k in UNCHANGED_FACTORS},
                finding["baseline_band"],
            ],
            sort_keys=True,
        )

    declared = _by_key(_declared_corpus()["findings"])
    inferred = _by_key(_inferred_corpus()["findings"])
    assert set(declared) == set(inferred)
    for key, members in declared.items():
        assert Counter(map(untouched, members)) == Counter(map(untouched, inferred[key])), key
    assert len(_declared_corpus()["findings"]) == len(_inferred_corpus()["findings"])


def test_gate_2_findings_that_share_a_key_share_a_score_within_each_run() -> None:
    """The scored JSON has no finding id, so where one rule fires more than once on a
    resource the agreement module matches the copies in score order. That choice can only
    matter if the copies differ. They do not, in either run - which is what lets the
    ranking figures below be recounted with no matching order at all."""
    repeated = 0
    for document in (_declared_corpus(), _inferred_corpus()):
        for key, members in _by_key(document["findings"]).items():
            if len(members) > 1:
                repeated += len(members)
                assert len({f["score"] for f in members}) == 1, key
                assert len({f["band"] for f in members}) == 1, key
    assert repeated, "no key holds two findings; the property would be untested"


def test_gate_2_no_declared_value_reaches_an_inferred_run() -> None:
    """One mode or the other, never merged. In the inferred runs every sensitivity or
    criticality is either a default or carries the convention origin in its evidence, and
    no explanation line anywhere cites declared context."""
    checked = 0
    for finding in _inferred_findings():
        assert not any("declared context for" in line for line in finding["explanation"])
        for factor in INFERRED_FACTORS:
            if finding["factor_states"].get(factor) == "resolved":
                line = next(line for line in finding["explanation"] if line.startswith(factor))
                assert ORIGIN in line, line
                checked += 1
    assert _inferred_corpus()["context_mode"] == _inferred_cases()["context_mode"]
    assert _inferred_corpus()["context_mode"] == "auto-inference"
    assert checked, "no inferred value was checked; the evidence assertion would be vacuous"


# --- gate 3: what the conventions resolved obeys the rules they were registered with ---


def test_gate_3_every_inferred_value_on_the_real_corpus_obeys_the_registered_rules() -> None:
    default = int(rubric.factors()["sensitivity"].unresolved_default)
    known_sources = {"tag", "label", "namespace", "name"}
    for identity, entry in _inferred_corpus()["inference"]["values"].items():
        for factor, value in entry.items():
            assert factor in INFERRED_FACTORS, identity
            assert value["source"] in known_sources, identity
            bounds = rubric.factors()[factor]
            assert bounds.minimum <= value["level"] <= bounds.maximum, identity
            if factor == "criticality":
                assert value["level"] <= 4, f"{identity}: criticality inferred above 4"
                assert value["source"] != "name", f"{identity}: criticality from a name"
            if value["source"] == "name":
                assert value["level"] > default, f"{identity}: a name hint lowered a value"


def test_gate_3_a_finding_is_resolved_exactly_where_the_table_holds_a_value() -> None:
    """The table of inferred values and the scored findings are written by different code.
    Held against each other both ways: a finding on a resource the table gives a value
    scores that level as `resolved`, and no finding is `resolved` without one. The second
    direction is what the earlier form of this gate lacked - it bounded the count from
    above by a sum the count could never exceed.

    A Terraform attachment that inherited an inferred value through the resource it
    governs would be resolved with no table entry of its own, and would fail here. None
    exists in this corpus; if one appears, this gate has to learn the inheritance rule.
    """
    resolved = 0
    for finding in claimed(_inferred_corpus()["findings"]):
        entry = _inferred_entry(finding["resource_identity"])
        for factor in INFERRED_FACTORS:
            if factor in entry:
                assert finding["contributions"][factor] == entry[factor]["level"]
                assert finding["factor_states"][factor] == "resolved"
                resolved += 1
            else:
                assert finding["factor_states"][factor] != "resolved", (
                    finding["resource_identity"],
                    factor,
                )
    assert resolved, "no inferred value reached a finding; the gate would be vacuous"
    assert resolved == sum(_record()["coverage"]["findings_inferred"].values())


# --- gate 4: the agreement record says what its rules promise -------------------------


def test_gate_4_coverage_is_recounted_from_the_table_of_inferred_values() -> None:
    """The agreement module counts a finding as inferred when its state is `resolved`.
    Here the same figures come from the other side: the resources the framework's own
    table names."""
    coverage = _record()["coverage"]
    counted = claimed(_inferred_corpus()["findings"])
    values = _inferred_corpus()["inference"]["values"]

    assert coverage["findings"] == len(counted)
    assert coverage["resources"] == len({f["resource_identity"] for f in counted})
    for factor in INFERRED_FACTORS:
        holders = [f for f in counted if factor in _inferred_entry(f["resource_identity"])]
        assert coverage["findings_inferred"][factor] == len(holders), factor
        assert coverage["resources_inferred"][factor] == len(
            {f["resource_identity"] for f in holders}
        ), factor
    assert coverage["indexed_resources_with_any_inferred_value"] == len(values)
    sources = Counter(
        f"{factor}:{value['source']}"
        for entry in values.values()
        for factor, value in entry.items()
    )
    assert coverage["inferred_values_by_factor_and_source"] == dict(sorted(sources.items()))


def test_gate_4_level_agreement_excludes_exactly_the_resources_with_no_single_reference() -> None:
    """Cross-checked against a record another tool wrote: the declared corpus artifact
    lists the identities corpus v1's cases declare differently."""
    conflicts = [
        c["resource_identity"] for c in _declared_corpus()["declared_context"]["conflicts"]
    ]
    level = _record()["level_agreement"]

    assert level["excluded_as_conflicting"] == sorted(conflicts)
    for factor in INFERRED_FACTORS:
        block = level["by_factor"][factor]
        assert block["resources"] == len(block["rows"])
        assert not {row["resource_identity"] for row in block["rows"]} & set(conflicts)
        assert block["resources"] + block["excluded_as_undeclared"] == level[
            "declared_resources"
        ] - len(conflicts)


def test_gate_4_level_agreement_is_recounted_from_the_ground_truth_and_every_case() -> None:
    """The module reads a resource's inferred level from the first finding of the first
    case that declares it. Here it is read from every finding on the resource in every
    inferred case, which must agree, and the strawman is the rubric's default rather than
    the copy of it in the sensitivity plan."""
    declarations: dict[str, set[tuple[Any, Any]]] = {}
    for case in _ground_truth()["cases"]:
        for identity, values in case["declared_context"].items():
            declarations.setdefault(identity, set()).add(
                (values["sensitivity"], values["criticality"])
            )
    scored: dict[str, dict[str, set[int]]] = {}
    for entry in _inferred_cases()["cases"].values():
        for finding in claimed(entry["findings"]):
            for factor in INFERRED_FACTORS:
                scored.setdefault(finding["resource_identity"], {}).setdefault(factor, set()).add(
                    finding["contributions"][factor]
                )

    level = _record()["level_agreement"]
    assert level["declared_resources"] == len(declarations)
    for index, factor in enumerate(INFERRED_FACTORS):
        default = int(rubric.factors()[factor].unresolved_default)
        mine: Counter[str] = Counter()
        for seen in declarations.values():
            if len(seen) != 1:
                continue
            declared = next(iter(seen))[index]
            if declared is None:
                mine["undeclared"] += 1
        for identity, seen in declarations.items():
            if len(seen) != 1 or next(iter(seen))[index] is None:
                continue
            declared = next(iter(seen))[index]
            (inferred,) = scored[identity][factor]
            mine["rows"] += 1
            mine["exact"] += inferred == declared
            mine["under"] += inferred < declared
            mine["over"] += inferred > declared
            mine["default_exact"] += default == declared
            mine["default_under"] += default < declared
            mine["default_over"] += default > declared

        block = level["by_factor"][factor]
        assert block["resources"] == mine["rows"], factor
        assert block["excluded_as_undeclared"] == mine["undeclared"], factor
        assert [block["inferred"][k] for k in ("exact", "under", "over")] == [
            mine["exact"],
            mine["under"],
            mine["over"],
        ], factor
        assert [block["all_default"][k] for k in ("exact", "under", "over")] == [
            mine["default_exact"],
            mine["default_under"],
            mine["default_over"],
        ], factor


def test_gate_4_the_all_default_strawman_is_beside_every_agreement_figure() -> None:
    plan = _load(agreement.PLAN)["frozen"]["unresolved_defaults"]
    for factor in INFERRED_FACTORS:
        block = _record()["level_agreement"]["by_factor"][factor]
        assert set(block["inferred"]) == set(block["all_default"])
        assert all(row["default"] == plan[factor] for row in block["rows"])
        assert block["resolved_by_a_convention"] == sum(
            1 for row in block["rows"] if row["inferred_from_a_convention"]
        )
        for row in block["rows"]:
            if not row["inferred_from_a_convention"]:
                assert row["inferred"] == row["default"], row


def test_gate_4_ranking_agreement_is_recounted_with_no_matching_order() -> None:
    """Every finding of a key has one score in each run (gate 2), so a key contributes its
    whole count to one outcome and nothing depends on which copy is matched with which."""
    declared = _by_key(claimed(_declared_corpus()["findings"]))
    inferred = _by_key(claimed(_inferred_corpus()["findings"]))
    assert set(declared) == set(inferred)

    tallies: dict[str, Counter[str]] = {"all": Counter(), "declared": Counter()}
    scores: dict[str, tuple[list[int], list[int]]] = {"all": ([], []), "declared": ([], [])}
    for key, members in declared.items():
        (before,) = {f["score"] for f in members}
        (after,) = {f["score"] for f in inferred[key]}
        (band_before,) = {f["band"] for f in members}
        (band_after,) = {f["band"] for f in inferred[key]}
        (on_declared,) = {
            any(f["factor_states"][factor] == "resolved" for factor in INFERRED_FACTORS)
            for f in members
        }
        for name in ("all", "declared") if on_declared else ("all",):
            tally, count = tallies[name], len(members)
            tally["findings"] += count
            tally["same_score"] += count * (before == after)
            tally["same_band"] += count * (band_before == band_after)
            tally["inferred_higher"] += count * (after > before)
            tally["inferred_lower"] += count * (after < before)
            tally["absolute"] += count * abs(after - before)
            scores[name][0].extend([before] * count)
            scores[name][1].extend([after] * count)

    ranking = _record()["ranking_agreement"]
    for name, block in (
        ("all", ranking["all_context_eligible_findings"]),
        ("declared", ranking["on_declared_resources"]),
    ):
        tally = tallies[name]
        for field in ("findings", "same_score", "same_band", "inferred_higher", "inferred_lower"):
            assert block[field] == tally[field], (name, field)
        assert block["mean_absolute_score_difference"] == pytest.approx(
            tally["absolute"] / tally["findings"]
        ), name
        assert block["kendall_tau_b"] == pytest.approx(tau_b(*scores[name])), name


def test_gate_4_a_pair_is_not_applicable_exactly_when_the_run_scores_its_cases_as_one() -> None:
    """Rule 6 from its consequence instead of its cause. The module calls a pair not
    applicable when its two cases declare the same resource. If that is right, the inferred
    run - which gives a resource one value - must have scored the two cases identically,
    and must not have done so for any other pair."""
    cases = _inferred_cases()["cases"]
    fields = ("resource_identity", "issue_class", "scanner", "rule_id", "score", "contributions")

    def scored(case_id: str) -> list[str]:
        return sorted(
            json.dumps({k: f[k] for k in fields}, sort_keys=True)
            for f in cases[case_id]["findings"]
        )

    identical = [
        pair["pair_id"]
        for pair in _ground_truth()["contrastive_pairs"]
        if scored(pair["case_high"]) == scored(pair["case_low"])
    ]
    oracle = _record()["oracle"]

    assert identical, "no pair is scored as one case; the gate would be vacuous"
    assert oracle["pairs_not_applicable"] == identical
    assert oracle["pairs_applicable"] == oracle["pairs_authored"] - len(identical)
    assert oracle["pairs_authored"] == len(_ground_truth()["contrastive_pairs"])


def test_gate_4_both_columns_of_the_oracle_are_regraded_from_the_scored_cases() -> None:
    truth = _ground_truth()
    oracle = _record()["oracle"]
    applicable = [
        pair
        for pair in truth["contrastive_pairs"]
        if pair["pair_id"] not in oracle["pairs_not_applicable"]
    ]
    for mode, document in (("declared", _declared_cases()), ("inferred", _inferred_cases())):
        top = {
            case_id: top_score(entry["findings"]) for case_id, entry in document["cases"].items()
        }
        column = oracle[mode]

        failed = failing_pairs(applicable, top)
        assert column["pairs_failed"] == failed, mode
        assert column["pairs_not_evaluable"] == [], mode
        assert column["pairs_passed"] == len(applicable) - len(failed), mode
        assert (
            column["pairs_passed"]
            + len(column["pairs_failed"])
            + len(column["pairs_not_evaluable"])
            == oracle["pairs_applicable"]
        ), mode

        exact = 0
        total: Counter[str] = Counter()
        for scenario in truth["scenarios"]:
            expected = scenario["expected_ordering"]
            mine = grade_scenario(expected, {c: top[c] for tier in expected for c in tier})
            block = column["by_scenario"][scenario["scenario_id"]]
            assert block["ordering"] == mine["ordering"], (mode, scenario["scenario_id"])
            assert block["exact_tier_match"] is mine["exact"], (mode, scenario["scenario_id"])
            if mine["tau_b"] is None:
                assert block["kendall_tau_b"] is None, (mode, scenario["scenario_id"])
            else:
                assert block["kendall_tau_b"] == pytest.approx(mine["tau_b"])
            if scenario["oracle"]["reviewer_verdict"] != "disagree":
                exact += mine["exact"]
                total.update(mine["counts"])
        assert column["scenarios_exact"] == exact, mode
        assert column["ordered_pairs_concordant"] == total["concordant"], mode
        assert column["ordered_pairs_tied"] == total["tied"], mode
        assert column["ordered_pairs_discordant"] == total["discordant"], mode


def test_gate_4_the_declared_column_agrees_with_the_evaluation_record() -> None:
    """A consistency check between two records, not an independent one: both are graded by
    `eval.harness`. Agreement shows that neither is stale."""
    evaluation = _load(REPO_ROOT / "artifacts" / "evaluation-v1.json")
    headline = evaluation["scenarios"]["summary"]["headline"]["framework"]["max"]
    declared = _record()["oracle"]["declared"]

    assert declared["scenarios_exact"] == headline["exact_tier_matches"]
    assert declared["ordered_pairs_concordant"] == headline["ordered_pairs_concordant"]
    assert declared["ordered_pairs_tied"] == headline["ordered_pairs_tied"]
    assert declared["ordered_pairs_discordant"] == headline["ordered_pairs_discordant"]


# --- gate 5: the conventions were registered before the mode was run -------------------
# Not a second route: the repository's history.


def test_gate_5_the_conventions_were_committed_before_any_inferred_run() -> None:
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")

    def first_commit(path: str) -> str:
        added = _git("log", "--diff-filter=A", "--format=%H", "--", path)
        assert added, f"{path} has no adding commit in history"
        return added.splitlines()[-1]

    registered = first_commit(CONVENTIONS)
    for artifact in (
        "artifacts/scored-corpus-v0-inferred.json",
        "artifacts/scored-cases-v1-inferred.json",
        "artifacts/auto-inference-agreement-v1.json",
    ):
        produced = first_commit(artifact)
        assert registered != produced, f"the conventions and {artifact} arrived in one commit"
        assert _git("merge-base", "--is-ancestor", registered, produced) is not None, artifact


def test_gate_5_the_conventions_have_not_changed_since_they_were_registered() -> None:
    """A word added after the fact - one that happened to match a declared resource -
    would turn a measurement of the conventions into a fit to the corpus."""
    if _git("rev-parse", "--is-shallow-repository") != "false":
        pytest.skip("needs full history: not a git checkout, or a shallow one")
    commits = _git("log", "--format=%H", "--", CONVENTIONS)
    assert commits is not None and len(commits.splitlines()) == 1, (
        f"{CONVENTIONS} has been modified since it was registered; a changed convention is "
        "a second registered round and needs its own file"
    )
    assert conventions()["registered"] == "2026-10-06"
