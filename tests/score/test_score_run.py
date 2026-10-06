"""`tools.score.run`: the replay that produces what S5's harness reads.

Three things are pinned here that nothing else would catch.

**The replay measures the same corpus as every other test.** `tools/` cannot import
`tests/_corpus.py`, so the tool wires its adapter runs independently - and two independent
wirings can drift while both stay green. `test_the_corpus_replay_is_the_wiring_every_other_
test_measures` compares them record for record.

**The pre-collapse population is the one S3b and S4 measured.** The tool's `before_dedupe`
block is compared with the path S4's gates score (`contextualize` then `score_all` over every
finding), and with the band distribution the S4 handoff records.

**A case is scored under its own declared context.** Asserted as wiring - each finding's
declared contributions equal the case's own declaration - and deliberately not as an outcome:
no test here says which case outranks which. That is the harness's question.
"""

from __future__ import annotations

import json
from collections import Counter
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import pytest

from _corpus import all_real_findings, real_dedupe, real_results, real_unparseable
from eval.ground_truth import load_and_validate
from iacrisk.context.extract import contextualize
from iacrisk.scoring import report
from iacrisk.scoring.engine import score_all
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS_LOCK = REPO_ROOT / "tools" / "corpus.lock.json"


@lru_cache(maxsize=1)
def _ground_truth() -> dict[str, Any]:
    return load_and_validate(score_run.GROUND_TRUTH)


@cache
def _replayed(name: str) -> score_run.Replayed:
    return score_run.replay(score_run.ROOTS[name])


@lru_cache(maxsize=1)
def _corpus() -> score_run.Replayed:
    return score_run.merge([_replayed(name) for name in score_run.CORPUS_V0])


@lru_cache(maxsize=1)
def _corpus_document() -> dict[str, Any]:
    return score_run.corpus_document()


@lru_cache(maxsize=1)
def _cases() -> dict[str, Any]:
    return score_run.score_cases(_ground_truth())


def _without_provenance(document: dict[str, Any]) -> dict[str, Any]:
    """`generated_utc` and `repo_commit` differ on every run by construction."""
    return {key: value for key, value in document.items() if key != "provenance"}


# --- the roots and their captures --------------------------------------------------


def test_roots_are_exactly_the_scan_roots_the_corpus_lockfile_declares() -> None:
    lock = json.loads(CORPUS_LOCK.read_bytes())
    declared = {(case["platform"], case["scan_root"]) for case in lock["cases"]}
    wired = {
        (root.platform, root.scan_root.relative_to(REPO_ROOT).as_posix())
        for root in score_run.ROOTS.values()
    }
    assert wired == declared


def test_every_capture_a_root_needs_is_committed() -> None:
    for name, root in score_run.ROOTS.items():
        paths = score_run.fixture_paths(root)
        assert paths, f"{name}: the lockfile declares no scanner for {root.platform}"
        assert all(path.is_file() for path in paths.values()), f"{name}: {paths}"


def test_tfsec_is_replayed_for_terraform_roots_only() -> None:
    """The platform matrix is the lockfile's, so this is a statement about data."""
    assert "tfsec" in score_run.fixture_paths(score_run.ROOTS["terragoat"])
    assert "tfsec" not in score_run.fixture_paths(score_run.ROOTS["kubernetes-goat"])


def test_the_corpus_replay_is_the_wiring_every_other_test_measures() -> None:
    corpus = _corpus()
    assert corpus.results == real_results()
    assert corpus.unparseable == real_unparseable()
    # A multiset, not a list: the two wirings visit the five runs in different orders, and
    # no figure depends on which run is read first.
    assert Counter(corpus.findings) == Counter(all_real_findings())


def test_merging_two_roots_that_share_an_adapter_run_is_an_error() -> None:
    terragoat = _replayed("terragoat")
    with pytest.raises(ValueError, match="share the adapter runs"):
        score_run.merge([terragoat, terragoat])


# --- declared context ---------------------------------------------------------------


def test_merged_declared_applies_the_last_case_and_reports_what_it_overrode() -> None:
    document = {
        "cases": [
            {"case_id": "a", "declared_context": {"r.x": {"sensitivity": 5, "criticality": 3}}},
            {"case_id": "b", "declared_context": {"r.y": {"sensitivity": 2, "criticality": 2}}},
            {"case_id": "c", "declared_context": {"r.x": {"sensitivity": 1, "criticality": 3}}},
            {"case_id": "d", "declared_context": {"r.y": {"sensitivity": 2, "criticality": 2}}},
        ]
    }
    declared, conflicts = score_run.merged_declared(document)

    assert declared == {
        "r.x": {"sensitivity": 1, "criticality": 3},
        "r.y": {"sensitivity": 2, "criticality": 2},
    }
    assert [c["resource_identity"] for c in conflicts] == ["r.x"], "r.y is declared twice, alike"
    assert conflicts[0]["applied"] == "c"
    assert [d["case_id"] for d in conflicts[0]["declarations"]] == ["a", "c"]


def test_every_real_conflict_is_an_identity_two_cases_declare_differently() -> None:
    """Counted independently of `merged_declared`, from the ground truth's own cases."""
    by_identity: dict[str, set[tuple[Any, Any]]] = {}
    for case in _ground_truth()["cases"]:
        for identity, values in case["declared_context"].items():
            by_identity.setdefault(identity, set()).add(
                (values["sensitivity"], values["criticality"])
            )
    expected = sorted(identity for identity, seen in by_identity.items() if len(seen) > 1)

    recorded = _corpus_document()["declared_context"]
    assert expected, "corpus v1 varies declared context on one resource; none would be vacuous"
    assert [c["resource_identity"] for c in recorded["conflicts"]] == expected
    assert recorded["identities"] == len(by_identity)


# --- the corpus target ----------------------------------------------------------------


def test_before_dedupe_is_the_population_s4s_gates_score() -> None:
    declared, _ = score_run.merged_declared(_ground_truth())
    corpus = _corpus()
    direct = report.to_json(
        report.build(
            score_all(
                contextualize(all_real_findings(), declared, corpus.tf_index, corpus.k8s_index)
            )
        )
    )
    assert _corpus_document()["before_dedupe"]["report"] == direct


def test_before_dedupe_reproduces_the_band_distribution_the_s4_handoff_records() -> None:
    """`docs/superpowers/specs/2026-10-01-s4-handoff.md` section 1, both columns. Restated
    on purpose: the claim under test is that this tool reproduces that committed record."""
    recorded = _corpus_document()["before_dedupe"]["report"]
    assert recorded["overall"] == {"Critical": 0, "High": 555, "Medium": 466, "Low": 34}
    assert recorded["eligible_only"] == {"Critical": 0, "High": 555, "Medium": 466, "Low": 4}


def test_the_ranked_population_is_what_survives_tier_1() -> None:
    document = _corpus_document()
    population = document["population"]
    removed = real_dedupe().collapsed_count

    assert population["findings_in"] == len(all_real_findings())
    assert population["tier1_collapsed"] == removed == document["retention"]["tier1_collapsed"]
    assert population["ranked"] == population["findings_in"] - removed
    assert len(document["findings"]) == document["report"]["total"] == population["ranked"]
    assert sum(document["report"]["overall"].values()) == population["ranked"]


def test_the_corpus_document_survives_a_json_round_trip() -> None:
    document = _corpus_document()
    assert json.loads(json.dumps(document)) == document


def test_provenance_says_replay_and_digests_every_capture() -> None:
    provenance = _corpus_document()["provenance"]
    captures = {
        path.relative_to(REPO_ROOT).as_posix()
        for name in score_run.CORPUS_V0
        for path in score_run.fixture_paths(score_run.ROOTS[name]).values()
    }
    assert provenance["mode"] == "replay"
    assert captures <= provenance["inputs"].keys()
    assert score_run.GROUND_TRUTH.relative_to(REPO_ROOT).as_posix() in provenance["inputs"]
    assert not any(":" in key or key.startswith("/") for key in provenance["inputs"])


def test_the_committed_corpus_artifact_matches_a_fresh_replay() -> None:
    """The tripwire for a stale artifact: a change to an adapter, an extractor, the engine or
    a capture that is not followed by regenerating `artifacts/scored-corpus-v0.json` fails
    here. Provenance is excluded - it carries a timestamp and the commit."""
    committed = json.loads(score_run.CORPUS_JSON.read_bytes())
    assert _without_provenance(committed) == _without_provenance(_corpus_document())


# --- the cases target -----------------------------------------------------------------


def test_every_case_is_scored_and_has_something_to_rank() -> None:
    cases = _cases()
    assert set(cases) == {case["case_id"] for case in _ground_truth()["cases"]}
    assert all(entry["findings"] for entry in cases.values())


def test_a_cases_findings_are_exactly_those_on_the_identities_it_declares() -> None:
    cases = _cases()
    for case in _ground_truth()["cases"]:
        entry = cases[case["case_id"]]
        declared = set(case["declared_context"])
        assert {f["resource_identity"] for f in entry["findings"]} == declared

        root = _replayed(entry["root"])
        on_identity = [f for f in root.findings if f.resource_identity in declared]
        assert sum(len(f["flagged_by"]) for f in entry["findings"]) == len(on_identity)


def test_every_case_is_scored_under_its_own_declared_context() -> None:
    """The reason the cases target exists. Two cases on one resource with different declared
    values must each see their own - which the corpus target's merged map cannot give."""
    cases = _cases()
    checked = 0
    for case in _ground_truth()["cases"]:
        for finding in cases[case["case_id"]]["findings"]:
            declared = case["declared_context"][finding["resource_identity"]]
            for key in ("sensitivity", "criticality"):
                if declared[key] is None:
                    assert finding["factor_states"][key] == "defaulted"
                else:
                    assert finding["factor_states"][key] == "resolved"
                    assert finding["contributions"][key] == declared[key]
                checked += 1
    assert checked, "no finding was checked; the loop would be vacuous"


def test_two_cases_on_one_resource_keep_their_own_declarations() -> None:
    """Derived from the ground truth rather than naming a pair: every identity the cases
    declare differently must show each case's own value, not one shared one."""
    cases = _cases()
    conflicts = _corpus_document()["declared_context"]["conflicts"]
    assert conflicts
    for conflict in conflicts:
        for declaration in conflict["declarations"]:
            for finding in cases[declaration["case_id"]]["findings"]:
                assert finding["contributions"]["sensitivity"] == declaration["sensitivity"]
                assert finding["contributions"]["criticality"] == declaration["criticality"]


def test_a_case_whose_identity_matches_no_finding_is_an_error() -> None:
    document = json.loads(json.dumps(_ground_truth()))
    case = document["cases"][0]
    case["declared_context"] = {
        "aws_s3_bucket.does_not_exist": {"sensitivity": 3, "criticality": 3}
    }
    with pytest.raises(ValueError, match="no finding"):
        score_run.score_cases(document)
