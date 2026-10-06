"""S3c acceptance gates: the auto-inference run and its agreement record.

`tests/context/test_inferred.py` and `tests/eval/test_agreement.py` pin the conventions and
the agreement rules on constructed inputs and were committed with them, before the mode had
been run. These gates run over the real committed artifacts and, as in the S5 and S6 gates,
restate no result: each checks a record against its inputs, its registration, or the other
record it has to agree with.

Judge this file by pytest's EXIT CODE (`CLAUDE.md`, Commands).
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

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
    """What makes the comparison a comparison of modes. Every finding in the declared run
    has its counterpart in the inferred run, and the four contributions the mode does not
    touch are identical on each pair."""
    pairs = agreement.pair_findings(_declared_corpus()["findings"], _inferred_corpus()["findings"])
    assert len(pairs) == len(_declared_corpus()["findings"]) == len(_inferred_corpus()["findings"])
    for declared, inferred in pairs:
        for factor in UNCHANGED_FACTORS:
            assert declared["contributions"].get(factor) == inferred["contributions"].get(factor)
            assert declared["factor_states"].get(factor) == inferred["factor_states"].get(factor)
        assert declared["baseline_band"] == inferred["baseline_band"]


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


def test_gate_3_the_scored_levels_are_the_inferred_levels() -> None:
    """The table of inferred values and the scored findings are produced separately; a
    finding whose resource has an inferred value must score exactly that level."""
    values = _inferred_corpus()["inference"]["values"]
    matched = 0
    for finding in _inferred_corpus()["findings"]:
        entry = values.get(finding["resource_identity"])
        if entry is None or finding["baseline_only_informational"]:
            continue
        for factor, value in entry.items():
            assert finding["contributions"][factor] == value["level"]
            assert finding["factor_states"][factor] == "resolved"
            matched += 1
    coverage = _record()["coverage"]["findings_inferred"]
    assert matched <= sum(coverage.values())


# --- gate 4: the agreement record says what its rules promise -------------------------


def test_gate_4_coverage_is_over_the_findings_the_framework_makes_a_claim_about() -> None:
    coverage = _record()["coverage"]
    counted = [
        f
        for f in _inferred_corpus()["findings"]
        if not f["unmapped"] and not f["baseline_only_informational"]
    ]
    assert coverage["findings"] == len(counted)
    assert coverage["resources"] == len({f["resource_identity"] for f in counted})
    for factor in INFERRED_FACTORS:
        assert coverage["findings_inferred"][factor] == sum(
            1 for f in counted if f["factor_states"][factor] == "resolved"
        )


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


def test_gate_4_a_pair_is_not_applicable_exactly_when_both_cases_are_one_resource() -> None:
    by_id = {case["case_id"]: case for case in _ground_truth()["cases"]}
    expected = [
        pair["pair_id"]
        for pair in _ground_truth()["contrastive_pairs"]
        if set(by_id[pair["case_high"]]["declared_context"])
        == set(by_id[pair["case_low"]]["declared_context"])
    ]
    oracle = _record()["oracle"]

    assert oracle["pairs_not_applicable"] == expected
    assert oracle["pairs_applicable"] == oracle["pairs_authored"] - len(expected)
    for mode in ("declared", "inferred"):
        assert not set(oracle[mode]["pairs_failed"]) & set(expected)
        assert (
            oracle[mode]["pairs_passed"] + len(oracle[mode]["pairs_failed"])
            == oracle["pairs_applicable"]
        )


def test_gate_4_the_declared_column_is_the_evaluation_records_own_verdict() -> None:
    """The agreement module grades the declared run again so both columns come from one
    function. It must reach what the evaluation record already says."""
    evaluation = _load(REPO_ROOT / "artifacts" / "evaluation-v1.json")
    headline = evaluation["scenarios"]["summary"]["headline"]["framework"]["max"]
    declared = _record()["oracle"]["declared"]

    assert declared["scenarios_exact"] == headline["exact_tier_matches"]
    assert declared["ordered_pairs_concordant"] == headline["ordered_pairs_concordant"]
    assert declared["ordered_pairs_tied"] == headline["ordered_pairs_tied"]
    assert declared["ordered_pairs_discordant"] == headline["ordered_pairs_discordant"]


# --- gate 5: the conventions were registered before the mode was run -------------------


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
