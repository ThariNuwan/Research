"""S4 acceptance gates (design spec §10).

Every figure these gates assert is derived from the committed golden fixtures
(`tests/harvest/fixtures/`) and the vendored corpus, never restated from a document.

Judge this file by pytest's EXIT CODE. Under `addopts = -q --strict-markers -rs` a failing
test prints `F` and a traceback and emits no line beginning with `FAILED`, so grepping for
one returns 0 on a red suite.

One lesson from S3b is binding here: a defect leaving 0 of 217 container identities unmatched
survived seven gates and 746 tests because every test built its own fixture keyed the way the
code expected. Gates that report a rate therefore measure it over the real corpus (gate 7),
not over hand-built inputs.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from _corpus import KUBERNETES_SCAN_ROOT as K8S_ROOT
from _corpus import TERRAFORM_SCAN_ROOT as TF_ROOT
from _corpus import all_real_findings as _all_real_findings
from iacrisk import rubric, taxonomy
from iacrisk.context.extract import ContextualizedFinding, contextualize
from iacrisk.context.kubernetes import build_body_index
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.terraform import build_index as build_tf_index
from iacrisk.scoring import emit, report
from iacrisk.scoring.engine import FACTOR_ORDER, ScoredFinding, score, score_all
from iacrisk.scoring.factor_map import (
    GAP_CANDIDATE_FACTORS,
    bearing_factors,
    is_factor_gap,
    is_substantive_gap,
    table,
)
from iacrisk.scoring.rank import rank_all

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"


def _declared() -> dict[str, dict[str, int]]:
    document = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    declared: dict[str, dict[str, int]] = {}
    for case in document["cases"]:
        for identity, values in (case.get("declared_context") or {}).items():
            declared[identity] = values
    return declared


def _tf_index() -> dict[str, TerraformResource]:
    return build_tf_index(sorted(TF_ROOT.rglob("*.tf")), TF_ROOT)


def _k8s_index() -> dict[str, dict[str, Any]]:
    files = sorted(K8S_ROOT.rglob("*.yaml")) + sorted(K8S_ROOT.rglob("*.yml"))
    return build_body_index(files)


def _contextualized() -> list[ContextualizedFinding]:
    return contextualize(_all_real_findings(), _declared(), _tf_index(), _k8s_index())


def _scored() -> list[ScoredFinding]:
    return score_all(_contextualized())


def _other_class_in_same_category(class_id: str) -> str:
    classes = taxonomy.classes()
    entry = classes.get(class_id)
    if entry is None:
        substitute = sorted(classes)[0]
    else:
        siblings = sorted(
            other
            for other, e in classes.items()
            if e.category == entry.category and other != class_id
        )
        assert siblings, f"category {entry.category!r} has one class; mutation would be vacuous"
        substitute = siblings[0]
    assert substitute != class_id, "mutation must change the class or the gate is vacuous"
    return substitute


def _any_other_class(class_id: str) -> str:
    classes = taxonomy.classes()
    entry = classes.get(class_id)
    own = entry.category if entry is not None else None
    others = sorted(o for o, e in classes.items() if e.category != own and o != class_id)
    assert others, f"no class outside category {own!r}; mutation would be vacuous"
    return others[0]


def test_gate_1_every_score_is_the_sum_of_its_contributions_in_bounds_and_banded() -> None:
    minimum, maximum = rubric.score_bounds()
    results = _scored()
    assert results, "expected a non-empty corpus"
    for item in results:
        assert sum(item.contributions.values()) == item.score, item.finding.resource_identity
        assert minimum <= item.score <= maximum
        assert item.band == rubric.band_for(item.score)
        assert item.action == next(b.action for b in rubric.bands() if b.name == item.band)


def test_gate_2_every_addend_is_a_scored_level_so_an_unresolved_factor_still_scores() -> None:
    """No contribution is ever read from `FactorValue.level`, which is `int | None`.

    Constructed rather than sampled: a finding with every context factor unresolved and an
    unknown severity must still produce six integer contributions summing to 20 - spec §1.1's
    washout. Reading `level` anywhere in the sum would raise a TypeError instead.
    """
    results = _scored()
    for item in results:
        assert all(isinstance(v, int) for v in item.contributions.values())

    all_unresolved = next(
        (
            item
            for item in results
            if item.severity.level is None
            and len(item.contextualized.unresolved_factors)
            + len(item.contextualized.defaulted_factors)
            == 5
        ),
        None,
    )
    assert all_unresolved is not None, "expected at least one fully unresolved finding in v0"
    assert all_unresolved.score == 20
    assert all_unresolved.band == "High"


def test_gate_3_every_scored_finding_carries_one_explanation_line_per_contribution() -> None:
    for item in _scored():
        assert len(item.explanation) == len(item.contributions)
        assert all(line.strip() for line in item.explanation)
        for key in item.contributions:
            assert any(line.startswith(f"{key}:") for line in item.explanation), key
            line = next(ln for ln in item.explanation if ln.startswith(f"{key}:"))
            assert str(item.contributions[key]) in line
            assert " - " in line, "an explanation line must carry its evidence"


def test_gate_4a_fencing_no_contribution_depends_on_the_issue_class() -> None:
    """`severity_context_fencing`, by mutation across AND within taxonomy categories.

    S3b's gate 5 proves it at layer 3. S4 re-proves it on the sum, because a scoring layer
    could reintroduce the dependency the extractors do not have.
    """
    findings = _all_real_findings()
    declared, tf_index, k8s_index = _declared(), _tf_index(), _k8s_index()
    baseline = score_all(contextualize(findings, declared, tf_index, k8s_index))

    for label, mutate in (
        ("same-category", _other_class_in_same_category),
        ("cross-category", _any_other_class),
    ):
        mutated_findings = [replace(f, issue_class=mutate(f.issue_class)) for f in findings]
        assert all(
            a.issue_class != b.issue_class for a, b in zip(findings, mutated_findings, strict=True)
        ), "every class must actually change or this gate is vacuous"
        mutated = score_all(contextualize(mutated_findings, declared, tf_index, k8s_index))
        assert len(baseline) == len(mutated)
        for before, after in zip(baseline, mutated, strict=True):
            assert before.contributions == after.contributions, (
                f"{before.finding.resource_identity}: contributions changed after {label} "
                f"class mutation - the scoring layer read the class"
            )


def test_gate_4b_orthogonality_declared_sensitivity_moves_only_its_own_factor() -> None:
    """`encryption_sensitivity_orthogonality`: the rule says the two axes share no input.

    Varying declared sensitivity must change the sensitivity contribution and nothing else -
    in particular not encryption, which keys only on the control-mandate being an established
    engineering requirement.
    """
    findings = _all_real_findings()
    tf_index, k8s_index = _tf_index(), _k8s_index()
    declared = _declared()
    assert declared, "expected corpus-v1 to declare context for some resources"

    low = {k: {**v, "sensitivity": 0} for k, v in declared.items()}
    high = {k: {**v, "sensitivity": 5} for k, v in declared.items()}

    a = score_all(contextualize(findings, low, tf_index, k8s_index))
    b = score_all(contextualize(findings, high, tf_index, k8s_index))

    moved = 0
    for before, after in zip(a, b, strict=True):
        for key in FACTOR_ORDER:
            if key not in before.contributions:
                continue
            if key == "sensitivity":
                if before.contributions[key] != after.contributions[key]:
                    moved += 1
                continue
            assert before.contributions[key] == after.contributions[key], (
                f"{before.finding.resource_identity}: {key} moved when only declared "
                f"sensitivity changed - the two axes share an input"
            )
    assert moved > 0, "declared sensitivity must move the sensitivity contribution somewhere"


def test_gate_5_context_ineligible_findings_score_on_severity_alone() -> None:
    """The washout `context_eligible` closes stays closed: no defaulted context creeps in."""
    ineligible = [item for item in _scored() if not item.finding.context_eligible]
    assert ineligible, "corpus v0 carries context-ineligible findings; expected some here"
    for item in ineligible:
        assert set(item.contributions) == {"severity"}
        assert item.score == item.contributions["severity"]
        assert item.baseline_only_informational is True
        assert len(item.explanation) == 1
        assert item.low_confidence is False


def test_gate_6_all_four_distributions_and_the_per_factor_summary_are_emitted() -> None:
    results = _scored()
    built = report.build(results)
    bands = {band.name for band in rubric.bands()}

    assert set(built.overall) == bands
    assert sum(built.overall.values()) == len(results)
    assert sorted(built.by_defaulted_count) == [0, 1, 2, 3, 4, 5]
    assert sum(sum(v.values()) for v in built.by_defaulted_count.values()) == len(results)

    # The three gap views, which spec §2.2 requires as a set rather than a single number.
    assert set(built.including_factor_gap) == bands
    assert set(built.excluding_substantive_gap) == bands
    assert set(built.excluding_all_gap) == bands
    assert sum(built.including_factor_gap.values()) == len(results)
    assert sum(built.excluding_all_gap.values()) == len(results) - built.factor_gap_count
    assert sum(built.excluding_substantive_gap.values()) == (
        len(results) - built.substantive_gap_count
    )

    assert sum(built.framework_vs_baseline.values()) == len(results)
    assert set(built.per_factor) == set(FACTOR_ORDER)

    payload = emit.to_json(rank_all(results), built)
    json.dumps(payload)
    assert len(payload["findings"]) == len(results)


def test_gate_7_the_factor_map_covers_28x6_and_the_gap_population_is_measured() -> None:
    """Spec §2.2 and §1.4. The counts come from the real corpus, not from a document.

    `CLAUDE.md` named five candidate gap classes and said the set was not established as
    complete. The sweep this table makes possible found 14, covering 42.3% of eligible
    findings rather than 11.9% - which is why the gate measures rather than restates.
    """
    assert set(table()) == set(taxonomy.classes())
    assert len(table()) == 28
    valid = set(rubric.factors())
    for class_id, factors in table().items():
        assert factors <= valid, class_id
        assert {"severity", "sensitivity", "criticality"} <= factors, class_id
    assert frozenset({"exposure", "privilege", "encryption"}) == GAP_CANDIDATE_FACTORS

    gap_classes = {c for c in table() if is_factor_gap(c)}
    assert len(gap_classes) == 14
    substantive_classes = {c for c in gap_classes if is_substantive_gap(c)}
    assert len(substantive_classes) == 10

    results = _scored()
    eligible = [r for r in results if r.finding.context_eligible]
    gap = [r for r in eligible if r.factor_gap]
    substantive = [r for r in gap if r.finding.issue_class in substantive_classes]

    # Derived from the table, never hand-listed: every gap finding's class is in the set.
    for item in gap:
        assert is_factor_gap(item.finding.issue_class)
    for item in eligible:
        if item.unmapped:
            assert item.factor_gap is False

    assert len(gap) == 434, len(gap)
    assert len(substantive) == 256, len(substantive)
    assert len(gap) - len(substantive) == 178

    built = report.build(results)
    assert built.factor_gap_count == len(gap)
    assert built.substantive_gap_count == len(substantive)


def test_gate_8_a_non_default_weight_map_is_rejected_by_the_report_path() -> None:
    """Spec §4.4: weights exist so S5 need not fork the engine, and the frozen primary model
    must not silently become weighted.
    """
    contextualized = _contextualized()[:20]
    weighted = score_all(contextualized, weights={"exposure": 2})
    assert any(item.weighted for item in weighted)
    with pytest.raises(ValueError, match="weighted"):
        emit.to_json(rank_all(weighted), report.build(weighted))

    unweighted = score_all(contextualized)
    assert not any(item.weighted for item in unweighted)
    emit.to_json(rank_all(unweighted), report.build(unweighted))


def test_the_bearing_factors_accessor_raises_for_an_unmapped_class() -> None:
    with pytest.raises(KeyError):
        bearing_factors("unmapped:checkov:CKV_AWS_62")


def test_a_single_scored_finding_is_internally_consistent() -> None:
    """A spot check that `score` alone, outside the corpus sweep, holds the same invariants."""
    item = score(_contextualized()[0])
    assert sum(item.contributions.values()) == item.score
    assert item.band == rubric.band_for(item.score)
