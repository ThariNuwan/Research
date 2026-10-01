# S4 — Risk Scoring and Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn each contextualized finding into an explainable score, a priority band and a rank, emit the JSON that S5's harness will read, and render a human report — enforcing the rubric's four coherence rules and the S1 structural freeze rather than restating them.

**Architecture:** A new package `src/iacrisk/scoring/`, mirroring the `context/` and `scanners/` precedent. A committed 28 × 6 class-to-factor data artifact with a thin loader (mirroring `taxonomy.py` and `rubric.py`), the engine, the severity baseline, the reports, and a renderer. `ScoredFinding` wraps `ContextualizedFinding`; nothing S3b wrote is modified. No evaluation metrics — those are S5's.

**Tech Stack:** Python 3.12 (pinned by `.python-version`), uv, `python-hcl2`, `pyyaml`, `jsonschema`, pytest, ruff, mypy (strict). Windows-native host.

**Spec:** `docs/superpowers/specs/2026-10-01-s4-scoring-reporting-design.md` — read it before Task 1. Its §2 carries the factor-gap ruling, §10 the eight acceptance gates, §11 the seven decisions with cost-if-wrong.

## Global Constraints

Copied from the spec's §0.1. Every task's requirements implicitly include this section.

- **The structural freeze is absolute.** Six factors, their ranges, the 1–28 bounds and the four bands were fixed at the end of S1 before any scoring output existed. **Add no factor and move no boundary.** Any such change is reported as sensitivity analysis (PLAN Q10), never applied to the primary model.
- **`scored_level` is the only arithmetic input.** Never read `FactorValue.level` in a sum — it is `int | None`. S3b built `scored_level` so a scoring call site cannot forget the unresolved branch.
- **`severity_level` on `NormalizedFinding` is ALREADY normalized** by S3a. It is `int | str`, where the string is the explicit `unknown` state. Measured over the committed fixtures: 566 integers (values 2, 3, 4, 5) and 489 `'unknown'`, with **zero mismatches** against `rubric.normalize_severity(scanner, native_severity)`. **Do not re-normalize** — convert what is already there.
- **All four coherence rules are enforced**: `severity_context_fencing`, `encryption_sensitivity_orthogonality`, `iam_governed_resource_inheritance`, `unresolved_default_reporting`. The first two are provable only by mutation.
- **Explicit states survive into the output**: `unresolved`, `defaulted`, `unknown`, `unmapped:`, `low_confidence`, `factor_gap`, `baseline_only_informational`. A consumer must be able to tell a resolved 3 from an unresolved one.
- **JSON is the source of truth**; the human report renders from it, never the reverse.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — docstrings, comments, test names, test docstrings, commit messages. Measured facts carry their source.
- **Windows-native.** Always `uv run python`, never bare `python`. `uv run mypy` takes **no** path argument.
- **Judge pytest by exit code, never by grepping for `FAILED`.** Under `-q --strict-markers -rs` a failing test prints `F` and a traceback and emits no `FAILED` line.
- **A gate that only inspects hand-built fixtures is not enough.** A defect leaving 0 of 217 container identities unmatched survived seven gates and 746 tests in S3b because every test built its own fixture keyed the way the code expected. Gates that report a rate must measure it over the real corpus.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/iacrisk/data/factor_map.json` | The committed 28 × 6 class-to-factor table (data, not code) |
| `src/iacrisk/scoring/__init__.py` | Package marker; re-exports `ScoredFinding`, `score_all` |
| `src/iacrisk/scoring/factor_map.py` | Thin typed loader over the table, plus `is_factor_gap(class_id)` |
| `src/iacrisk/scoring/engine.py` | `ScoredFinding`, severity→`FactorValue` conversion, the sum, band, action, explanation |
| `src/iacrisk/scoring/baseline.py` | Severity level → baseline band, and the unknown-severity rate |
| `src/iacrisk/scoring/rank.py` | Ranking with ties preserved and a documented presentational sub-order |
| `src/iacrisk/scoring/report.py` | The four band distributions and the per-factor contribution summary |
| `src/iacrisk/scoring/emit.py` | JSON emission (the source of truth) and the human renderer |
| `tests/scoring/test_*.py` | One test module per source module |
| `tests/test_s4_gates.py` | The eight acceptance gates from spec §10 |

`tests/scoring/__init__.py` is **not** created — `tests/context/` and `tests/paircand/` have none and must not gain one.

---

### Task 1: The class-to-factor map

**Files:**
- Create: `src/iacrisk/data/factor_map.json`, `src/iacrisk/scoring/__init__.py`, `src/iacrisk/scoring/factor_map.py`
- Test: `tests/scoring/test_factor_map.py`

**Interfaces:**
- Consumes: `iacrisk.taxonomy` — `taxonomy.classes()` returns a mapping of 28 class ids to `IssueClass(id, category, title, definition)`; `iacrisk.rubric` — `rubric.factors()` keyed by the six factor keys.
- Produces: `bearing_factors(class_id) -> frozenset[str]`; `is_factor_gap(class_id) -> bool`; `table() -> Mapping[str, frozenset[str]]`; `GAP_CANDIDATE_FACTORS: frozenset[str]`.

**The decision rule for every cell, which is what makes this authoring reproducible rather than taste.** A factor *bears* on a class when the risk dimension the class names is one that factor measures.

- **`severity` bears on every class.** Every finding arrives from a rule that carries (or lacks) a severity; this is the context-free baseline.
- **`sensitivity` and `criticality` bear on every class.** They describe the *asset and environment*, not the risk mechanism, so they modulate any finding on that resource.
- **`exposure` bears only where the named risk is inbound network reachability.**
- **`privilege` bears only where the named risk is the breadth of granted IAM or RBAC permission.**
- **`encryption` bears only where the named risk is a missing data-protection control.**

**Therefore `factor_gap` is decided by the three parsed factors alone** — `exposure`, `privilege`, `encryption` — because the other three bear on everything and so can never distinguish a gap. `GAP_CANDIDATE_FACTORS` is exactly that set, and `is_factor_gap` is `bearing_factors(c) & GAP_CANDIDATE_FACTORS == frozenset()`.

Applying the rule to the five classes spec §1.4 measures, as a worked check the authored table must reproduce:

| Class | exposure | privilege | encryption | Gap? |
|---|---|---|---|---|
| `networking-egress-exposure` | no — exposure measures **inbound**; egress is outbound | no | no | **yes** |
| `containers-host-isolation-breakout` | no | no — privilege measures IAM/RBAC breadth, not kernel namespace isolation | no | **yes** |
| `iam-hardcoded-secrets` | no | no — the risk is credential *exposure*, not granted breadth | no — the secret is not an encryption control | **yes** |
| `compute-instance-metadata-hardening` | no | no — IMDSv1 enables credential *theft*; the factor measures granted breadth | no | **yes** |
| `containers-image-supply-chain` | no | no | no | **yes** |

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_factor_map.py
import pytest

from iacrisk import rubric, taxonomy
from iacrisk.scoring.factor_map import (
    GAP_CANDIDATE_FACTORS,
    bearing_factors,
    is_factor_gap,
    table,
)

GAP_CLASSES = {
    "networking-egress-exposure",
    "containers-host-isolation-breakout",
    "iam-hardcoded-secrets",
    "compute-instance-metadata-hardening",
    "containers-image-supply-chain",
}


def test_the_table_covers_every_taxonomy_class_with_no_unmapped_cell() -> None:
    """Gate 7's core. The S2 handoff records that no class-to-factor mapping existed
    anywhere in the data, which is why the gap set was never shown to be complete. A
    table missing a class leaves that class's gap status undecided rather than decided.
    """
    assert set(table()) == set(taxonomy.classes())
    assert len(table()) == 28


def test_every_named_factor_is_a_real_rubric_factor() -> None:
    valid = set(rubric.factors())
    for class_id, factors in table().items():
        assert factors <= valid, f"{class_id} names a factor the rubric does not define"


def test_the_three_always_bearing_factors_bear_on_every_class() -> None:
    """severity, sensitivity and criticality describe the rule, the asset and the
    environment rather than the risk mechanism, so they modulate any finding.
    """
    for class_id, factors in table().items():
        assert {"severity", "sensitivity", "criticality"} <= factors, class_id


def test_gap_candidates_are_exactly_the_three_parsed_factors() -> None:
    """The other three bear on everything, so they can never distinguish a gap."""
    assert GAP_CANDIDATE_FACTORS == frozenset({"exposure", "privilege", "encryption"})


def test_the_five_measured_gap_classes_are_gaps() -> None:
    for class_id in GAP_CLASSES:
        assert is_factor_gap(class_id), class_id
        assert not (bearing_factors(class_id) & GAP_CANDIDATE_FACTORS)


def test_no_other_class_is_a_gap() -> None:
    """Pins the gap set at exactly five. If a sixth is genuinely a gap, this test is
    where that is argued and recorded - not somewhere a reader has to infer it.
    """
    gaps = {c for c in taxonomy.classes() if is_factor_gap(c)}
    assert gaps == GAP_CLASSES


def test_an_unknown_class_is_a_hard_error_not_a_silent_gap() -> None:
    """An `unmapped:` class has no entry. Returning "gap" for it would conflate two
    different exclusions that PLAN Q7 and Q8 report separately.
    """
    with pytest.raises(KeyError):
        bearing_factors("unmapped:checkov:CKV_AWS_62")
    with pytest.raises(KeyError):
        is_factor_gap("not-a-class")


def test_an_exposure_bearing_class_names_exposure() -> None:
    """A spot check that the table is not uniformly 'no' on the parsed factors, which
    would make every class a gap and the marker meaningless.
    """
    assert "exposure" in bearing_factors("networking-ingress-exposure")
    assert "exposure" in bearing_factors("storage-public-accessibility")
    assert "encryption" in bearing_factors("storage-encryption-at-rest")
    assert "privilege" in bearing_factors("iam-overpermissive-policy")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/scoring/test_factor_map.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.scoring'`.

- [ ] **Step 3: List the 28 class ids and their definitions, so each cell is decided against the definition rather than the name**

Run:
```bash
uv run python -c "from iacrisk import taxonomy; [print(c.id, '|', c.category, '|', c.definition) for c in sorted(taxonomy.classes().values(), key=lambda x: x.id)]"
```

Decide each cell against the printed **definition**, not the class id. The S2 handoff's standing warning applies directly: *a class named for a factor is not evidence of that factor* — `iam-authentication-controls` and `networking-egress-exposure` both read as factor evidence and are not.

- [ ] **Step 4: Author `src/iacrisk/data/factor_map.json`**

Shape — one entry per class, `bears` listing the factor keys that bear, and a one-line `rationale` for the parsed-factor decisions so a reader can check the judgement:

```json
{
  "schema_version": 1,
  "rule": "A factor bears on a class when the risk dimension the class names is one that factor measures. severity, sensitivity and criticality bear on every class (rule baseline, asset, environment). exposure bears only on inbound network reachability; privilege only on granted IAM/RBAC breadth; encryption only on a missing data-protection control. factor_gap is decided by those three alone.",
  "gap_candidate_factors": ["exposure", "privilege", "encryption"],
  "classes": {
    "networking-egress-exposure": {
      "bears": ["severity", "sensitivity", "criticality"],
      "rationale": "Exposure measures inbound reachability; egress is the opposite direction and the taxonomy itself calls it a distinct property. No parsed factor captures exfiltration."
    }
  }
}
```

- [ ] **Step 5: Write the loader**

```python
# src/iacrisk/scoring/factor_map.py
"""The committed class-to-factor table, and the factor-gap marker derived from it.

Spec §2.2. This artifact did not exist before S4: the S2 handoff records that "no
class-to-factor mapping exists anywhere in the data", which is why single-factor purity
remained an authored judgement and the factor-gap set was never established as complete.
The table makes the 28 x 6 sweep a committed artifact, and `is_factor_gap` derives the
marker from it rather than from a hand-maintained list of class names that a taxonomy
change could leave stale.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType

__all__ = ["GAP_CANDIDATE_FACTORS", "bearing_factors", "is_factor_gap", "rule", "table"]

_PATH = Path(__file__).resolve().parent.parent / "data" / "factor_map.json"

GAP_CANDIDATE_FACTORS = frozenset({"exposure", "privilege", "encryption"})


@lru_cache(maxsize=1)
def _document() -> Mapping[str, object]:
    return MappingProxyType(json.loads(_PATH.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def table() -> Mapping[str, frozenset[str]]:
    classes = _document()["classes"]
    assert isinstance(classes, dict)
    return MappingProxyType(
        {class_id: frozenset(entry["bears"]) for class_id, entry in classes.items()}
    )


def bearing_factors(class_id: str) -> frozenset[str]:
    """The factors that bear on this class. KeyError for a class not in the table.

    An `unmapped:<scanner>:<rule_id>` class has no entry by design. Raising rather than
    returning an empty set keeps two different exclusions distinct: PLAN Q7 excludes
    `unmapped:` findings from prioritization-quality claims, while spec §2.3 deliberately
    does NOT exclude factor-gap findings.
    """
    return table()[class_id]


def is_factor_gap(class_id: str) -> bool:
    """True when no parsed factor bears on the risk this class names."""
    return not (bearing_factors(class_id) & GAP_CANDIDATE_FACTORS)


def rule() -> str:
    """The authoring rule, carried as data so the table and its rule cannot drift."""
    value = _document()["rule"]
    assert isinstance(value, str)
    return value
```

```python
# src/iacrisk/scoring/__init__.py
"""Layers 4 and 5 - risk scoring, banding, ranking and reporting (S4)."""
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/scoring/test_factor_map.py`
Expected: 8 passed. If `test_no_other_class_is_a_gap` fails, a sixth class was authored as a gap — do not edit the test to match. Decide whether the authoring or the expectation is right, and if a sixth class genuinely is a gap, add it to `GAP_CLASSES` **and** to spec §1.4's table, and say so in the report.

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/data/factor_map.json src/iacrisk/scoring tests/scoring/test_factor_map.py
git commit -m "feat(s4): the committed 28x6 class-to-factor table and its loader"
```

---

### Task 2: The scoring engine

**Files:**
- Create: `src/iacrisk/scoring/engine.py`
- Modify: `src/iacrisk/scoring/__init__.py` (re-export `ScoredFinding`, `score`, `score_all`)
- Test: `tests/scoring/test_engine.py`

**Interfaces:**
- Consumes: `iacrisk.context.extract.ContextualizedFinding` with fields `finding`, `exposure`, `privilege`, `sensitivity`, `criticality`, `encryption` (each `FactorValue | None`), properties `factors`, `defaulted_factors`, `unresolved_factors`, `low_confidence`; `iacrisk.context.value.FactorValue` with `key`, `level`, `state`, `evidence`, `scored_level`; `rubric.band_for(score) -> str`; `rubric.bands() -> tuple[Band, ...]` with `.name`/`.action`; `rubric.score_bounds() -> (1, 28)`; `factor_map.is_factor_gap`.
- Produces: `FACTOR_ORDER: tuple[str, ...]`; `severity_factor(finding) -> FactorValue`; `ScoredFinding` frozen dataclass; `score(contextualized) -> ScoredFinding`; `score_all(iterable) -> list[ScoredFinding]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_engine.py
import pytest

from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorState, FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.engine import FACTOR_ORDER, score, severity_factor


def _finding(
    severity: int | str = 3,
    *,
    issue_class: str = "storage-encryption-at-rest",
    eligible: bool = True,
) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1", issue_class=issue_class,
        title="t", remediation=None, native_severity=None, severity_level=severity,
        platform="terraform", resource_identity="aws_s3_bucket.b", identity_kind="terraform",
        file_path="x.tf", line_range=None, fingerprint=None, context_eligible=eligible,
    )


def _ctx(finding: NormalizedFinding, **levels: int | None) -> ContextualizedFinding:
    def fv(key: str) -> FactorValue | None:
        if key not in levels:
            return None
        value = levels[key]
        if value is None:
            return FactorValue.unresolved(key, f"{key} unresolved in test")
        return FactorValue.resolved(key, value, f"{key}={value} in test")

    return ContextualizedFinding(
        finding=finding,
        exposure=fv("exposure"),
        privilege=fv("privilege"),
        sensitivity=fv("sensitivity"),
        criticality=fv("criticality"),
        encryption=fv("encryption"),
    )


def test_the_factor_order_is_the_rubrics_formula_order() -> None:
    assert FACTOR_ORDER == (
        "severity", "exposure", "privilege", "sensitivity", "criticality", "encryption",
    )


def test_an_integer_severity_becomes_a_resolved_factor_value() -> None:
    value = severity_factor(_finding(5))
    assert (value.state, value.level, value.scored_level) == (FactorState.RESOLVED, 5, 5)


def test_an_unknown_severity_becomes_an_unresolved_factor_value_scoring_four() -> None:
    """severity_level is ALREADY normalized by S3a and is `int | str`, the trap both the
    S1 and S3a handoffs record. Converting once at this boundary is what stops a string
    reaching six call sites.
    """
    value = severity_factor(_finding("unknown"))
    assert value.state is FactorState.UNRESOLVED
    assert value.level is None
    assert value.scored_level == 4


def test_the_score_is_the_sum_of_six_contributions() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert scored.contributions == {
        "severity": 3, "exposure": 4, "privilege": 2,
        "sensitivity": 5, "criticality": 4, "encryption": 1,
    }
    assert scored.score == 19
    assert sum(scored.contributions.values()) == scored.score


def test_the_band_and_action_come_from_the_rubric() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert scored.band == "High"
    assert scored.action == "Fix before production / require approval"


def test_an_all_unresolved_finding_still_scores_and_lands_in_high() -> None:
    """Spec §1.1's washout, asserted rather than described: the five context defaults sum
    to 16 and unknown severity resolves to 4, so this lands on exactly 20.
    """
    scored = score(
        _ctx(
            _finding("unknown"),
            exposure=None, privilege=None, sensitivity=None,
            criticality=None, encryption=None,
        )
    )
    assert scored.score == 20
    assert scored.band == "High"


def test_the_minimum_and_maximum_attainable_scores_are_the_frozen_bounds() -> None:
    low = score(
        _ctx(_finding(1), exposure=0, privilege=0, sensitivity=0, criticality=0, encryption=0)
    )
    high = score(
        _ctx(_finding(5), exposure=5, privilege=5, sensitivity=5, criticality=5, encryption=3)
    )
    assert (low.score, low.band) == (1, "Low")
    assert (high.score, high.band) == (28, "Critical")


def test_every_scored_finding_carries_one_explanation_line_per_factor() -> None:
    scored = score(
        _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    )
    assert len(scored.explanation) == 6
    for key in FACTOR_ORDER:
        assert any(line.startswith(key) for line in scored.explanation), key
    assert all(line.strip() for line in scored.explanation)


def test_an_unresolved_factor_says_so_in_its_explanation_line() -> None:
    scored = score(_ctx(_finding(3), exposure=None, privilege=2, sensitivity=5, criticality=4, encryption=1))
    exposure_line = next(line for line in scored.explanation if line.startswith("exposure"))
    assert "unresolved" in exposure_line
    assert "3" in exposure_line  # the default it scored


def test_a_context_ineligible_finding_scores_on_severity_alone() -> None:
    """Spec §3.3. Defaulting its five factors would re-open the washout that
    `context_eligible` exists to close.
    """
    scored = score(_ctx(_finding(4, eligible=False)))
    assert scored.contributions == {"severity": 4}
    assert scored.score == 4
    assert scored.band == "Low"
    assert scored.baseline_only_informational is True


def test_the_factor_gap_marker_is_derived_from_the_table() -> None:
    gap = score(_ctx(_finding(3, issue_class="containers-image-supply-chain"),
                     exposure=1, privilege=1, sensitivity=1, criticality=1, encryption=1))
    not_gap = score(_ctx(_finding(3, issue_class="storage-encryption-at-rest"),
                         exposure=1, privilege=1, sensitivity=1, criticality=1, encryption=1))
    assert gap.factor_gap is True
    assert not_gap.factor_gap is False


def test_an_unmapped_class_is_not_marked_a_factor_gap() -> None:
    """Two different exclusions: PLAN Q7 excludes `unmapped:` from quality claims, while
    spec §2.3 deliberately does not exclude factor-gap findings. Conflating them would
    make one of the two reports impossible.
    """
    scored = score(_ctx(_finding(3, issue_class="unmapped:checkov:CKV_AWS_62"),
                        exposure=1, privilege=1, sensitivity=1, criticality=1, encryption=1))
    assert scored.factor_gap is False
    assert scored.unmapped is True


def test_a_weight_map_other_than_all_ones_is_rejected_by_default() -> None:
    """Spec §4.4: weights exist so S5's sensitivity analysis need not fork the engine, and
    the frozen primary model must not silently become weighted.
    """
    ctx = _ctx(_finding(3), exposure=4, privilege=2, sensitivity=5, criticality=4, encryption=1)
    weighted = score(ctx, weights={"exposure": 2})
    assert weighted.score != 19
    assert weighted.weighted is True
    assert score(ctx).weighted is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/scoring/test_engine.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.scoring.engine'`.

- [ ] **Step 3: Write the implementation**

`ScoredFinding` is a frozen dataclass with `contextualized`, `severity: FactorValue`, `contributions: Mapping[str, int]`, `score: int`, `band: str`, `action: str`, `factor_gap: bool`, `unmapped: bool`, `baseline_only_informational: bool`, `weighted: bool`, `explanation: tuple[str, ...]`, plus `low_confidence` delegating to the contextualized finding.

`severity_factor` reads `finding.severity_level` — already normalized — and returns
`FactorValue.resolved("severity", level, ...)` for an int, or
`FactorValue.unresolved("severity", ...)` for the `'unknown'` string. It must **not** call
`rubric.normalize_severity`; re-normalizing would read a field S3a already consumed.

`score(contextualized, weights=None)` builds contributions in `FACTOR_ORDER`, using
`scored_level` for every addend, multiplies by the weight (default 1), sums, asserts the
total is within `rubric.score_bounds()`, and derives band and action from `rubric`. For a
context-ineligible finding — identified by `contextualized.factors == ()` — only severity
contributes. `factor_gap` calls `factor_map.is_factor_gap` inside a `try/except KeyError`
returning False, since an `unmapped:` class has no entry and is tracked by `unmapped`
instead.

Each explanation line reads `"<key>: <level-or-default> (<state>) — <evidence>"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/scoring/test_engine.py`
Expected: 14 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/scoring tests/scoring/test_engine.py
git commit -m "feat(s4): the scoring engine, with severity converted at the boundary"
```

---

### Task 3: The severity-normalized baseline

**Files:**
- Create: `src/iacrisk/scoring/baseline.py`
- Test: `tests/scoring/test_baseline.py`

**Interfaces:**
- Consumes: `NormalizedFinding.severity_level` (`int | str`); `rubric.severity_normalization()` for `unknown_resolves_to`.
- Produces: `SEVERITY_BAND_MAP: Mapping[int, str]`; `baseline_band(finding) -> str`; `BaselineCoverage` frozen dataclass with `total`, `from_unknown`, `per_band`; `baseline_coverage(findings) -> BaselineCoverage`.

**Requirements** (spec §6). The baseline is **a band assignment, not a score** — a 1–5 severity cannot be banded against a 1–28 ceiling, and scaling it there would invent precision the scanner never supplied. The committed map is `5 → Critical`, `4 → High`, `3 → Medium`, `2 → Low`, `1 → Low`. An `'unknown'` severity bands through the rubric's `unknown_resolves_to` of 4, i.e. High, and **the rate must be reported with every baseline figure**, because 489 of 1,055 corpus findings reach the baseline that way.

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_baseline.py
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.baseline import SEVERITY_BAND_MAP, baseline_band, baseline_coverage


def _finding(severity: int | str) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1",
        issue_class="storage-encryption-at-rest", title="t", remediation=None,
        native_severity=None, severity_level=severity, platform="terraform",
        resource_identity="aws_s3_bucket.b", identity_kind="terraform", file_path="x.tf",
        line_range=None, fingerprint=None, context_eligible=True,
    )


def test_the_map_covers_every_level_the_rubric_defines() -> None:
    assert SEVERITY_BAND_MAP == {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Low"}


def test_each_severity_bands_as_the_committed_map_says() -> None:
    assert baseline_band(_finding(5)) == "Critical"
    assert baseline_band(_finding(4)) == "High"
    assert baseline_band(_finding(3)) == "Medium"
    assert baseline_band(_finding(2)) == "Low"
    assert baseline_band(_finding(1)) == "Low"


def test_an_unknown_severity_bands_through_the_rubrics_unknown_resolution() -> None:
    """unknown_resolves_to is 4, so High - and the rate is reported separately because
    489 of 1055 corpus findings reach the baseline this way.
    """
    assert baseline_band(_finding("unknown")) == "High"


def test_coverage_reports_the_unknown_rate_separately_from_the_bands() -> None:
    coverage = baseline_coverage([_finding(5), _finding("unknown"), _finding("unknown")])
    assert coverage.total == 3
    assert coverage.from_unknown == 2
    assert coverage.per_band["Critical"] == 1
    assert coverage.per_band["High"] == 2


def test_every_band_key_is_present_even_at_zero() -> None:
    """An absent band is indistinguishable from an unmeasured one."""
    coverage = baseline_coverage([_finding(5)])
    assert set(coverage.per_band) == {"Critical", "High", "Medium", "Low"}
```

- [ ] **Step 2: Run it, confirm it fails, implement, re-run**

Run: `uv run pytest tests/scoring/test_baseline.py`
Expected first: `ModuleNotFoundError`. After implementing: 5 passed.

- [ ] **Step 3: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/scoring/baseline.py tests/scoring/test_baseline.py
git commit -m "feat(s4): severity-normalized baseline as a band assignment"
```

---

### Task 4: Ranking with ties preserved

**Files:**
- Create: `src/iacrisk/scoring/rank.py`
- Test: `tests/scoring/test_rank.py`

**Interfaces:**
- Consumes: `ScoredFinding` (Task 2).
- Produces: `RankedFinding` frozen dataclass with `scored` and `rank: int`; `rank_all(scored) -> list[RankedFinding]`.

**Requirements** (spec §5). Descending score. **Equal scores share a rank** — `corpus-v1`'s containers scenario contains a deliberate tie, and an arbitrary tiebreak would make the framework appear to discriminate where it does not. Ranks are competition-style: after three findings sharing rank 1, the next is rank 4. The sub-order *within* a tie is canonical identity, then issue class, then scanner, and is **presentational only** — it never changes a rank number.

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_rank.py
from iacrisk.scoring.rank import rank_all


def test_equal_scores_share_a_rank_and_the_next_rank_skips() -> None:
    """Competition ranking. corpus-v1's containers scenario contains a deliberate tie, so
    collapsing ties into distinct ranks would misreport the framework as discriminating.
    """
    ranked = rank_all(_scored_with_scores([20, 20, 20, 15]))
    assert [r.rank for r in ranked] == [1, 1, 1, 4]


def test_findings_sort_by_descending_score() -> None:
    ranked = rank_all(_scored_with_scores([5, 25, 15]))
    assert [r.scored.score for r in ranked] == [25, 15, 5]


def test_the_sub_order_within_a_tie_is_stable_and_does_not_change_ranks() -> None:
    a = _scored(score=20, identity="aws_s3_bucket.z")
    b = _scored(score=20, identity="aws_s3_bucket.a")
    ranked = rank_all([a, b])
    assert [r.scored.contextualized.finding.resource_identity for r in ranked] == [
        "aws_s3_bucket.a", "aws_s3_bucket.z",
    ]
    assert [r.rank for r in ranked] == [1, 1]


def test_an_empty_input_ranks_to_an_empty_list() -> None:
    assert rank_all([]) == []
```

Build `_scored` and `_scored_with_scores` helpers in the test module from Task 2's `score()`
over constructed contextualized findings, choosing factor levels that sum to the target
score. Do **not** construct `ScoredFinding` directly — going through `score()` keeps the
ranking tests honest about what the engine actually produces.

- [ ] **Step 2: Run it, confirm it fails, implement, re-run**

Expected after implementing: 4 passed.

- [ ] **Step 3: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/scoring/rank.py tests/scoring/test_rank.py
git commit -m "feat(s4): ranking with ties preserved as ties"
```

---

### Task 5: The band distributions and the per-factor contribution summary

**Files:**
- Create: `src/iacrisk/scoring/report.py`
- Test: `tests/scoring/test_report.py`

**Interfaces:**
- Consumes: `ScoredFinding` (Task 2), `baseline_band` (Task 3).
- Produces: `PriorityReport` frozen dataclass with `overall: dict[str, int]`, `by_defaulted_count: dict[int, dict[str, int]]`, `excluding_factor_gap: dict[str, int]`, `including_factor_gap: dict[str, int]`, `framework_vs_baseline: dict[tuple[str, str], int]`, `per_factor: dict[str, FactorContribution]`, `low_confidence_count: int`, `factor_gap_count: int`; `build(scored) -> PriorityReport`; `to_json(report) -> dict[str, object]`.

**Requirements** (spec §7.2, §7.3). Four distributions, **none combined**: overall; split by
count-of-defaulted-or-unresolved factors 0–5; with and without factor-gap findings; and a
framework-band × baseline-band contingency table of **counts only** — any claim about which
ranking is *better* is S5's. All four band keys always present even at zero, and all six
defaulted-count keys always present, because an absent key is indistinguishable from an
unmeasured one.

`FactorContribution` carries `resolved: int`, `defaulted_or_unresolved: int`, and
`distribution: dict[int, int]`. This is what makes spec §1.2 visible — a factor contributing
a flat 3 to 91% of findings shows up as a near-constant column, so a reader can see which
factors do the ranking work.

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_report.py
import json

from iacrisk.scoring.report import build, to_json

BANDS = {"Critical", "High", "Medium", "Low"}


def test_all_four_band_keys_are_present_even_at_zero() -> None:
    report = build(_scored_with_scores([20]))
    assert set(report.overall) == BANDS
    assert report.overall["High"] == 1
    assert report.overall["Low"] == 0


def test_all_six_defaulted_count_keys_are_present() -> None:
    report = build(_scored_with_scores([20]))
    assert sorted(report.by_defaulted_count) == [0, 1, 2, 3, 4, 5]


def test_the_gap_distributions_are_reported_as_a_pair() -> None:
    """Spec §2.2: whether excluding gap findings changes a conclusion must be measurable,
    which needs both halves. Gate 6 asserts both are emitted.
    """
    report = build(_mixed_gap_and_non_gap())
    assert report.including_factor_gap != {} and report.excluding_factor_gap != {}
    assert sum(report.including_factor_gap.values()) > sum(report.excluding_factor_gap.values())
    assert report.factor_gap_count > 0


def test_the_contingency_table_is_counts_only() -> None:
    report = build(_scored_with_scores([20, 20]))
    assert all(isinstance(v, int) for v in report.framework_vs_baseline.values())
    assert sum(report.framework_vs_baseline.values()) == 2


def test_per_factor_contribution_shows_a_near_constant_column() -> None:
    """Spec §1.2 made visible: a factor that is unresolved on almost everything
    contributes a flat default, which this column is what exposes.
    """
    report = build(_many_with_unresolved_exposure(10))
    exposure = report.per_factor["exposure"]
    assert exposure.defaulted_or_unresolved == 10
    assert exposure.resolved == 0
    assert exposure.distribution == {3: 10}


def test_to_json_is_serialisable_with_string_keys() -> None:
    payload = to_json(build(_scored_with_scores([20])))
    json.dumps(payload)
    assert sorted(payload["by_defaulted_count"]) == ["0", "1", "2", "3", "4", "5"]
```

Build the helpers from Task 2's `score()` as in Task 4.

- [ ] **Step 2: Run it, confirm it fails, implement, re-run**

Expected after implementing: 6 passed.

- [ ] **Step 3: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/scoring/report.py tests/scoring/test_report.py
git commit -m "feat(s4): four band distributions and the per-factor contribution summary"
```

---

### Task 6: JSON emission and the human report

**Files:**
- Create: `src/iacrisk/scoring/emit.py`
- Test: `tests/scoring/test_emit.py`

**Interfaces:**
- Consumes: `RankedFinding` (Task 4), `PriorityReport` (Task 5), `baseline_band` (Task 3).
- Produces: `to_json(ranked, report) -> dict[str, object]`; `render_markdown(payload) -> str`.

**Requirements** (spec §7.1, §7.4). The JSON is the source of truth and carries per finding:
identity, class, scanner, rank, the six contributions, score, band, action, the explanation
lines, the baseline band, and every explicit-state flag. **`render_markdown` takes the JSON
payload, not the dataclasses** — that is what makes the human report a view rather than a
second source, and a test asserts the renderer's signature accepts only the payload.

- [ ] **Step 1: Write the failing test**

```python
# tests/scoring/test_emit.py
import json

from iacrisk.scoring.emit import render_markdown, to_json


def test_the_payload_round_trips_through_json() -> None:
    payload = to_json(*_ranked_and_report())
    json.dumps(payload)


def test_every_finding_carries_its_states_and_decomposition() -> None:
    payload = to_json(*_ranked_and_report())
    entry = payload["findings"][0]
    for key in (
        "rank", "resource_identity", "issue_class", "scanner", "score", "band", "action",
        "contributions", "explanation", "baseline_band", "low_confidence", "factor_gap",
        "unmapped", "baseline_only_informational",
    ):
        assert key in entry, key
    assert len(entry["contributions"]) in (1, 6)
    assert len(entry["explanation"]) == len(entry["contributions"])


def test_per_factor_state_survives_into_the_payload() -> None:
    """A consumer must be able to tell a resolved 3 from an unresolved one, because S5's
    reports depend on the difference.
    """
    payload = to_json(*_ranked_with_unresolved_exposure())
    states = payload["findings"][0]["factor_states"]
    assert states["exposure"] == "unresolved"


def test_the_renderer_reads_the_payload_and_nothing_else() -> None:
    """The human report is a view, never a second source. Passing it the payload is what
    guarantees it cannot disagree with the JSON.
    """
    payload = to_json(*_ranked_and_report())
    text = render_markdown(payload)
    assert "Critical" in text or "High" in text
    assert str(payload["findings"][0]["score"]) in text


def test_the_renderer_groups_critical_first() -> None:
    text = render_markdown(to_json(*_ranked_mixed_bands()))
    assert text.index("## Critical") < text.index("## High") < text.index("## Medium")
```

- [ ] **Step 2: Run it, confirm it fails, implement, re-run**

Expected after implementing: 5 passed.

- [ ] **Step 3: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest
git add src/iacrisk/scoring/emit.py tests/scoring/test_emit.py
git commit -m "feat(s4): JSON as the source of truth and the human report as a view"
```

---

### Task 7: The eight acceptance gates

**Files:**
- Create: `tests/test_s4_gates.py`
- Test: itself

**Interfaces:**
- Consumes: every prior task, plus `tests/_corpus.py` (`all_real_findings`, `TERRAFORM_SCAN_ROOT`, `KUBERNETES_SCAN_ROOT`) and `eval/ground_truth/corpus-v1.json` for declared context.

Implement spec §10's eight gates. Follow `tests/test_s3b_gates.py` for structure, including
its `_probe` helper pattern and its practice of building the real corpus once per gate.

- [ ] **Step 1: Write the gates**

Gates 1, 2, 3, 5, 6 and 8 are direct assertions over the real corpus. Two need care:

**Gate 4 is two mutations, not one.** Fencing: substituting `issue_class` within *and across*
categories must change no contribution — S3b's gate 5 proves it at layer 3, and S4 re-proves
it on the sum because a scoring layer could reintroduce the dependency. Orthogonality: varying
declared `sensitivity` must change the sensitivity contribution and **nothing else**, and
varying an encryption attribute must change only encryption. Reuse S3b's
`_other_class_in_same_category` and `_any_other_class` shape, and assert the substitution is
real — a helper that silently returns the same class makes the gate vacuous, which this
project has hit before.

**Gate 7 measures over the real corpus and reports.** Assert the table covers 28 × 6 with no
unmapped cell and that `factor_gap` is derived, then compute the gap population over the real
corpus and assert it is **reported** — the count, and both halves of the with/without band
distribution. Print the measured figures so the commit message can carry them.

- [ ] **Step 2: Run the gates**

Run: `uv run pytest tests/test_s4_gates.py`
Expected: 8 passed.

- [ ] **Step 3: Run every gate command**

```bash
uv run pytest                     # judge by EXIT CODE, not by grepping for FAILED
uv run ruff check .
uv run ruff format --check .      # must report 0 files to reformat
uv run mypy                       # BARE, no path arguments
```

- [ ] **Step 4: Measure and record the band distribution**

Run the scoring pipeline over the committed fixtures with `corpus-v1`'s declared context and
record in the commit message: the overall band distribution, the distribution split by
defaulted count, both halves of the factor-gap pair, the framework-vs-baseline contingency
table, and the per-factor contribution summary.

**State plainly whether the distribution is degenerate.** Spec §1.1 predicts that an
all-defaulted finding lands in High, and §1.3 measures 77.9% of corpus-v0 findings as
low-confidence — so a High-dominated distribution over v0 is the expected outcome, not a
surprise, and the declared-path distribution is the one that bears on the framework's claim.
If the bands collapse into one, say so rather than reporting the gates as simply green.

- [ ] **Step 5: Commit**

```bash
git add tests/test_s4_gates.py
git commit -m "test(s4): the eight acceptance gates, with fencing and orthogonality by mutation"
```

---

## Self-Review

**Spec coverage.** §2.2's factor map → Task 1; §2.3's non-exclusion → Task 2's
`test_an_unmapped_class_is_not_marked_a_factor_gap`; §3's record and §3.1's boundary
conversion → Task 2; §3.2's explanation → Task 2 and gate 3; §3.3's ineligible handling →
Task 2 and gate 5; §4.1–§4.2 → Task 2; §4.3's four rules → gate 4 (two by mutation) and
Task 5 (`unresolved_default_reporting` is a reporting obligation, so Task 5's
`by_defaulted_count` *is* its enforcement); §4.4's weights → Task 2 and gate 8; §5 → Task 4;
§6 → Task 3; §7.1–§7.4 → Tasks 5 and 6; §10's eight gates → Task 7. §0.1's constraints are
copied into Global Constraints.

**Placeholder scan.** Tasks 1 and 2 carry full implementations or the exact decision rule for
every cell; Tasks 3–6 give exact signatures, exact expected values and the requirements that
fix the remaining choices. Every expected value in every test is a literal. No step says
"similar to Task N".

**Type consistency.** `ScoredFinding` is produced only by `score()` in Tasks 2, 4, 5, 6 and 7
— the ranking and report tests build through `score()` rather than constructing it, which is
stated explicitly in Tasks 4 and 5. `FACTOR_ORDER` is the single source of factor order in
Tasks 2, 5 and 6. `baseline_band(finding)` takes a `NormalizedFinding` in Tasks 3, 5 and 6.
`to_json` appears in three modules with different signatures (`factor_map` has none,
`report.to_json(report)`, `emit.to_json(ranked, report)`) — they are in different modules and
are never imported together unqualified.

**Four interface facts verified against the tree before this plan was committed**, so no task
has to discover them: `severity_level` is **already normalized** (`int | str`, 566 ints over
values 2–5 and 489 `'unknown'`, zero mismatches against `normalize_severity`);
`rubric.band_for` exists, maps 1–8/9–15/16–21/22–28 and **raises** outside 1–28;
`rubric.bands()` returns `Band(name, minimum, maximum, action)` so the action comes from the
artifact; and `rubric.coherence_rules()` has **four** entries, not the three the earlier
handoffs mention — `encryption_sensitivity_orthogonality` is the fourth and gate 4 covers it.

**One thing this plan deliberately does not do.** It does not assert a target band
distribution. The measured distribution is a finding to report, not a threshold to pass, and
pinning one would convert an empirical result into a test that must be kept green — the same
reasoning that left S3b's gate 6 without a resolution-rate floor.
