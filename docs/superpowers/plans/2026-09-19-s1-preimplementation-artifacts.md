# S1 — Pre-Implementation Specification Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Author the five version-controlled S1 specification artifacts — issue-class taxonomy + scanner-rule-ID mapping, six-factor scoring rubric, scanner severity-normalization table, evaluation ground-truth schema + validator, and the canonical-identity module — each with a loader thin enough to test and an acceptance gate copied from the spec.

**Architecture:** Every artifact is **data, not code** (mirroring how S0 treats the platform matrix in `scanners.lock.json`). Two JSON data files live inside the runtime package at `src/iacrisk/data/`, each fronted by a thin typed loader in `src/iacrisk/`. The evaluation schema and its validator live under `eval/` so the harness never shares code with what it grades. The canonical-identity module is pure string formatting with an explicit `<unresolved>` sentinel — no I/O, no scanner coupling. The two bulk data files are produced once by throwaway generator scripts in `scratch/` that read the frozen S1 design output; the **committed JSON is the source of truth**, and the test suites pin its invariants against the committed `artifacts/rule-inventory.json` rather than against the generator.

**Tech Stack:** Python 3.12 (pinned by `.python-version`), uv, `jsonschema>=4.23.0`, pytest, ruff, mypy (strict). Windows-native host.

**Spec:** `docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md`

## Global Constraints

Copied verbatim from spec §0 "Global constraints"; every task's requirements implicitly include this section.

- **Explicit-state discipline.** `unresolved`, `unattributed`, `unmapped:`, `unknown`, `None` are first-class states in the record and output JSON. None is ever silently defaulted to low/safe (PLAN Q9).
- **Frozen model.** Risk = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk. Ranges: Severity 1–5, Exposure/Privilege/Sensitivity/Criticality 0–5, EncryptionRisk 0–3. Max 28, min 1. Bands: Critical ≥22, High 16–21, Medium 9–15, Low <9. Ranges and bands **freeze at the end of S1**, before any scoring output is generated; later movement is reported as sensitivity analysis (Q10), never tuned to fit.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — applies to docstrings, comments, test names, briefs, ledger, commit messages, and this spec.
- **Windows-native host.** Always `uv run python`. Path normalization is by explicit character replacement (see §5).
- **Corpus v0 is a corpus observation, not a scanner contract.** Facts measured on this host (four severity levels, 46.4% null severity) describe corpus v0, not the scanners' capabilities.

Operational constraints that bind every task in this repo:

- **No pipeline code in S1.** These are specification artifacts plus the thin loaders needed to test them. Scoring, context extraction and scanner adapters are S3.
- **Always `uv run python`** — never bare `python` (it resolves to a broken Microsoft Store stub when the venv is off PATH).
- **`uv run mypy` takes no path argument.** A path overrides `[tool.mypy] files` and silently drops the test files. Bare is the only form that cannot drift.
- **Write JSON with LF endings and no BOM:** `path.write_text(text, encoding="utf-8", newline="\n")`. `tests/test_architecture.py::test_no_crlf_in_the_index` fails on a CRLF blob.
- **Ruff:** line-length 100, rules `E,F,I,N,UP,B,SIM,PTH,RUF`. `PTH` means `pathlib`, never `os.path`. **Mypy:** `strict = true` over `src`, `tools`, `eval`, `tests` — every function annotated, tests included (`-> None`).
- **Never** re-download or clear `tools/cache/`, `tools/bin/`, `corpus/vendor/`, `tests/harvest/fixtures/`, `tools/resolved.json`, `artifacts/scanner-behavior.json`; never run `tools\bootstrap.ps1`; never recompute a pinned digest/version/vendored SHA from disk.
- **Precondition (Tasks 1–2):** `scratch/s1_final.json` must exist — it is the frozen brainstorming output (28 classes with definitions, 255 rule assignments, 6 rubric factors). If absent, regenerate with `uv run python scratch/finalize_taxonomy.py`, which rebuilds it from `scratch/s1_design_input.json`. It is git-ignored scratch and is **not** committed; only its transformed output is.

## File Structure

| Path | Responsibility | Task |
|---|---|---|
| `src/iacrisk/data/taxonomy.json` | 28 classes + 255 `(scanner, rule_id)` mapping rows + the `unmapped:` fallback contract | 1 |
| `src/iacrisk/taxonomy.py` | Typed loader: `classes()`, `mapping()`, `class_for()`, `canonical_rule_id()`, `is_unmapped()` | 1 |
| `src/iacrisk/data/rubric.json` | Frozen model + bands + 6 source-anchored factors (Task 2), then the severity-normalization table (Task 3) | 2, 3 |
| `src/iacrisk/rubric.py` | Typed loader: `factors()`, `bands()`, `band_for()`, `unresolved_default()` (Task 2); `normalize_severity()` (Task 3) | 2, 3 |
| `eval/ground_truth.schema.json` | JSON Schema for the three ground-truth record types | 4 |
| `eval/ground_truth.py` | Schema + cross-record validator; hard-rejects, never skips | 4 |
| `eval/ground_truth/example.json` | Schema exemplar exercising all three record types | 4 |
| `src/iacrisk/identity.py` | Canonical identity: TF, K8s, path normalization, dedupe key | 5 |
| `tests/test_taxonomy.py` | Taxonomy gate + `unmapped:` fallback + twin co-location | 1 |
| `tests/test_rubric.py` | Six factors, anchors, frozen bands, unresolved defaults | 2 |
| `tests/test_severity_normalization.py` | Token scale + `unknown` routing + Q9 never-low guard | 3 |
| `tests/test_ground_truth.py` | Schema accept/reject + cross-record semantics | 4 |
| `tests/test_identity.py` | Every corpus resource shape + path normalization + dedupe | 5 |
| `tests/test_s1_gates.py` | The five acceptance gates and the end-of-S1 freeze, as tests | 6 |
| `scratch/build_taxonomy.py`, `scratch/build_rubric.py` | Throwaway one-shot generators (git-ignored, not committed) | 1, 2 |

**Why loaders at all**, when the spec says "data, not code": the spec mandates behaviours that only a function can carry — the `unmapped:` fallback (§2.4: "A test feeds a synthetic unknown rule ID and asserts it lands in `unmapped:`"), the `unknown` severity routing (§3.3), and the identity formatting rules (§5). Each loader is the minimum surface those tests need, and nothing more.

**Deferred to later sub-projects, deliberately.** Three spec items need a scoring engine that S1 does not build, so they are **not** in this plan: the §3.5.1 assertion that no privilege-5 resource-attached finding is capped below High; the §3.5.3 empirical contrastive-pair proof and severity-vs-context correlation number; and the §2.4 runtime behaviour that scores an `unmapped:` finding severity-only. S1 ships the *contract* for each (the fallback block in `taxonomy.json`, the inheritance rule in the rubric's `coherence_rules`, the factor definitions); S3/S4 ship the enforcement. Task 6 records this split so the gate report does not claim more than the artifacts support (§G3).

---

## Task 1: Issue-class taxonomy + 255-row scanner-rule-ID mapping

Implements spec §1 and §2. Produces the cross-cutting single source of truth that §3 (rubric class-anchoring), §4 (test design) and §5.4 (dedupe) all rest on.

**Files:**
- Create: `scratch/build_taxonomy.py` (throwaway generator — run once, do not commit)
- Create: `src/iacrisk/data/taxonomy.json` (generated, committed)
- Create: `src/iacrisk/taxonomy.py`
- Test: `tests/test_taxonomy.py`

**Interfaces:**
- Consumes: `scratch/s1_final.json` (frozen design output), `artifacts/rule-inventory.json` (S0, authoritative `(scanner, rule_id)` universe).
- Produces, relied on by Tasks 4 and 6:
  - `CATEGORIES: tuple[str, ...]` = `("storage", "networking", "iam", "compute", "containers")`
  - `IssueClass` frozen dataclass: `id: str`, `category: str`, `title: str`, `definition: str`
  - `MappingRow` frozen dataclass: `scanner: str`, `rule_id: str`, `canonical_id: str`, `class_id: str`, `title: str`
  - `classes() -> dict[str, IssueClass]` keyed by class id
  - `mapping() -> dict[tuple[str, str], MappingRow]` keyed by `(scanner, rule_id)`
  - `canonical_rule_id(rule_id: str) -> str`
  - `class_for(scanner: str, rule_id: str) -> str`
  - `is_unmapped(class_id: str) -> bool`

- [ ] **Step 1: Write the failing test**

Create `tests/test_taxonomy.py`:

```python
"""The taxonomy is the single source of truth for mapping, rubric anchoring, and dedupe.

Every count asserted here is a corpus v0 observation measured on this host, not a
scanner contract (spec section 0). The gate these tests enforce is spec section 1.4:
every rule ID the pinned scanners emit maps to a class or an explicit `unmapped:`
entry, and all five tested categories are populated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iacrisk import taxonomy

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "artifacts" / "rule-inventory.json"

# Per-category class counts from spec section 1.2. Asserted as a whole dict rather
# than a bare total so a class silently moving between categories still fails.
EXPECTED_CLASS_COUNTS = {
    "storage": 7,
    "networking": 6,
    "iam": 4,
    "compute": 4,
    "containers": 7,
}


def _inventory_rule_ids() -> set[tuple[str, str]]:
    """Every (scanner, rule_id) the S0 harvest actually observed."""
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    return {
        (scanner, rule_id)
        for scanner, block in document["by_scanner"].items()
        for rule_id in block["rule_ids"]
    }


def test_taxonomy_has_28_classes_across_five_categories() -> None:
    """Spec section 1.2: 28 classes, category-first, over the five tested domains."""
    classes = taxonomy.classes()
    assert len(classes) == 28

    counts: dict[str, int] = {}
    for issue_class in classes.values():
        counts[issue_class.category] = counts.get(issue_class.category, 0) + 1
    assert counts == EXPECTED_CLASS_COUNTS


def test_every_class_carries_a_definition() -> None:
    """A class with no definition cannot anchor a rubric score or a test case."""
    undefined = [
        issue_class.id
        for issue_class in taxonomy.classes().values()
        if not issue_class.definition.strip()
    ]
    assert undefined == [], f"classes with an empty definition: {undefined}"


def test_every_observed_rule_id_maps_to_a_real_class() -> None:
    """The section 1.4 gate: 255/255 mapped, 0 unmapped in corpus v0.

    Driven from artifacts/rule-inventory.json rather than from taxonomy.json's own
    row list, so the assertion is against what the scanners emitted, not against
    the artifact restating itself.
    """
    observed = _inventory_rule_ids()
    assert len(observed) == 255

    class_ids = set(taxonomy.classes())
    unmapped = [
        (scanner, rule_id)
        for scanner, rule_id in sorted(observed)
        if taxonomy.class_for(scanner, rule_id) not in class_ids
    ]
    assert unmapped == [], f"{len(unmapped)} observed rule ids do not map: {unmapped[:10]}"


def test_mapping_contains_no_row_the_inventory_never_observed() -> None:
    """The other direction: no invented rows padding the coverage number."""
    observed = _inventory_rule_ids()
    invented = sorted(set(taxonomy.mapping()) - observed)
    assert invented == [], f"mapping rows absent from the S0 inventory: {invented[:10]}"


def test_no_class_is_empty() -> None:
    """An empty class is a taxonomy defect: it can never be exercised or evaluated."""
    used = {row.class_id for row in taxonomy.mapping().values()}
    empty = sorted(set(taxonomy.classes()) - used)
    assert empty == [], f"classes with no rule assigned: {empty}"


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("AVD-AWS-0026", "AWS-0026"),  # tfsec form
        ("AWS-0026", "AWS-0026"),  # trivy form of the same Aqua rule - already canonical
        ("CKV_AWS_3", "CKV_AWS_3"),  # checkov ids are their own canonical form
        ("CKV2_AWS_8", "CKV2_AWS_8"),
        ("AVD-AVD-1", "AVD-1"),  # strips exactly one leading prefix, not all of them
    ],
)
def test_canonical_rule_id_strips_one_leading_avd(rule_id: str, expected: str) -> None:
    """Spec section 2.2: trivy AWS-#### and tfsec AVD-AWS-#### are the same Aqua rule."""
    assert taxonomy.canonical_rule_id(rule_id) == expected


def test_trivy_and_tfsec_twins_share_one_class() -> None:
    """Spec section 2.2 co-location, locked so no future edit can split a twin.

    True by construction for the 45 twin pairs (trivy took tfsec's class during
    derivation). This test is what keeps it true.
    """
    by_canonical: dict[str, dict[str, str]] = {}
    for row in taxonomy.mapping().values():
        by_canonical.setdefault(row.canonical_id, {})[row.scanner] = row.class_id

    twins = {
        canonical: per_scanner
        for canonical, per_scanner in by_canonical.items()
        if "trivy" in per_scanner and "tfsec" in per_scanner
    }
    assert len(twins) == 45, f"expected 45 trivy/tfsec twin pairs, found {len(twins)}"

    split = {
        canonical: per_scanner
        for canonical, per_scanner in twins.items()
        if per_scanner["trivy"] != per_scanner["tfsec"]
    }
    assert split == {}, f"twins split across classes: {split}"


def test_unknown_rule_id_falls_back_to_an_explicit_unmapped_class() -> None:
    """Spec section 2.4: a rule the table has never seen is named, never dropped.

    This is the PLAN Q9 explicit-state rule at the taxonomy seam: an unseen rule
    must not quietly acquire a real class, and must not vanish.
    """
    class_id = taxonomy.class_for("trivy", "AWS-9999")

    assert class_id == "unmapped:trivy:AWS-9999"
    assert taxonomy.is_unmapped(class_id)
    assert class_id not in taxonomy.classes()


def test_real_class_ids_are_not_reported_as_unmapped() -> None:
    """Guard the guard: is_unmapped must be precise, not merely wide."""
    assert not taxonomy.is_unmapped("storage-encryption-at-rest")


def test_unmapped_fallback_contract_is_recorded_in_the_artifact() -> None:
    """The Q7 #9 / Q8 #6 policy ships as data, so S3 cannot reinvent it differently."""
    fallback = taxonomy.fallback_contract()

    assert fallback["class_id_format"] == "unmapped:<scanner>:<rule_id>"
    assert fallback["counted_once"] is True
    assert fallback["dropped"] is False
    assert fallback["excluded_from_prioritization_quality_claims"] is True
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_taxonomy.py -q
```

Expected: collection error — `ModuleNotFoundError: No module named 'iacrisk.taxonomy'`.

- [ ] **Step 3: Write the generator and produce `taxonomy.json`**

Create `scratch/build_taxonomy.py`:

```python
"""One-shot: build src/iacrisk/data/taxonomy.json from the frozen S1 design output.

Reads scratch/s1_final.json (28 classes with definitions + 255 rule assignments)
and artifacts/rule-inventory.json (S0 - the authoritative (scanner, rule_id)
universe), and writes the committed taxonomy artifact.

Throwaway by design: the committed taxonomy.json is the source of truth and
tests/test_taxonomy.py pins its invariants against artifacts/rule-inventory.json,
so nothing downstream depends on re-running this script.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
CATEGORIES = ["storage", "networking", "iam", "compute", "containers"]

final = json.loads((REPO / "scratch" / "s1_final.json").read_text(encoding="utf-8"))
inventory = json.loads((REPO / "artifacts" / "rule-inventory.json").read_text(encoding="utf-8"))

scanner_of: dict[str, str] = {}
for scanner, block in inventory["by_scanner"].items():
    for rule_id in block["rule_ids"]:
        if rule_id in scanner_of:
            raise SystemExit(f"rule_id {rule_id} is claimed by two scanners")
        scanner_of[rule_id] = scanner

classes = [
    {
        "id": entry["id"],
        "category": entry["category"],
        "title": entry["title"],
        "definition": entry["definition"],
    }
    for entry in final["classes"]
]
class_ids = {entry["id"] for entry in classes}
if len(classes) != 28:
    raise SystemExit(f"expected 28 classes, got {len(classes)}")
for entry in classes:
    if entry["category"] not in CATEGORIES:
        raise SystemExit(f"class {entry['id']} has unknown category {entry['category']}")
    if not entry["definition"].strip():
        raise SystemExit(f"class {entry['id']} has an empty definition")

mapping: list[dict[str, Any]] = []
for assignment in final["assignments"]:
    rule_id = assignment["rule_id"]
    if rule_id not in scanner_of:
        raise SystemExit(f"assignment {rule_id} is absent from the S0 inventory")
    if assignment["class_id"] not in class_ids:
        raise SystemExit(f"assignment {rule_id} names undefined class {assignment['class_id']}")
    row: dict[str, Any] = {
        "scanner": scanner_of[rule_id],
        "rule_id": rule_id,
        "canonical_id": rule_id.removeprefix("AVD-"),
        "class_id": assignment["class_id"],
        "title": assignment["title"],
        "confidence": assignment.get("confidence", "high"),
    }
    if assignment.get("note"):
        row["note"] = assignment["note"]
    mapping.append(row)

missing = sorted(set(scanner_of) - {row["rule_id"] for row in mapping})
if missing:
    raise SystemExit(f"{len(missing)} inventory rule ids are unmapped: {missing[:10]}")

empty = sorted(class_ids - {row["class_id"] for row in mapping})
if empty:
    raise SystemExit(f"classes with no rule assigned: {empty}")

document = {
    "schema_version": 1,
    "frozen": True,
    "categories": CATEGORIES,
    "classes": sorted(classes, key=lambda c: (CATEGORIES.index(c["category"]), c["id"])),
    "mapping": sorted(mapping, key=lambda r: (r["scanner"], r["rule_id"])),
    "unmapped_fallback": {
        "class_id_format": "unmapped:<scanner>:<rule_id>",
        "scoring": "severity-only, default context",
        "surfaced_as": "baseline-only informational",
        "counted_once": True,
        "dropped": False,
        "excluded_from_prioritization_quality_claims": True,
        "authority": "PLAN.md Q8 #6 and Q7 #9; design spec section 2.4",
    },
    "provenance": {
        "corpus": "corpus v0 as measured on this host",
        "source_inventory": "artifacts/rule-inventory.json",
        "distinct_rule_ids": {
            scanner: block["distinct_rule_ids"] for scanner, block in inventory["by_scanner"].items()
        },
        "note": "255/255 mapped is a corpus observation, not a scanner contract.",
    },
}

out = REPO / "src" / "iacrisk" / "data" / "taxonomy.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
)
print(f"wrote {out}: {len(classes)} classes, {len(mapping)} mapping rows")
```

Run it:

```
uv run python scratch/build_taxonomy.py
```

Expected: `wrote ...taxonomy.json: 28 classes, 255 mapping rows`. Any `SystemExit` message is a real defect in the design input — stop and report it rather than loosening the check.

- [ ] **Step 4: Write the loader**

Create `src/iacrisk/taxonomy.py`:

```python
"""The issue-class taxonomy and the scanner-rule-ID mapping (design spec sections 1-2).

The taxonomy is the cross-cutting single source of truth: the mapping keys on it,
the rubric anchors against it, the evaluation test design is drawn over it, and
the dedupe key (spec section 5.4) carries it as one of three components.

This module is deliberately thin. taxonomy.json is the artifact; everything here
exists because a behaviour in the spec needs a function to carry it - chiefly the
`unmapped:` fallback of section 2.4, which is the PLAN Q9 explicit-state rule at
the taxonomy seam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "taxonomy.json"

CATEGORIES = ("storage", "networking", "iam", "compute", "containers")
"""The five tested domains, in the order the spec presents them."""

UNMAPPED_PREFIX = "unmapped:"


@dataclass(frozen=True)
class IssueClass:
    """One issue class: an id, its category, a title, and a one-sentence definition."""

    id: str
    category: str
    title: str
    definition: str


@dataclass(frozen=True)
class MappingRow:
    """One observed `(scanner, rule_id)` and the class it maps to.

    Keyed on the raw rule id exactly as the scanner emitted it, never a
    pre-normalized key, so every row stays independently verifiable against the
    S0 fixtures (spec section 2.1). `canonical_id` is the cross-scanner form.
    """

    scanner: str
    rule_id: str
    canonical_id: str
    class_id: str
    title: str


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return parsed


@lru_cache(maxsize=1)
def classes() -> MappingProxyType[str, IssueClass]:
    """Every issue class, keyed by id. Read-only: one parse shared by all callers."""
    return MappingProxyType(
        {
            entry["id"]: IssueClass(
                id=entry["id"],
                category=entry["category"],
                title=entry["title"],
                definition=entry["definition"],
            )
            for entry in _document()["classes"]
        }
    )


@lru_cache(maxsize=1)
def mapping() -> MappingProxyType[tuple[str, str], MappingRow]:
    """Every observed rule, keyed by `(scanner, rule_id)`. Read-only."""
    return MappingProxyType(
        {
            (entry["scanner"], entry["rule_id"]): MappingRow(
                scanner=entry["scanner"],
                rule_id=entry["rule_id"],
                canonical_id=entry["canonical_id"],
                class_id=entry["class_id"],
                title=entry["title"],
            )
            for entry in _document()["mapping"]
        }
    )


def fallback_contract() -> MappingProxyType[str, Any]:
    """The `unmapped:` policy, as data (spec section 2.4).

    Shipped in the artifact rather than restated in S3 so the runtime cannot
    quietly adopt a different policy from the one the dissertation reports.
    """
    return MappingProxyType(dict(_document()["unmapped_fallback"]))


def canonical_rule_id(rule_id: str) -> str:
    """The cross-scanner form of a rule id: one leading ``AVD-`` removed.

    trivy emits ``AWS-0088`` and tfsec emits ``AVD-AWS-0088`` for the same Aqua
    rule (spec section 2.2). Checkov ids carry no such prefix and are returned
    unchanged. `removeprefix` strips exactly one occurrence, which is why
    ``AVD-AVD-1`` becomes ``AVD-1`` rather than ``1``.
    """
    return rule_id.removeprefix("AVD-")


def class_for(scanner: str, rule_id: str) -> str:
    """The class id for an observed rule, or an explicit `unmapped:` id.

    A rule the table has never seen - a newer scanner version, an unseen rule -
    is named, counted, and surfaced as baseline-only informational. It is never
    dropped and never assigned a real class by guesswork (spec section 2.4).
    """
    row = mapping().get((scanner, rule_id))
    if row is None:
        return f"{UNMAPPED_PREFIX}{scanner}:{rule_id}"
    return row.class_id


def is_unmapped(class_id: str) -> bool:
    """Whether a class id is the explicit fallback state rather than a real class."""
    return class_id.startswith(UNMAPPED_PREFIX)
```

- [ ] **Step 5: Run the tests to verify they pass**

```
uv run pytest tests/test_taxonomy.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Expected: all `tests/test_taxonomy.py` tests pass; ruff reports no issues and 0 files to reformat; mypy reports `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/iacrisk/data/taxonomy.json src/iacrisk/taxonomy.py tests/test_taxonomy.py
git commit -m "S1: issue-class taxonomy and 255-row scanner-rule-ID mapping

28 classes over the five tested categories; every rule id observed in corpus v0
maps to exactly one class, with an explicit unmapped: fallback for rules the
table has never seen. Closes the spec section 1.4 gate: 255/255 mapped."
```

---

## Task 2: Six-factor scoring rubric config

Implements spec §3.1, §3.2, §3.4, §3.5 and the frozen model of §0. The severity-normalization table that sits beneath the Severity factor is Task 3.

**Files:**
- Create: `scratch/build_rubric.py` (throwaway generator — run once, do not commit)
- Create: `src/iacrisk/data/rubric.json` (generated, committed)
- Create: `src/iacrisk/rubric.py`
- Test: `tests/test_rubric.py`

**Interfaces:**
- Consumes: `scratch/s1_final.json` `factors` block (six factors, in the order severity, exposure, privilege, sensitivity, criticality, encryption).
- Produces, relied on by Tasks 3, 4 and 6:
  - `FACTOR_KEYS: tuple[str, ...]` = `("severity", "exposure", "privilege", "sensitivity", "criticality", "encryption")`
  - `Level` frozen dataclass: `score: int`, `meaning: str`, `justification: str`, `source: str`
  - `Factor` frozen dataclass: `key: str`, `name: str`, `minimum: int`, `maximum: int`, `levels: tuple[Level, ...]`, `unresolved_default: int`, `unresolved_policy: str`, `unresolved_rationale: str`, `sensitivity_sweep: tuple[int, int] | None`
  - `factors() -> MappingProxyType[str, Factor]`
  - `bands() -> tuple[Band, ...]` where `Band` is a frozen dataclass `name: str`, `minimum: int`, `maximum: int`, `action: str`
  - `band_for(score: int) -> str`
  - `unresolved_default(factor_key: str) -> int`
  - `score_bounds() -> tuple[int, int]` returning `(1, 28)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rubric.py`:

```python
"""The rubric is frozen at the end of S1 and mirrored verbatim in the dissertation.

Every number here is fixed a priori from the score structure (spec section 0).
These tests are the freeze: later movement of a range, a band, or an unresolved
default has to break a test and be reported as sensitivity analysis (PLAN Q10),
not slipped in to fit the data.
"""

from __future__ import annotations

import pytest

from iacrisk import rubric

# Factor key -> (minimum, maximum, unresolved default, unresolved policy).
# Spec section 3.2, reproduced as the freeze.
EXPECTED_FACTORS = {
    "severity": (1, 5, 4, "conservative-scored"),
    "exposure": (0, 5, 3, "sensitivity-analysed"),
    "privilege": (0, 5, 4, "conservative-scored"),
    "sensitivity": (0, 5, 3, "conservative-scored"),
    "criticality": (0, 5, 4, "conservative-scored"),
    "encryption": (0, 3, 2, "conservative-scored"),
}

# The external standards the spec section 3 anchors name. A level whose source
# cites none of these is unanchored, which is the section 3.6 gate's failure mode.
# PLAN.md is deliberately absent: the project's own planning document is not an
# external standard, and letting it count would let a level self-anchor.
ANCHORS = ("CVSS", "NIST", "NSA", "OWASP", "FIPS")


def test_the_six_factors_are_exactly_the_model_terms() -> None:
    """Six factors, no more: a seventh term would move the score ceiling."""
    assert rubric.FACTOR_KEYS == tuple(EXPECTED_FACTORS)
    assert set(rubric.factors()) == set(EXPECTED_FACTORS)


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_factor_range_matches_the_frozen_model(key: str) -> None:
    """Ranges are frozen: Severity 1-5, four context factors 0-5, Encryption 0-3."""
    minimum, maximum, _, _ = EXPECTED_FACTORS[key]
    factor = rubric.factors()[key]

    assert (factor.minimum, factor.maximum) == (minimum, maximum)


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_every_score_point_in_the_range_has_exactly_one_level(key: str) -> None:
    """A gap or a duplicate would make a score point unjustifiable (spec 3.6)."""
    minimum, maximum, _, _ = EXPECTED_FACTORS[key]
    scores = [level.score for level in rubric.factors()[key].levels]

    assert scores == list(range(minimum, maximum + 1))


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_every_level_is_source_anchored_and_justified(key: str) -> None:
    """Spec section 3.6: every score point cites a standard and says why.

    The 8-agent verification pass (spec 3.1) found no fabricated standard; this
    test is what stops one being introduced later.
    """
    for level in rubric.factors()[key].levels:
        assert level.meaning.strip(), f"{key} level {level.score} has no meaning"
        assert level.justification.strip(), f"{key} level {level.score} has no justification"
        assert any(anchor in level.source for anchor in ANCHORS), (
            f"{key} level {level.score} cites no recognised standard: {level.source!r}"
        )


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_unresolved_default_and_policy_match_the_spec(key: str) -> None:
    """Spec section 3.2, verified against PLAN Q9's never-silently-low rule."""
    _, _, default, policy = EXPECTED_FACTORS[key]
    factor = rubric.factors()[key]

    assert factor.unresolved_default == default
    assert factor.unresolved_policy == policy
    assert rubric.unresolved_default(key) == default
    assert factor.unresolved_rationale.strip(), f"{key} default has no recorded rationale"


@pytest.mark.parametrize("key", list(EXPECTED_FACTORS))
def test_no_unresolved_default_sits_in_the_bottom_half_of_its_range(key: str) -> None:
    """PLAN Q9: unresolved is never silently scored low.

    Stated as a property rather than a restatement of the six numbers, so it
    still bites if a default is ever revised downward.
    """
    factor = rubric.factors()[key]
    midpoint = (factor.minimum + factor.maximum) / 2

    assert factor.unresolved_default > midpoint, (
        f"{key} unresolved default {factor.unresolved_default} is not above the "
        f"midpoint of {factor.minimum}..{factor.maximum}"
    )


def test_only_exposure_carries_a_sensitivity_sweep() -> None:
    """Spec section 3.2: Q9 names exposure as the factor a fixed default distorts."""
    assert rubric.factors()["exposure"].sensitivity_sweep == (2, 5)
    for key in EXPECTED_FACTORS:
        if key != "exposure":
            assert rubric.factors()[key].sensitivity_sweep is None


def test_score_bounds_are_the_frozen_1_to_28() -> None:
    """Sum of the factor ranges. Changing any range must move this number."""
    assert rubric.score_bounds() == (1, 28)
    assert sum(f.minimum for f in rubric.factors().values()) == 1
    assert sum(f.maximum for f in rubric.factors().values()) == 28


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (28, "Critical"),
        (22, "Critical"),  # the flagship knife-edge: spec 4.4 flags it explicitly
        (21, "High"),
        (16, "High"),
        (15, "Medium"),
        (9, "Medium"),
        (8, "Low"),
        (1, "Low"),
    ],
)
def test_band_boundaries_are_frozen(score: int, band: str) -> None:
    """Critical >= 22, High 16-21, Medium 9-15, Low < 9 - fixed a priori."""
    assert rubric.band_for(score) == band


def test_bands_tile_the_whole_score_range_without_gap_or_overlap() -> None:
    """Every reachable score lands in exactly one band."""
    minimum, maximum = rubric.score_bounds()
    for score in range(minimum, maximum + 1):
        matches = [b.name for b in rubric.bands() if b.minimum <= score <= b.maximum]
        assert len(matches) == 1, f"score {score} matched bands {matches}"


@pytest.mark.parametrize("score", [0, 29])
def test_a_score_outside_the_model_is_rejected_not_silently_banded(score: int) -> None:
    """An out-of-range total means the caller broke the frozen model."""
    with pytest.raises(ValueError, match="outside the frozen model range"):
        rubric.band_for(score)


def test_the_model_is_equal_weighted_and_additive() -> None:
    """Spec section 3.6: the equal-weighted additive sum is the primary model.

    The formula assertion is the half that earns the word "additive" in this
    test's name. Without it the test would claim coverage it does not have.
    """
    model = rubric.model()

    assert model["formula"] == (
        "Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk"
    )
    assert model["equal_weighted"] is True
    assert "sensitivity analysis" in model["weighting"]


def test_class_id_is_not_a_term_in_the_score() -> None:
    """Spec section 3.5(3): the taxonomy dimension must never re-amplify exposure.

    The S1-level form of that assertion - the rubric declares six factors and
    none of them is class-derived. The runtime form, asserted over a computed
    score, belongs to S3 where a scoring function exists.
    """
    assert "class" not in " ".join(rubric.FACTOR_KEYS)
    for factor in rubric.factors().values():
        assert "class_id" not in factor.name
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_rubric.py -q
```

Expected: collection error — `ModuleNotFoundError: No module named 'iacrisk.rubric'`.

- [ ] **Step 3: Write the generator and produce `rubric.json`**

Create `scratch/build_rubric.py`:

```python
"""One-shot: build src/iacrisk/data/rubric.json from the frozen S1 design output.

Reads the six verified factors out of scratch/s1_final.json and stamps the frozen
model bounds and bands around them. The per-level source/justification/meaning
text is carried verbatim - it is the output of the 8-agent verification pass
(design spec section 3.1) and is mirrored in the dissertation.

Throwaway: the committed rubric.json is the source of truth, pinned by
tests/test_rubric.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]

# (key, minimum, maximum, unresolved default, sensitivity sweep) in s1_final order.
FACTOR_SPEC: list[tuple[str, int, int, int, list[int] | None]] = [
    ("severity", 1, 5, 4, None),
    ("exposure", 0, 5, 3, [2, 5]),
    ("privilege", 0, 5, 4, None),
    ("sensitivity", 0, 5, 3, None),
    ("criticality", 0, 5, 4, None),
    ("encryption", 0, 3, 2, None),
]
EXPECTED_POLICY = {
    "severity": "conservative-scored",
    "exposure": "sensitivity-analysed",
    "privilege": "conservative-scored",
    "sensitivity": "conservative-scored",
    "criticality": "conservative-scored",
    "encryption": "conservative-scored",
}

final = json.loads((REPO / "scratch" / "s1_final.json").read_text(encoding="utf-8"))
raw_factors = final["factors"]
if len(raw_factors) != len(FACTOR_SPEC):
    raise SystemExit(f"expected {len(FACTOR_SPEC)} factors, got {len(raw_factors)}")

factors: list[dict[str, Any]] = []
for (key, low, high, default, sweep), source in zip(FACTOR_SPEC, raw_factors, strict=True):
    levels = sorted(
        (
            {
                "score": level["score"],
                "meaning": level["meaning"],
                "justification": level["justification"],
                "source": level["source"],
            }
            for level in source["levels"]
        ),
        key=lambda level: int(level["score"]),
    )
    scores = [level["score"] for level in levels]
    if scores != list(range(low, high + 1)):
        raise SystemExit(f"factor {key}: level scores {scores} do not span {low}..{high}")
    if not low <= default <= high:
        raise SystemExit(f"factor {key}: unresolved default {default} outside {low}..{high}")
    if source["unresolved_policy"] != EXPECTED_POLICY[key]:
        raise SystemExit(
            f"factor {key}: policy {source['unresolved_policy']!r} "
            f"!= {EXPECTED_POLICY[key]!r}"
        )
    factors.append(
        {
            "key": key,
            "name": source["factor"],
            "minimum": low,
            "maximum": high,
            "levels": levels,
            "unresolved_default": default,
            "unresolved_policy": EXPECTED_POLICY[key],
            "unresolved_rationale": source["unresolved_default"],
            "sensitivity_sweep": sweep,
        }
    )

minimum = sum(int(factor["minimum"]) for factor in factors)
maximum = sum(int(factor["maximum"]) for factor in factors)
if (minimum, maximum) != (1, 28):
    raise SystemExit(f"model bounds {minimum}..{maximum} are not the frozen 1..28")

document = {
    "schema_version": 1,
    "frozen": True,
    "freeze_note": (
        "Ranges and bands freeze at the end of S1, before any scoring output is "
        "generated. Later movement is reported as sensitivity analysis (PLAN Q10), "
        "never tuned to fit test data."
    ),
    "model": {
        "formula": "Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk",
        "equal_weighted": True,
        "minimum_score": minimum,
        "maximum_score": maximum,
        "weighting": (
            "Equal weights are the primary model; any weighting scheme is a tunable "
            "reported as sensitivity analysis (PLAN Q10)."
        ),
    },
    "bands": [
        {
            "name": "Critical",
            "minimum": 22,
            "maximum": 28,
            "action": "Block deployment, remediate immediately",
        },
        {
            "name": "High",
            "minimum": 16,
            "maximum": 21,
            "action": "Fix before production / require approval",
        },
        {
            "name": "Medium",
            "minimum": 9,
            "maximum": 15,
            "action": "Schedule in normal sprint/backlog",
        },
        {
            "name": "Low",
            "minimum": 1,
            "maximum": 8,
            "action": "Monitor / document / fix when convenient",
        },
    ],
    "factors": factors,
    "coherence_rules": {
        "iam_governed_resource_inheritance": (
            "For a resource-attached IAM finding, Sensitivity and Criticality are "
            "inherited from the governed resource's declared context (available via "
            "the Q4 context-join, no graph resolve). A pure account-level policy with "
            "no attachment keeps the band cap and is documented as a stated limitation "
            "of the transparent additive model. Design spec section 3.5(1)."
        ),
        "unresolved_default_reporting": (
            "Band distribution is reported split by count-of-defaulted-factors; "
            "findings above a defaulted-factor threshold are flagged low-confidence and "
            "excluded from prioritization-quality claims; the stacked-default total is "
            "carried into the Q10 sensitivity analysis. Design spec section 3.5(2)."
        ),
        "severity_context_fencing": (
            "Scanner severity is a context-free rule baseline. The five context factors "
            "are instance-level deltas scored only from resolved instance evidence and "
            "are never re-derived from the rule. class_id is never a term in the score. "
            "Design spec section 3.5(3)."
        ),
        "encryption_sensitivity_orthogonality": (
            "Encryption level 3 keys only on the control-mandate being an established "
            "engineering requirement; the data's regulated status raises Sensitivity "
            "alone, so the two axes share no input. Design spec section 3.5."
        ),
    },
}

out = REPO / "src" / "iacrisk" / "data" / "rubric.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
)
print(f"wrote {out}: {len(factors)} factors, model {minimum}..{maximum}")
```

Run it:

```
uv run python scratch/build_rubric.py
```

Expected: `wrote ...rubric.json: 6 factors, model 1..28`.

- [ ] **Step 4: Write the loader**

Create `src/iacrisk/rubric.py`:

```python
"""The frozen six-factor scoring rubric (design spec section 3).

Risk = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk.
Equal-weighted, additive, explainable - not machine learning. Every level carries
the standard it is anchored to, because the rubric is mirrored verbatim in the
dissertation and each score point has to be defensible on its own.

Ranges and bands freeze at the end of S1. `band_for` raises rather than clamping
an out-of-range total: a score outside 1..28 means a caller has broken the frozen
model, and silently banding it would hide that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "rubric.json"

FACTOR_KEYS = ("severity", "exposure", "privilege", "sensitivity", "criticality", "encryption")
"""The six model terms, in formula order. A seventh would move the score ceiling."""


@dataclass(frozen=True)
class Level:
    """One score point: what it means, why that number, and the standard behind it."""

    score: int
    meaning: str
    justification: str
    source: str


@dataclass(frozen=True)
class Factor:
    """One model term, its range, its levels, and its unresolved-state policy.

    `unresolved_default` is the value an unresolvable instance takes. Every one of
    the six sits above the midpoint of its own range - PLAN Q9 forbids an
    unresolved state ever reading as low. `sensitivity_sweep` is set only for
    exposure, the factor Q9 names as the one a fixed numeric default distorts.
    """

    key: str
    name: str
    minimum: int
    maximum: int
    levels: tuple[Level, ...]
    unresolved_default: int
    unresolved_policy: str
    unresolved_rationale: str
    sensitivity_sweep: tuple[int, int] | None


@dataclass(frozen=True)
class Band:
    """One priority band and the remediation action it prescribes."""

    name: str
    minimum: int
    maximum: int
    action: str


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return parsed


@lru_cache(maxsize=1)
def factors() -> MappingProxyType[str, Factor]:
    """The six factors, keyed by their model-term key. Read-only."""
    built: dict[str, Factor] = {}
    for entry in _document()["factors"]:
        sweep = entry["sensitivity_sweep"]
        built[entry["key"]] = Factor(
            key=entry["key"],
            name=entry["name"],
            minimum=entry["minimum"],
            maximum=entry["maximum"],
            levels=tuple(
                Level(
                    score=level["score"],
                    meaning=level["meaning"],
                    justification=level["justification"],
                    source=level["source"],
                )
                for level in entry["levels"]
            ),
            unresolved_default=entry["unresolved_default"],
            unresolved_policy=entry["unresolved_policy"],
            unresolved_rationale=entry["unresolved_rationale"],
            sensitivity_sweep=None if sweep is None else (sweep[0], sweep[1]),
        )
    return MappingProxyType(built)


@lru_cache(maxsize=1)
def bands() -> tuple[Band, ...]:
    """The four priority bands, highest first."""
    return tuple(
        Band(
            name=entry["name"],
            minimum=entry["minimum"],
            maximum=entry["maximum"],
            action=entry["action"],
        )
        for entry in _document()["bands"]
    )


def model() -> MappingProxyType[str, Any]:
    """The frozen model block: formula, equal weighting, and score bounds."""
    return MappingProxyType(dict(_document()["model"]))


def coherence_rules() -> MappingProxyType[str, str]:
    """The four structural rules from spec section 3.5, carried as data for S3."""
    return MappingProxyType(dict(_document()["coherence_rules"]))


def score_bounds() -> tuple[int, int]:
    """The reachable total-score range: (1, 28) under the frozen ranges."""
    block = _document()["model"]
    return (int(block["minimum_score"]), int(block["maximum_score"]))


def unresolved_default(factor_key: str) -> int:
    """The value an unresolved instance of `factor_key` takes (spec section 3.2)."""
    return factors()[factor_key].unresolved_default


def band_for(score: int) -> str:
    """The priority band a total score falls in.

    Raises `ValueError` outside 1..28. An out-of-range total is a caller that has
    broken the frozen model, and a clamped band would bury that rather than
    surface it.
    """
    minimum, maximum = score_bounds()
    if not minimum <= score <= maximum:
        raise ValueError(
            f"score {score} is outside the frozen model range {minimum}..{maximum}"
        )
    for band in bands():
        if band.minimum <= score <= band.maximum:
            return band.name
    raise ValueError(f"score {score} matched no band; rubric.json bands do not tile the range")
```

- [ ] **Step 5: Run the tests to verify they pass**

```
uv run pytest tests/test_rubric.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Expected: all `tests/test_rubric.py` tests pass; ruff clean; mypy `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/iacrisk/data/rubric.json src/iacrisk/rubric.py tests/test_rubric.py
git commit -m "S1: six-factor scoring rubric, frozen ranges and bands

Every score point carries the CVSS/NIST/NSA-CISA/OWASP/FIPS anchor the
verification pass confirmed, plus its unresolved default and policy. Bands and
the 1..28 bounds freeze here; the four spec 3.5 coherence rules ship as data so
S3 cannot adopt a different reading."
```

---

## Task 3: Scanner severity-normalization table

Implements spec §3.3 (Deliverable 3) — the operational layer beneath the rubric's Severity factor, which is what makes the raw-scanner baseline comparable across scanners (PLAN Q7 #5). Extends the `rubric.json` created in Task 2.

**Files:**
- Modify: `src/iacrisk/data/rubric.json` (add the `severity_normalization` block)
- Modify: `src/iacrisk/rubric.py` (add `UNKNOWN`, `normalize_severity`, `severity_normalization`)
- Test: `tests/test_severity_normalization.py`

**Interfaces:**
- Consumes from Task 2: `rubric._document()`, `rubric.factors()`, `rubric.unresolved_default`.
- Produces, relied on by Task 6:
  - `UNKNOWN: str` = `"unknown"`
  - `normalize_severity(scanner: str, token: str | None) -> int | str` — returns `1..5`, or the literal `"unknown"`
  - `severity_normalization() -> MappingProxyType[str, Any]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_severity_normalization.py`:

```python
"""The baseline is only comparable across scanners if the tokens normalize (PLAN Q7 #5).

The load-bearing case is `unknown`. Trivy's fifth level is UNKNOWN - severity
undetermined, NOT a benign informational band - and 489 of corpus v0's 1055 rows
carry no severity at all, every one of them Checkov. Both route to the explicit
unknown state and take the conservative default of 4. Neither is ever scored low.
Phase0 section A.3 item 4 left this open rather than warning about it: it recorded
that only four levels were observed across the 566 rows carrying a severity, and
required S1's normalization spec to say what the fifth level is for or drop to
four. This table is that answer - the fifth slot is UNKNOWN, routed to the
unresolved default, with level 1 held in reserve for a CVSS None the corpus never
exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iacrisk import rubric

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNERS = ["checkov", "trivy", "tfsec"]


@pytest.mark.parametrize(
    ("token", "level"),
    [("CRITICAL", 5), ("HIGH", 4), ("MEDIUM", 3), ("LOW", 2), ("NONE", 1)],
)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_every_scale_token_maps_to_its_frozen_level(scanner: str, token: str, level: int) -> None:
    """Spec section 3.3: CRITICAL 5, HIGH 4, MEDIUM 3, LOW 2, CVSS None 1."""
    assert rubric.normalize_severity(scanner, token) == level


@pytest.mark.parametrize("raw", ["critical", " Critical ", "CrItIcAl"])
def test_token_matching_is_case_and_whitespace_insensitive(raw: str) -> None:
    """Scanners are not required to agree on casing; the table should not care."""
    assert rubric.normalize_severity("trivy", raw) == 5


def test_trivy_unknown_is_severity_undetermined_not_informational() -> None:
    """The grave correction from the verification pass (spec section 3.4).

    Trivy's fifth level is UNKNOWN. Reading it as the CVSS None band and scoring
    it 1 would treat a severity the scanner could not determine as nearly benign.
    """
    assert rubric.normalize_severity("trivy", "UNKNOWN") == rubric.UNKNOWN


def test_checkov_null_severity_routes_to_unknown() -> None:
    """46.4% of corpus v0. Severity reaches Checkov's JSON only via the API-key path."""
    assert rubric.normalize_severity("checkov", None) == rubric.UNKNOWN


@pytest.mark.parametrize("token", ["", "   ", "SEVERE", "P1", "informational"])
def test_an_unrecognised_token_is_unknown_never_a_guess(token: str) -> None:
    """Explicit-state discipline: a token the table does not know is named, not mapped."""
    assert rubric.normalize_severity("trivy", token) == rubric.UNKNOWN


def test_an_unrecognised_scanner_is_unknown_never_a_guess() -> None:
    """A scanner outside the pinned three cannot have a verified token vocabulary."""
    assert rubric.normalize_severity("snyk", "HIGH") == rubric.UNKNOWN


def test_unknown_resolves_to_the_severity_factor_default() -> None:
    """One source of truth: the table's routing and the factor's default must agree."""
    table = rubric.severity_normalization()

    assert table["unknown_resolves_to"] == rubric.unresolved_default("severity") == 4


def test_unknown_is_never_scored_below_an_observed_low() -> None:
    """PLAN Q9 at the severity seam, stated as a property.

    An undetermined severity must never rank below a scanner-asserted LOW; that
    is the false-reassurance failure mode the framework exists to prevent.
    """
    low = rubric.normalize_severity("trivy", "LOW")
    resolved_unknown = rubric.severity_normalization()["unknown_resolves_to"]

    assert isinstance(low, int)
    assert resolved_unknown > low


def test_the_reserved_none_band_is_recorded_as_unexercised() -> None:
    """Level 1 exists so the scale need not shift later; corpus v0 never hits it.

    Checks the claim rather than restating it: NONE must appear in no scanner's
    observed levels, which is what makes 'reserved' and 'unexercised' both true.
    """
    table = rubric.severity_normalization()

    assert table["reserved_unexercised"] == ["NONE"]
    assert table["token_scale"]["NONE"] == 1
    for scanner, block in table["per_scanner"].items():
        assert "NONE" not in block["observed_in_corpus_v0"], f"{scanner} observed NONE"


def test_the_recorded_corpus_measurement_matches_the_harvest() -> None:
    """The recorded numbers are checked against the harvest, not against themselves.

    Spec section 0: these are corpus v0 observations measured on this host. If the
    corpus is re-harvested and the counts move, this fails and the recorded block
    has to be updated - which is the drift the guard exists to catch. Comparing
    against literals typed into the test would make it a dormant guard: it could
    never fail for the reason its name promises.
    """
    inventory = json.loads(
        (REPO_ROOT / "artifacts" / "rule-inventory.json").read_text(encoding="utf-8")
    )
    by_scanner = inventory["by_scanner"]
    rows = sum(block["rows"] for block in by_scanner.values())
    missing = sum(block["missing_severity_rows"] for block in by_scanner.values())

    corpus = rubric.severity_normalization()["corpus_v0"]

    assert corpus["rows"] == rows
    assert corpus["missing_severity_rows"] == missing
    assert corpus["all_missing_are_checkov"] is True
    assert by_scanner["checkov"]["missing_severity_rows"] == missing


@pytest.mark.parametrize("scanner", SCANNERS)
def test_every_pinned_scanner_has_a_recorded_vocabulary(scanner: str) -> None:
    """The per-scanner block is what lets the unknown rate be reported per scanner.

    Observed levels are compared against the harvest rather than merely asserted
    present, so a re-harvest cannot leave this block stale. The comparison is on
    sets: the rubric records levels in severity order, the inventory alphabetically.
    """
    inventory = json.loads(
        (REPO_ROOT / "artifacts" / "rule-inventory.json").read_text(encoding="utf-8")
    )
    per_scanner = rubric.severity_normalization()["per_scanner"]

    assert scanner in per_scanner
    recorded = per_scanner[scanner]["observed_in_corpus_v0"]
    observed = inventory["by_scanner"][scanner]["observed_severity_levels"]
    assert set(recorded) == set(observed)
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_severity_normalization.py -q
```

Expected: FAIL — `AttributeError: module 'iacrisk.rubric' has no attribute 'normalize_severity'`.

- [ ] **Step 3: Add the table to `rubric.json`**

Append a `severity_normalization` key to `src/iacrisk/data/rubric.json`, as a sibling of `factors` and `coherence_rules`. Insert this block verbatim (keeping the file's two-space indentation and LF endings):

```json
  "severity_normalization": {
    "unknown_state": "unknown",
    "unknown_resolves_to": 4,
    "token_scale": {
      "CRITICAL": 5,
      "HIGH": 4,
      "MEDIUM": 3,
      "LOW": 2,
      "NONE": 1
    },
    "unknown_tokens": ["UNKNOWN"],
    "null_routes_to": "unknown",
    "reserved_unexercised": ["NONE"],
    "per_scanner": {
      "checkov": {
        "vocabulary": [],
        "observed_in_corpus_v0": [],
        "note": "Severity reaches checkov's JSON only through the API-key policyMetadata path; the public path fills guideline and id and leaves severity null. 489 of 489 rows null in corpus v0."
      },
      "trivy": {
        "vocabulary": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        "observed_in_corpus_v0": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "note": "UNKNOWN is severity-undetermined, not an informational band. It routes to the unknown state, never to level 1."
      },
      "tfsec": {
        "vocabulary": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "observed_in_corpus_v0": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "note": "119 rows in corpus v0, all four levels exercised."
      }
    },
    "corpus_v0": {
      "rows": 1055,
      "missing_severity_rows": 489,
      "missing_severity_rate": 0.464,
      "all_missing_are_checkov": true,
      "note": "A corpus observation measured on this host, not a scanner contract."
    },
    "reporting": "The per-scanner unknown-severity rate is reported as an evaluation-integrity metric (PLAN Q3 #4); unknown stays a first-class state in the finding record and the output JSON."
  },
```

- [ ] **Step 4: Add the normalization functions to `rubric.py`**

Add the `UNKNOWN` constant immediately after `FACTOR_KEYS`:

```python
UNKNOWN = "unknown"
"""The explicit severity-undetermined state. Never coerced to a numeric level."""
```

Then append these two functions to the end of `src/iacrisk/rubric.py`:

```python
def severity_normalization() -> MappingProxyType[str, Any]:
    """The per-scanner raw-token to 1-5 table (design spec section 3.3)."""
    return MappingProxyType(dict(_document()["severity_normalization"]))


def normalize_severity(scanner: str, token: str | None) -> int | str:
    """Map a scanner's raw severity token to a 1-5 level, or to `UNKNOWN`.

    This is what makes the raw-scanner baseline comparable across scanners
    (PLAN Q7 #5). Four routes end in `UNKNOWN`, and none of them ends in a low
    number, which is the whole point:

    - `None`: the scanner emitted no severity at all. Every one of corpus v0's
      489 such rows is Checkov.
    - A token in `unknown_tokens`: trivy's `UNKNOWN` is severity-undetermined,
      not a benign informational band. Scoring it 1 was the defect the
      verification pass caught (spec section 3.4).
    - A token the table does not know: named, not guessed at.
    - A scanner outside the pinned three: no verified token vocabulary exists
      for it, so its tokens cannot be trusted to mean what they look like.

    The caller resolves `UNKNOWN` through `unresolved_default("severity")`, which
    the table's own `unknown_resolves_to` is asserted to agree with.
    """
    table = _document()["severity_normalization"]
    if scanner not in table["per_scanner"]:
        return UNKNOWN
    if token is None:
        return UNKNOWN
    normalized = token.strip().upper()
    if not normalized or normalized in table["unknown_tokens"]:
        return UNKNOWN
    scale: dict[str, int] = table["token_scale"]
    level = scale.get(normalized)
    return UNKNOWN if level is None else level
```

- [ ] **Step 5: Run the tests to verify they pass**

```
uv run pytest tests/test_severity_normalization.py tests/test_rubric.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Expected: both test modules pass (Task 2's tests must stay green — the block is additive); ruff clean; mypy `Success`.

- [ ] **Step 6: Commit**

```bash
git add src/iacrisk/data/rubric.json src/iacrisk/rubric.py tests/test_severity_normalization.py
git commit -m "S1: scanner severity-normalization table with explicit unknown routing

Per-scanner raw token to 1-5, so the raw-severity baseline is comparable across
scanners. Trivy UNKNOWN and Checkov null both route to the explicit unknown
state and resolve to 4, never to the reserved level-1 None band."
```

---

## Task 4: Evaluation ground-truth schema and validator

Implements spec §4. The harness *reads* ground truth; results are never hand-judged (PLAN Q7). Three record types, never merged.

**Files:**
- Create: `eval/ground_truth.schema.json`
- Create: `eval/ground_truth.py`
- Create: `eval/ground_truth/example.json`
- Test: `tests/test_ground_truth.py`

**Interfaces:**
- Consumes: the class-id shape from Task 1 and the factor keys from Task 2 — as schema `enum`/`pattern` values only. **No import of `iacrisk`**: `tests/test_architecture.py::test_eval_does_not_import_scoring` forbids the harness sharing code with what it grades, and staying import-free keeps that guard trivially satisfied.
- Produces:
  - `GroundTruthError(ValueError)`
  - `SCHEMA_PATH: Path`, `load_schema() -> dict[str, Any]`
  - `validate(document: Any) -> None` — raises `GroundTruthError`, never returns a skip
  - `load_and_validate(path: Path) -> dict[str, Any]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ground_truth.py`:

```python
"""A malformed ground-truth record is a hard reject, never a skip (spec section 4.5).

A harness that skips a bad case silently shrinks its own denominator and reports
a better number than it earned. Every test here is about the reject path being
loud.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from eval.ground_truth import GroundTruthError, load_and_validate, validate

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "eval" / "ground_truth" / "example.json"


def _document() -> dict[str, Any]:
    """A minimal document that exercises all three record types and validates."""
    return {
        "schema_version": 1,
        "cases": [
            {
                "case_id": "tg-aws-s3",
                "platform": "terraform",
                "domain": "storage",
                "source": {
                    "repo": "bridgecrewio/terragoat",
                    "commit": "729f8da6",
                    "path": "terraform/aws/s3.tf",
                },
                "declared_context": {
                    "aws_s3_bucket.data": {"sensitivity": 4, "criticality": 4},
                    "aws_s3_bucket.financials": {"sensitivity": None, "criticality": None},
                },
                "expected": {
                    "findings": [
                        {
                            "resource_identity": "aws_s3_bucket.data",
                            "issue_class": "storage-encryption-at-rest",
                            "expected_band": "High",
                        },
                        {
                            "resource_identity": "aws_s3_bucket.financials",
                            "issue_class": "unmapped:trivy:AWS-9999",
                            "excluded_from_quality_claims": True,
                        },
                    ]
                },
            },
            {
                "case_id": "tg-aws-s3-locked",
                "platform": "terraform",
                "domain": "storage",
                "source": "hand-crafted",
                "declared_context": {
                    "aws_s3_bucket.data": {"sensitivity": 4, "criticality": 4}
                },
                "expected": {"findings": []},
            },
        ],
        "contrastive_pairs": [
            {
                "pair_id": "exposure-public-vs-private-bucket",
                "factor_under_test": "exposure",
                "case_high": "tg-aws-s3",
                "case_low": "tg-aws-s3-locked",
                "expected_rank_order": "high_above_low",
                "expected_score_delta_sign": "positive",
                "rationale": "The two cases differ only in the public-access-block setting.",
            }
        ],
        "scenarios": [
            {
                "scenario_id": "storage-triage-order",
                "domain": "storage",
                "expected_ordering": [["tg-aws-s3"], ["tg-aws-s3-locked"]],
                "rationale": "A world-readable bucket holding regulated data outranks a locked one.",
                "oracle": {
                    "author": "258243J",
                    "reviewer": "supervisor",
                    "registered_at": "2026-09-19T00:00:00Z",
                    "reviewer_verdict": "agree",
                },
            }
        ],
    }


def test_a_well_formed_document_validates() -> None:
    validate(_document())


def test_the_committed_example_validates() -> None:
    """The shipped exemplar has to be an example of something that actually passes."""
    assert load_and_validate(EXAMPLE)["schema_version"] == 1


def test_a_case_with_no_expected_block_is_rejected() -> None:
    """The spec section 4.5 gate, stated exactly: missing expected is a hard reject."""
    document = _document()
    del document["cases"][0]["expected"]

    with pytest.raises(GroundTruthError, match="expected"):
        validate(document)


def test_a_case_with_an_ill_formed_expected_block_is_rejected() -> None:
    document = _document()
    document["cases"][0]["expected"] = {"findings": "not-a-list"}

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_null_declared_context_value_is_allowed() -> None:
    """Null is how a case deliberately exercises the default-fallback path (4.1)."""
    document = _document()
    document["cases"][0]["declared_context"]["aws_s3_bucket.data"] = {
        "sensitivity": None,
        "criticality": None,
    }

    validate(document)


@pytest.mark.parametrize("value", [-1, 6, 2.5, "3"])
def test_a_declared_context_value_outside_0_to_5_is_rejected(value: object) -> None:
    """Declared context feeds two 0-5 factors; anything else is ill-formed."""
    document = _document()
    document["cases"][0]["declared_context"]["aws_s3_bucket.data"]["sensitivity"] = value

    with pytest.raises(GroundTruthError):
        validate(document)


def test_expected_band_is_optional() -> None:
    """Spec section 4.4: ordering is primary, absolute band is secondary."""
    document = _document()
    del document["cases"][0]["expected"]["findings"][0]["expected_band"]

    validate(document)


def test_an_unmapped_issue_class_is_a_first_class_expected_value() -> None:
    """The harness has to be able to hold an unmapped finding to the Q7 #9 exclusion."""
    document = _document()
    finding = document["cases"][0]["expected"]["findings"][1]

    assert finding["issue_class"].startswith("unmapped:")
    validate(document)


def test_a_duplicate_case_id_is_rejected() -> None:
    document = _document()
    document["cases"].append(copy.deepcopy(document["cases"][0]))

    with pytest.raises(GroundTruthError, match="duplicate case_id"):
        validate(document)


def test_a_pair_referencing_an_unknown_case_is_rejected() -> None:
    """A dangling reference means the pair tests nothing - it must not pass quietly."""
    document = _document()
    document["contrastive_pairs"][0]["case_low"] = "no-such-case"

    with pytest.raises(GroundTruthError, match="unknown case"):
        validate(document)


def test_a_pair_whose_two_cases_are_the_same_is_rejected() -> None:
    """A pair with one case cannot differ in exactly one factor (spec 4.2)."""
    document = _document()
    document["contrastive_pairs"][0]["case_low"] = "tg-aws-s3"

    with pytest.raises(GroundTruthError, match="same case"):
        validate(document)


def test_a_pair_with_an_unknown_factor_under_test_is_rejected() -> None:
    document = _document()
    document["contrastive_pairs"][0]["factor_under_test"] = "vibes"

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_scenario_tier_referencing_an_unknown_case_is_rejected() -> None:
    document = _document()
    document["scenarios"][0]["expected_ordering"] = [["tg-aws-s3"], ["ghost-case"]]

    with pytest.raises(GroundTruthError, match="unknown case"):
        validate(document)


def test_an_oracle_authored_and_reviewed_by_one_person_is_rejected() -> None:
    """Spec section 4.3: author != reviewer, or the oracle reviews itself.

    JSON Schema cannot express a field inequality, so this is the validator's
    own check - and it is the reason the validator exists rather than a bare
    jsonschema call at the harness entry point.
    """
    document = _document()
    document["scenarios"][0]["oracle"]["reviewer"] = "258243J"

    with pytest.raises(GroundTruthError, match="author and reviewer"):
        validate(document)


def test_a_disagreeing_oracle_must_record_the_disagreement() -> None:
    """Disagreement is reported as oracle uncertainty, never resolved away (4.3)."""
    document = _document()
    document["scenarios"][0]["oracle"]["reviewer_verdict"] = "disagree"

    with pytest.raises(GroundTruthError):
        validate(document)

    document["scenarios"][0]["oracle"]["disagreement_note"] = "Reviewer ranks IAM above storage."
    validate(document)


def test_an_unknown_top_level_key_is_rejected() -> None:
    """Three record types, never merged - and never quietly extended either."""
    document = _document()
    document["findings"] = []

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_non_object_document_is_rejected() -> None:
    with pytest.raises(GroundTruthError, match="schema validation"):
        validate([1, 2, 3])


def test_load_and_validate_rejects_malformed_json(tmp_path: Path) -> None:
    """A truncated file must not read as an empty-but-valid document."""
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema_version": 1, "cases": [', encoding="utf-8")

    with pytest.raises(GroundTruthError, match="not valid JSON"):
        load_and_validate(broken)


def test_the_schema_file_is_itself_valid_json() -> None:
    path = REPO_ROOT / "eval" / "ground_truth.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_ground_truth.py -q
```

Expected: collection error — `ModuleNotFoundError: No module named 'eval.ground_truth'`.

- [ ] **Step 3: Write the schema**

Create `eval/ground_truth.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/258243J/iacrisk/eval/ground_truth.schema.json",
  "title": "S1 evaluation ground truth",
  "description": "Three record types, never merged: cases, contrastive pairs (mechanism tests), and scenario orderings (realistic tests). Design spec section 4.",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "cases", "contrastive_pairs", "scenarios"],
  "properties": {
    "schema_version": { "const": 1 },
    "cases": { "type": "array", "items": { "$ref": "#/$defs/case" } },
    "contrastive_pairs": { "type": "array", "items": { "$ref": "#/$defs/contrastive_pair" } },
    "scenarios": { "type": "array", "items": { "$ref": "#/$defs/scenario" } }
  },
  "$defs": {
    "domain": { "enum": ["storage", "networking", "iam", "compute", "containers"] },
    "factor_key": {
      "enum": ["severity", "exposure", "privilege", "sensitivity", "criticality", "encryption"]
    },
    "band": { "enum": ["Critical", "High", "Medium", "Low"] },
    "context_value": {
      "description": "A declared 0-5 context value, or null to exercise the default-fallback path.",
      "type": ["integer", "null"],
      "minimum": 0,
      "maximum": 5
    },
    "issue_class": {
      "description": "A taxonomy class id, or the explicit unmapped:<scanner>:<rule_id> fallback.",
      "type": "string",
      "pattern": "^(unmapped:[^:]+:.+|[a-z0-9]+(-[a-z0-9]+)+)$"
    },
    "case": {
      "type": "object",
      "additionalProperties": false,
      "required": ["case_id", "platform", "domain", "source", "declared_context", "expected"],
      "properties": {
        "case_id": { "type": "string", "minLength": 1 },
        "platform": { "enum": ["terraform", "kubernetes"] },
        "domain": { "$ref": "#/$defs/domain" },
        "source": {
          "oneOf": [
            {
              "type": "object",
              "additionalProperties": false,
              "required": ["repo", "commit", "path"],
              "properties": {
                "repo": { "type": "string", "minLength": 1 },
                "commit": { "type": "string", "pattern": "^[0-9a-f]{7,40}$" },
                "path": { "type": "string", "minLength": 1 }
              }
            },
            { "const": "hand-crafted" }
          ]
        },
        "declared_context": {
          "description": "Keyed on canonical resource identity (design spec section 5).",
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "additionalProperties": false,
            "required": ["sensitivity", "criticality"],
            "properties": {
              "sensitivity": { "$ref": "#/$defs/context_value" },
              "criticality": { "$ref": "#/$defs/context_value" }
            }
          }
        },
        "expected": {
          "type": "object",
          "additionalProperties": false,
          "required": ["findings"],
          "properties": {
            "findings": { "type": "array", "items": { "$ref": "#/$defs/expected_finding" } },
            "notes": { "type": "string" }
          }
        }
      }
    },
    "expected_finding": {
      "type": "object",
      "additionalProperties": false,
      "required": ["resource_identity", "issue_class"],
      "properties": {
        "resource_identity": { "type": "string", "minLength": 1 },
        "issue_class": { "$ref": "#/$defs/issue_class" },
        "expected_band": {
          "description": "Secondary and optional. Ordering is the primary signal (spec 4.4).",
          "$ref": "#/$defs/band"
        },
        "unresolved_factors": {
          "type": "array",
          "items": { "$ref": "#/$defs/factor_key" },
          "uniqueItems": true
        },
        "excluded_from_quality_claims": { "type": "boolean" }
      }
    },
    "contrastive_pair": {
      "description": "Mechanism test. The differs-in-exactly-one-factor invariant is machine-checked by the harness against the two cases' resolved factors (spec 4.2).",
      "type": "object",
      "additionalProperties": false,
      "required": [
        "pair_id",
        "factor_under_test",
        "case_high",
        "case_low",
        "expected_rank_order",
        "expected_score_delta_sign"
      ],
      "properties": {
        "pair_id": { "type": "string", "minLength": 1 },
        "factor_under_test": { "$ref": "#/$defs/factor_key" },
        "case_high": { "type": "string", "minLength": 1 },
        "case_low": { "type": "string", "minLength": 1 },
        "expected_rank_order": { "const": "high_above_low" },
        "expected_score_delta_sign": {
          "description": "Fixed positive by the case_high/case_low orientation. Stated in the data rather than left implicit in harness code, so the assertion the pair rests on is one the artifact carries.",
          "const": "positive"
        },
        "rationale": { "type": "string" }
      }
    },
    "scenario": {
      "description": "Realistic test: a pre-registered partial order over cases, with a two-person oracle.",
      "type": "object",
      "additionalProperties": false,
      "required": ["scenario_id", "domain", "expected_ordering", "rationale", "oracle"],
      "properties": {
        "scenario_id": { "type": "string", "minLength": 1 },
        "domain": { "$ref": "#/$defs/domain" },
        "expected_ordering": {
          "description": "Tiers, highest first. Cases inside one tier are unordered with respect to each other.",
          "type": "array",
          "minItems": 2,
          "items": {
            "type": "array",
            "minItems": 1,
            "items": { "type": "string", "minLength": 1 },
            "uniqueItems": true
          }
        },
        "rationale": { "type": "string", "minLength": 1 },
        "oracle": { "$ref": "#/$defs/oracle" }
      }
    },
    "oracle": {
      "type": "object",
      "additionalProperties": false,
      "required": ["author", "reviewer", "registered_at", "reviewer_verdict"],
      "properties": {
        "author": { "type": "string", "minLength": 1 },
        "reviewer": { "type": "string", "minLength": 1 },
        "registered_at": {
          "description": "Must precede any scoring output. Pre-registration is what makes the ordering an oracle rather than a post-hoc rationalisation.",
          "type": "string",
          "format": "date-time"
        },
        "reviewer_verdict": { "enum": ["agree", "disagree", "partial"] },
        "disagreement_note": { "type": "string", "minLength": 1 }
      },
      "allOf": [
        {
          "if": { "properties": { "reviewer_verdict": { "enum": ["disagree", "partial"] } } },
          "then": { "required": ["disagreement_note"] }
        }
      ]
    }
  }
}
```

- [ ] **Step 4: Write the validator**

Create `eval/ground_truth.py`:

```python
"""Validation at the harness entry point (design spec section 4.5).

The gate is exact: a case with a missing or ill-formed `expected` block is a hard
reject, not a skip. A harness that skips a bad case shrinks its own denominator
and reports a better number than it earned.

Two layers, because one is not enough:

1. JSON Schema, for shape.
2. Cross-record semantics, for the things JSON Schema structurally cannot say -
   uniqueness of ids across a list, references from pairs and scenarios resolving
   to real cases, and `author != reviewer` on an oracle. That last one is a field
   inequality, which no JSON Schema keyword expresses, and it is the reason this
   module exists rather than a bare `jsonschema.validate` call at the call site.

This module deliberately imports nothing from `iacrisk`: the harness may not share
code with what it grades (PLAN Q7), a boundary
`tests/test_architecture.py::test_eval_does_not_import_scoring` enforces.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parent / "ground_truth.schema.json"


class GroundTruthError(ValueError):
    """A ground-truth document the harness must reject rather than skip."""


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """The JSON Schema for the three record types."""
    parsed: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return parsed


def _check_shape(document: Any) -> None:
    schema = load_schema()
    validator_class = jsonschema.validators.validator_for(schema)
    validator = validator_class(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    rendered = "; ".join(
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors[:5]
    )
    suffix = f" (and {len(errors) - 5} more)" if len(errors) > 5 else ""
    raise GroundTruthError(f"ground truth failed schema validation - {rendered}{suffix}")


def _unique_ids(records: list[dict[str, Any]], key: str) -> set[str]:
    seen: set[str] = set()
    for record in records:
        identifier = record[key]
        if identifier in seen:
            raise GroundTruthError(f"duplicate {key}: {identifier!r}")
        seen.add(identifier)
    return seen


def _check_semantics(document: dict[str, Any]) -> None:
    case_ids = _unique_ids(document["cases"], "case_id")
    _unique_ids(document["contrastive_pairs"], "pair_id")
    _unique_ids(document["scenarios"], "scenario_id")

    for pair in document["contrastive_pairs"]:
        for side in ("case_high", "case_low"):
            if pair[side] not in case_ids:
                raise GroundTruthError(
                    f"contrastive pair {pair['pair_id']!r} {side} names unknown case "
                    f"{pair[side]!r}"
                )
        if pair["case_high"] == pair["case_low"]:
            raise GroundTruthError(
                f"contrastive pair {pair['pair_id']!r} names the same case on both sides; "
                "a pair cannot differ in exactly one factor from itself"
            )

    for scenario in document["scenarios"]:
        for tier in scenario["expected_ordering"]:
            for case_id in tier:
                if case_id not in case_ids:
                    raise GroundTruthError(
                        f"scenario {scenario['scenario_id']!r} orders unknown case {case_id!r}"
                    )
        oracle = scenario["oracle"]
        if oracle["author"] == oracle["reviewer"]:
            raise GroundTruthError(
                f"scenario {scenario['scenario_id']!r} oracle author and reviewer are the "
                f"same person ({oracle['author']!r}); the oracle would be reviewing itself"
            )


def validate(document: Any) -> None:
    """Validate a ground-truth document, raising `GroundTruthError` on any defect."""
    _check_shape(document)
    _check_semantics(document)


def load_and_validate(path: Path) -> dict[str, Any]:
    """Read, parse and validate a ground-truth file.

    A truncated or malformed file raises rather than reading as an empty-but-valid
    document - the same reject-do-not-skip discipline applied one layer earlier.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GroundTruthError(f"{path} is not valid JSON: {exc}") from exc
    validate(document)
    parsed: dict[str, Any] = document
    return parsed
```

- [ ] **Step 5: Write the committed exemplar**

Create `eval/ground_truth/example.json`. This is a schema exemplar, not corpus ground truth — the real corpus cases are authored in S2, against this schema.

```json
{
  "schema_version": 1,
  "cases": [
    {
      "case_id": "example-s3-public",
      "platform": "terraform",
      "domain": "storage",
      "source": {
        "repo": "bridgecrewio/terragoat",
        "commit": "729f8da6",
        "path": "terraform/aws/s3.tf"
      },
      "declared_context": {
        "aws_s3_bucket.data": { "sensitivity": 4, "criticality": 4 },
        "aws_s3_bucket.scratch": { "sensitivity": null, "criticality": null }
      },
      "expected": {
        "findings": [
          {
            "resource_identity": "aws_s3_bucket.data",
            "issue_class": "storage-public-accessibility",
            "expected_band": "Critical"
          },
          {
            "resource_identity": "aws_s3_bucket.scratch",
            "issue_class": "storage-encryption-at-rest",
            "unresolved_factors": ["sensitivity", "criticality"],
            "excluded_from_quality_claims": true
          }
        ],
        "notes": "The scratch bucket declares null context deliberately: it exercises the default-fallback path and is therefore held out of prioritization-quality claims."
      }
    },
    {
      "case_id": "example-s3-locked",
      "platform": "terraform",
      "domain": "storage",
      "source": "hand-crafted",
      "declared_context": {
        "aws_s3_bucket.data": { "sensitivity": 4, "criticality": 4 }
      },
      "expected": {
        "findings": [
          {
            "resource_identity": "aws_s3_bucket.data",
            "issue_class": "storage-encryption-at-rest",
            "expected_band": "Medium"
          }
        ],
        "notes": "Identical to example-s3-public but with the public-access-block enabled."
      }
    },
    {
      "case_id": "example-k8s-privileged",
      "platform": "kubernetes",
      "domain": "containers",
      "source": {
        "repo": "madhuakula/kubernetes-goat",
        "commit": "723a0db4",
        "path": "scenarios/system-monitor/deployment.yaml"
      },
      "declared_context": {
        "apps/v1/Deployment/default/system-monitor [container=system-monitor]": {
          "sensitivity": 5,
          "criticality": 4
        }
      },
      "expected": {
        "findings": [
          {
            "resource_identity": "apps/v1/Deployment/default/system-monitor [container=system-monitor]",
            "issue_class": "containers-privileged-execution",
            "expected_band": "Critical"
          }
        ]
      }
    }
  ],
  "contrastive_pairs": [
    {
      "pair_id": "exposure-public-vs-locked-bucket",
      "factor_under_test": "exposure",
      "case_high": "example-s3-public",
      "case_low": "example-s3-locked",
      "expected_rank_order": "high_above_low",
      "expected_score_delta_sign": "positive",
      "rationale": "The two cases are identical apart from the public-access-block setting, so any rank difference is attributable to Public Exposure alone."
    }
  ],
  "scenarios": [
    {
      "scenario_id": "example-storage-triage-order",
      "domain": "storage",
      "expected_ordering": [["example-s3-public"], ["example-s3-locked"]],
      "rationale": "A world-readable bucket holding regulated data must be triaged before the same bucket with public access blocked.",
      "oracle": {
        "author": "258243J",
        "reviewer": "supervisor",
        "registered_at": "2026-09-19T00:00:00Z",
        "reviewer_verdict": "partial",
        "disagreement_note": "Reviewer agrees on the ordering but would place the locked bucket in Low rather than Medium; recorded as oracle uncertainty on the band, not on the order."
      }
    }
  ]
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```
uv run pytest tests/test_ground_truth.py -q
uv run pytest tests/test_architecture.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Expected: `tests/test_ground_truth.py` passes; `test_eval_does_not_import_scoring` still passes; ruff clean; mypy `Success`.

- [ ] **Step 7: Commit**

```bash
git add eval/ground_truth.schema.json eval/ground_truth.py eval/ground_truth/example.json tests/test_ground_truth.py
git commit -m "S1: evaluation ground-truth schema and rejecting validator

Three record types, never merged. Schema checks shape; the validator adds the
cross-record semantics JSON Schema cannot express - id uniqueness, pair and
scenario references resolving to real cases, and oracle author != reviewer.
A missing or ill-formed expected block is a hard reject, never a skip."
```

---

## Task 5: Canonical-identity module (Terraform + Kubernetes)

Implements spec §5. This is the identity the context-join (Q4) and dedupe (Q8) key on.

**Files:**
- Create: `src/iacrisk/identity.py`
- Test: `tests/test_identity.py`

**Interfaces:**
- Consumes: nothing. Pure string formatting, no I/O, no scanner coupling.
- Produces, relied on by Task 6:
  - `UNRESOLVED: str` = `"<unresolved>"`
  - `DEFAULT_NAMESPACE: str` = `"default"`
  - `normalize_path(raw: str) -> str`
  - `is_templated(value: str) -> bool`
  - `terraform_identity(resource_type: str, resource_name: str, *, module_path: str = "", instance_key: str | int | None = None) -> str`
  - `kubernetes_identity(api_version: str, kind: str, name: str, *, namespace: str | None = None, container: str | None = None) -> str`
  - `dedupe_key(resource_identity: str, issue_class: str, fingerprint: str) -> tuple[str, str, str]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_identity.py`:

```python
"""Identity is defined for every resource shape corpus v0 actually contains (spec 5.5).

Path normalization is the load-bearing piece: Checkov emits mixed separators for
the same file across framework blocks, so without it the context-join silently
misses - and a silent miss is the worst failure mode available here.
"""

from __future__ import annotations

import pytest

from iacrisk import identity


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\\ec2.tf", "ec2.tf"),  # checkov's backslash spelling
        ("/ec2.tf", "ec2.tf"),  # checkov's forward-slash spelling of the same file
        ("ec2.tf", "ec2.tf"),  # and the bare one
        ("/resources\\Dockerfile", "resources/Dockerfile"),  # mixed in one path
        ("\\resources\\db\\main.tf", "resources/db/main.tf"),
        ("//double.tf", "double.tf"),
        ("", ""),
    ],
)
def test_normalize_path_collapses_every_observed_spelling(raw: str, expected: str) -> None:
    """Spec section 5.3: replace backslashes explicitly, then strip the leading separator.

    PurePosixPath does not translate backslashes on Windows, which is exactly why
    this is character replacement rather than a path-library call.
    """
    assert identity.normalize_path(raw) == expected


def test_the_three_observed_spellings_of_one_file_converge() -> None:
    """The property that matters: no single spelling per file can be assumed."""
    spellings = ["\\ec2.tf", "/ec2.tf", "ec2.tf"]

    assert len({identity.normalize_path(spelling) for spelling in spellings}) == 1


def test_terraform_root_module_resource_is_the_bare_address() -> None:
    """The shape the entire TF corpus exercises: 39 resource types, no modules."""
    assert identity.terraform_identity("aws_s3_bucket", "data") == "aws_s3_bucket.data"


def test_terraform_count_index_is_rendered_unquoted() -> None:
    """The one instance-key case in corpus v0: aws_neptune_cluster_instance.default."""
    result = identity.terraform_identity(
        "aws_neptune_cluster_instance", "default", instance_key=0
    )

    assert result == "aws_neptune_cluster_instance.default [0]"


def test_terraform_for_each_key_is_rendered_quoted() -> None:
    """Quoting is what keeps count index 0 distinct from for_each key "0"."""
    counted = identity.terraform_identity("aws_s3_bucket", "b", instance_key=0)
    keyed = identity.terraform_identity("aws_s3_bucket", "b", instance_key="0")

    assert counted == "aws_s3_bucket.b [0]"
    assert keyed == 'aws_s3_bucket.b ["0"]'
    assert counted != keyed


def test_terraform_module_path_disambiguates_duplicate_local_names() -> None:
    """Not exercised by corpus v0 - defined for robustness, and stated as such."""
    result = identity.terraform_identity(
        "aws_s3_bucket", "data", module_path="module.storage"
    )

    assert result == "module.storage :: aws_s3_bucket.data"


def test_terraform_unresolvable_instance_key_is_explicit() -> None:
    """Spec section 5.1: never silently merged into the un-keyed identity."""
    result = identity.terraform_identity(
        "aws_instance", "web", instance_key=identity.UNRESOLVED
    )

    assert result == "aws_instance.web [<unresolved>]"
    assert result != identity.terraform_identity("aws_instance", "web")


def test_terraform_boolean_instance_key_is_rejected() -> None:
    """bool subclasses int; left alone it would render `[True]` and look deliberate."""
    with pytest.raises(TypeError, match="bool"):
        identity.terraform_identity("aws_s3_bucket", "b", instance_key=True)


def test_kubernetes_namespaced_identity() -> None:
    assert (
        identity.kubernetes_identity("apps/v1", "Deployment", "api", namespace="prod")
        == "apps/v1/Deployment/prod/api"
    )


@pytest.mark.parametrize("kind", ["Namespace", "ClusterRoleBinding", "ClusterPolicy"])
def test_kubernetes_cluster_scoped_kinds_omit_the_namespace_component(kind: str) -> None:
    """All three are present in the kubernetes-goat scenarios (spec section 5.5)."""
    result = identity.kubernetes_identity("v1", kind, "big-monolith")

    assert result == f"v1/{kind}/big-monolith"
    assert "//" not in result


def test_kubernetes_container_scoped_identity() -> None:
    """internal-proxy has two containers; health-check has an initContainer too."""
    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
    )

    assert result == "apps/v1/Deployment/default/internal-proxy [container=nginx]"


def test_two_containers_in_one_pod_get_distinct_identities() -> None:
    """Without the container component the multi-container pod collapses to one row."""
    first = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
    )
    second = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="proxy"
    )

    assert first != second


def test_kubernetes_omitted_namespace_uses_the_documented_default() -> None:
    """Spec section 5.2: an omitted metadata.namespace takes the documented default."""
    assert identity.DEFAULT_NAMESPACE == "default"

    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "api", namespace=identity.DEFAULT_NAMESPACE
    )

    assert result == "apps/v1/Deployment/default/api"


@pytest.mark.parametrize(
    "value",
    ["{{ .Release.Name }}", "{{ .Release.Name }}-db", "prefix-{{ .Values.env }}"],
)
def test_is_templated_detects_helm_interpolation(value: str) -> None:
    assert identity.is_templated(value)


@pytest.mark.parametrize("value", ["metadata-db", "default", "nginx", ""])
def test_is_templated_is_precise_not_merely_wide(value: str) -> None:
    assert not identity.is_templated(value)


def test_kubernetes_helm_templated_components_become_unresolved() -> None:
    """The metadata-db scenario: the K8s analogue of the TF dynamic-key case (5.2)."""
    result = identity.kubernetes_identity(
        "apps/v1",
        "Deployment",
        "{{ .Release.Name }}-metadata-db",
        namespace="{{ .Release.Namespace }}",
        container="{{ .Chart.Name }}",
    )

    assert result == "apps/v1/Deployment/<unresolved>/<unresolved> [container=<unresolved>]"


def test_a_partially_templated_resource_keeps_the_components_it_resolved() -> None:
    """Marking the whole identity unresolved would throw away real information."""
    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "{{ .Release.Name }}-db", namespace="prod"
    )

    assert result == "apps/v1/Deployment/prod/<unresolved>"


def test_dedupe_key_is_the_three_spec_components() -> None:
    """Spec section 5.4: (resource identity, normalized issue class, fingerprint)."""
    key = identity.dedupe_key(
        "aws_s3_bucket.data", "storage-encryption-at-rest", "server_side_encryption_configuration"
    )

    assert key == (
        "aws_s3_bucket.data",
        "storage-encryption-at-rest",
        "server_side_encryption_configuration",
    )


def test_cross_scanner_twins_on_one_resource_collapse_to_one_key() -> None:
    """The deduplication half of the Q7/Q8 alert-reduction number.

    trivy AWS-0026 and tfsec AVD-AWS-0026 are a verified twin pair in corpus v0
    and share the class storage-encryption-at-rest by the section 2.2
    co-location guarantee, so on one resource with one fingerprint they produce
    one key - which is what makes the reduction real rather than arithmetic.
    """
    trivy = identity.dedupe_key("aws_s3_bucket.data", "storage-encryption-at-rest", "sse")
    tfsec = identity.dedupe_key("aws_s3_bucket.data", "storage-encryption-at-rest", "sse")

    assert trivy == tfsec
    assert len({trivy, tfsec}) == 1


def test_different_violations_on_one_resource_stay_distinct() -> None:
    """The fingerprint is what stops two real problems collapsing into one row."""
    first = identity.dedupe_key(
        "aws_security_group.web", "networking-ingress-exposure", "ingress[0]"
    )
    second = identity.dedupe_key(
        "aws_security_group.web", "networking-ingress-exposure", "ingress[1]"
    )

    assert first != second


@pytest.mark.parametrize("position", [0, 1, 2])
def test_an_empty_dedupe_component_is_rejected(position: int) -> None:
    """An empty fingerprint would over-collapse exactly what section 5.4 protects."""
    parts = ["aws_s3_bucket.data", "storage-encryption-at-rest", "sse"]
    parts[position] = ""

    with pytest.raises(ValueError, match="empty"):
        identity.dedupe_key(*parts)
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_identity.py -q
```

Expected: collection error — `ModuleNotFoundError: No module named 'iacrisk.identity'`.

- [ ] **Step 3: Write the module**

Create `src/iacrisk/identity.py`:

```python
"""Canonical resource identity for Terraform and Kubernetes (design spec section 5).

This is the identity the context-join (PLAN Q4) and the dedupe key (Q8) rest on.
Pure string formatting: no I/O, no scanner coupling, no parsing. Deciding whether
a value is resolvable belongs to the extractor in S3; this module's job is to
render an identity the same way every time, and to make an unresolved component
visible instead of letting it merge silently into a resolved one.
"""

from __future__ import annotations

UNRESOLVED = "<unresolved>"
"""An identity component that could not be resolved from literals.

First-class, never merged into the resolved form and never dropped. Its rate is
reported as the identity fallback rate (PLAN Q9).
"""

DEFAULT_NAMESPACE = "default"
"""Kubernetes' documented default when `metadata.namespace` is omitted.

Applied explicitly and flagged by the caller, rather than left blank - a blank
namespace component would make a namespaced resource look cluster-scoped.
"""


def normalize_path(raw: str) -> str:
    """Collapse a scanner-reported file path to one spelling (spec section 5.3).

    Checkov emits mixed separators for the same file across framework blocks -
    `\\ec2.tf` and `/ec2.tf`, `/resources\\Dockerfile` - so no single spelling per
    file can be assumed. Without this the context-join silently misses.

    Backslash translation is explicit character replacement on purpose:
    `PurePosixPath` does not treat a backslash as a separator, including on
    Windows, so a path library would leave `\\ec2.tf` intact.

    Leading separators are stripped with `lstrip`, which also folds the `//`
    form. These are scanner-emitted relative paths; no UNC or absolute path
    reaches this function.
    """
    return raw.replace("\\", "/").lstrip("/")


def is_templated(value: str) -> bool:
    """Whether a value carries Helm interpolation and so cannot be resolved statically."""
    return "{{" in value


def _resolved(value: str) -> str:
    return UNRESOLVED if is_templated(value) else value


def _render_instance_key(key: str | int) -> str:
    """Render a `count` index or a `for_each` key.

    Integers render bare and strings render quoted, which is what keeps a count
    index `[0]` distinct from a `for_each` key `["0"]`. `bool` is rejected rather
    than accepted as an `int` subclass: `[True]` would render cleanly and read as
    though someone meant it.
    """
    if isinstance(key, bool):
        raise TypeError(f"instance key must not be a bool, got {key!r}")
    if isinstance(key, int):
        return str(key)
    if key == UNRESOLVED:
        return UNRESOLVED
    return f'"{key}"'


def terraform_identity(
    resource_type: str,
    resource_name: str,
    *,
    module_path: str = "",
    instance_key: str | int | None = None,
) -> str:
    """Canonical Terraform identity: `<module_path> :: <type>.<name> [<instance_key>]`.

    `module_path` is empty for root-module resources, which render as the bare
    `type.name` Terraform itself uses; it is only present to disambiguate
    duplicate local names across modules. `instance_key` is the `for_each` key or
    `count` index where one exists, or `UNRESOLVED` for a dynamic key the
    extractor could not evaluate.

    Corpus v0 exercises the bare form (39 resource types, no modules, no
    `for_each`, no `moved`) and exactly one static `count = 1` index. The module
    and unresolved machinery is defined for robustness and is stated as untested
    by the corpus rather than implied stressed (spec section 5.5).
    """
    address = f"{resource_type}.{resource_name}"
    if module_path:
        address = f"{module_path} :: {address}"
    if instance_key is None:
        return address
    return f"{address} [{_render_instance_key(instance_key)}]"


def kubernetes_identity(
    api_version: str,
    kind: str,
    name: str,
    *,
    namespace: str | None = None,
    container: str | None = None,
) -> str:
    """Canonical Kubernetes identity: `<apiVersion>/<kind>/<namespace>/<name> [container=...]`.

    `namespace=None` omits the component entirely, which is how cluster-scoped
    kinds are written - `Namespace`, `ClusterRoleBinding` and `ClusterPolicy` are
    all present in the corpus. A namespaced resource whose `metadata.namespace`
    was omitted should be passed `DEFAULT_NAMESPACE` explicitly by the caller,
    not `None`.

    `container` distinguishes container-scoped findings inside a multi-container
    pod or an initContainer; without it those findings would collapse onto the
    workload and dedupe would lose them.

    Helm-templated components become `UNRESOLVED` individually, so a partially
    templated resource keeps the components that did resolve.
    """
    parts = [_resolved(api_version), _resolved(kind)]
    if namespace is not None:
        parts.append(_resolved(namespace))
    parts.append(_resolved(name))
    rendered = "/".join(parts)
    if container is not None:
        rendered = f"{rendered} [container={_resolved(container)}]"
    return rendered


def dedupe_key(
    resource_identity: str, issue_class: str, fingerprint: str
) -> tuple[str, str, str]:
    """The Q8 dedupe key (spec section 5.4).

    `(canonical resource identity, normalized issue class, violation fingerprint)`.
    The fingerprint is the specific affected attribute or config path - one IAM
    action, one security-group ingress rule, one Kubernetes container field - so
    materially different violations on one resource are not collapsed into a
    single row.

    Cross-scanner collapsing falls out of this: a trivy rule and its tfsec twin
    share a class by the section 2.2 co-location guarantee, so on one resource
    with one fingerprint they produce one key. Scanner provenance is retained as
    metadata by the caller, never as part of the key.

    Every component must be non-empty. An empty fingerprint would over-collapse
    exactly what this key exists to keep apart, and an empty identity or class
    would merge unrelated findings - so both raise rather than producing a key
    that silently under-counts.
    """
    for label, value in (
        ("resource_identity", resource_identity),
        ("issue_class", issue_class),
        ("fingerprint", fingerprint),
    ):
        if not value:
            raise ValueError(
                f"dedupe key component {label!r} is empty; an empty component would "
                "collapse findings this key exists to keep distinct"
            )
    return (resource_identity, issue_class, fingerprint)
```

- [ ] **Step 4: Run the tests to verify they pass**

```
uv run pytest tests/test_identity.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Expected: all `tests/test_identity.py` tests pass; ruff clean; mypy `Success`.

- [ ] **Step 5: Commit**

```bash
git add src/iacrisk/identity.py tests/test_identity.py
git commit -m "S1: canonical-identity module for Terraform and Kubernetes

Identity for every resource shape corpus v0 contains, plus the explicit
<unresolved> path for dynamic for_each keys and Helm-templated components.
Path normalization is explicit character replacement - PurePosixPath does not
translate backslashes on Windows, which is the silent context-join miss."
```

---

## Task 6: Close the S1 acceptance gates and freeze

Turns the five gates from spec §6 into tests, records what S1 deliberately defers, and updates the repo's stated current state. Nothing new is designed here.

**Files:**
- Create: `tests/test_s1_gates.py`
- Modify: `CLAUDE.md` (the "Current state" section)
- Modify: `docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md` (status line only)

**Interfaces:**
- Consumes: `iacrisk.taxonomy`, `iacrisk.rubric`, `iacrisk.identity`, `eval.ground_truth` — all as defined in Tasks 1–5.
- Produces: nothing new. This task only asserts.

- [ ] **Step 1: Write the gate tests**

Create `tests/test_s1_gates.py`:

```python
"""The five S1 acceptance gates, as tests rather than as a claim in a report.

Each gate's docstring quotes PLAN.md verbatim where PLAN states one. A gate
asserted here is one the artifacts actually support; a gate PLAN states that S1
cannot yet meet is recorded in `test_deferred_gate_items_are_named` rather than
quietly counted as met (the section G3 defect class).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.ground_truth import GroundTruthError, load_and_validate, validate
from iacrisk import identity, rubric, taxonomy

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_gate_1_every_emitted_rule_id_maps_and_all_five_categories_are_covered() -> None:
    """The PLAN.md gate, verbatim:

    "Every rule ID emitted by the pinned scanner versions across the corpus maps
    to an issue-class or an explicit `unmapped:` entry (measured mapping
    completeness); taxonomy covers all five tested categories."
    """
    inventory = json.loads(
        (REPO_ROOT / "artifacts" / "rule-inventory.json").read_text(encoding="utf-8")
    )
    observed = [
        (scanner, rule_id)
        for scanner, block in inventory["by_scanner"].items()
        for rule_id in block["rule_ids"]
    ]
    class_ids = set(taxonomy.classes())

    resolved = [taxonomy.class_for(scanner, rule_id) for scanner, rule_id in observed]
    assert len(resolved) == 255
    assert all(class_id in class_ids for class_id in resolved)
    assert not any(taxonomy.is_unmapped(class_id) for class_id in resolved)

    covered = {issue_class.category for issue_class in taxonomy.classes().values()}
    assert covered == set(taxonomy.CATEGORIES)


def test_gate_2_every_rubric_score_point_is_anchored_and_the_model_is_additive() -> None:
    """Spec section 3.6: anchors cite CVSS/NIST/NSA-CISA/OWASP, each score point
    justifiable; the equal-weighted additive sum is the primary model; weighting
    is a tunable framed as sensitivity analysis.
    """
    anchors = ("CVSS", "NIST", "NSA", "OWASP", "FIPS")
    for factor in rubric.factors().values():
        for level in factor.levels:
            assert any(anchor in level.source for anchor in anchors)
            assert level.justification.strip()

    assert rubric.model()["formula"] == (
        "Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk"
    )
    assert rubric.model()["equal_weighted"] is True
    assert "sensitivity analysis" in rubric.model()["weighting"]


def test_gate_3_severity_normalizes_per_scanner_with_explicit_unknown_routing() -> None:
    """Spec section 3.3, which is what makes the raw-severity baseline comparable."""
    table = rubric.severity_normalization()

    assert set(table["per_scanner"]) == {"checkov", "trivy", "tfsec"}
    assert rubric.normalize_severity("trivy", "CRITICAL") == 5
    assert rubric.normalize_severity("trivy", "UNKNOWN") == rubric.UNKNOWN
    assert rubric.normalize_severity("checkov", None) == rubric.UNKNOWN
    assert table["unknown_resolves_to"] == rubric.unresolved_default("severity")


def test_gate_4_the_schema_validates_good_records_and_rejects_bad_ones() -> None:
    """The PLAN.md gate, verbatim:

    "Schema validates on all corpus cases; harness rejects a case with
    missing/ill-formed expected outputs rather than skipping it."

    The reject half is asserted here in full. The "all corpus cases" half is
    asserted against the committed exemplar, because the corpus ground truth
    itself is authored in S2 against this schema - see
    `test_deferred_gate_items_are_named`.
    """
    document = load_and_validate(REPO_ROOT / "eval" / "ground_truth" / "example.json")
    assert document["cases"]

    broken = json.loads(json.dumps(document))
    del broken["cases"][0]["expected"]
    with pytest.raises(GroundTruthError):
        validate(broken)


def test_gate_5_every_corpus_resource_shape_has_a_defined_identity() -> None:
    """The PLAN.md gate, verbatim:

    "Identity is defined for every resource/instance shape present in the
    corpus (module, `for_each`/`count`, namespace/kind)."

    One assertion per shape the spec section 5.5 inventory enumerates.
    """
    shapes = {
        # Terraform: the bare form, and the one static count index in the corpus.
        "tf-bare": identity.terraform_identity("aws_s3_bucket", "data"),
        "tf-count": identity.terraform_identity(
            "aws_neptune_cluster_instance", "default", instance_key=0
        ),
        "tf-module": identity.terraform_identity(
            "aws_s3_bucket", "data", module_path="module.storage"
        ),
        "tf-for-each": identity.terraform_identity("aws_s3_bucket", "b", instance_key="alpha"),
        "tf-unresolved": identity.terraform_identity(
            "aws_instance", "web", instance_key=identity.UNRESOLVED
        ),
        # Kubernetes: namespaced, cluster-scoped, container-scoped, and templated.
        "k8s-namespaced": identity.kubernetes_identity(
            "apps/v1", "Deployment", "api", namespace="prod"
        ),
        "k8s-cluster-scoped": identity.kubernetes_identity("v1", "Namespace", "big-monolith"),
        "k8s-container": identity.kubernetes_identity(
            "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
        ),
        "k8s-helm": identity.kubernetes_identity(
            "apps/v1", "Deployment", "{{ .Release.Name }}-db", namespace="{{ .Release.Namespace }}"
        ),
    }

    assert all(rendered for rendered in shapes.values())
    assert len(set(shapes.values())) == len(shapes), "two distinct shapes rendered identically"
    assert shapes["k8s-helm"].count(identity.UNRESOLVED) == 2


def test_the_model_and_bands_are_frozen_at_the_end_of_s1() -> None:
    """Spec section 0: ranges and bands freeze here, before any scoring output."""
    assert rubric.score_bounds() == (1, 28)
    assert [band.name for band in rubric.bands()] == ["Critical", "High", "Medium", "Low"]
    assert (rubric.band_for(22), rubric.band_for(21)) == ("Critical", "High")
    assert (rubric.band_for(16), rubric.band_for(15)) == ("High", "Medium")
    assert (rubric.band_for(9), rubric.band_for(8)) == ("Medium", "Low")


def test_deferred_gate_items_are_named() -> None:
    """What S1 ships as a contract and S3/S4 ship as enforcement.

    Naming these keeps the gate report honest: each item below is a spec
    requirement that needs a scoring engine S1 does not build, so S1 carries the
    rule as data and the later sub-project enforces it. A gate claimed without
    its enforcement would be a claim the artifact does not support.
    """
    rules = rubric.coherence_rules()

    assert "iam_governed_resource_inheritance" in rules  # spec 3.5(1), enforced in S3
    assert "unresolved_default_reporting" in rules  # spec 3.5(2), enforced in S4
    assert "severity_context_fencing" in rules  # spec 3.5(3), enforced in S3

    # Spec 2.4: the unmapped: scoring behaviour ships as a contract here.
    fallback = taxonomy.fallback_contract()
    assert fallback["scoring"] == "severity-only, default context"
    assert fallback["excluded_from_prioritization_quality_claims"] is True
```

- [ ] **Step 2: Run the gate tests to verify they pass**

```
uv run pytest tests/test_s1_gates.py -q
```

Expected: all pass. A failure here is a real gate miss — fix the artifact, never the gate.

- [ ] **Step 3: Run the full suite and every check**

```
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

Expected: the whole suite green (S0's harvest tests included — S1 touches none of their inputs), ruff clean with 0 files to reformat, mypy `Success`.

- [ ] **Step 4: Update the repo's stated current state**

In `CLAUDE.md`, replace the "Current state" opening paragraph:

```markdown
S0 complete: a pinned toolchain plus an empirical rule-ID inventory over a
vendored corpus. Phase 1 (the five specification artifacts) is next — see
`docs/superpowers/specs/` and `docs/superpowers/plans/`.
```

with:

```markdown
S0 and S1 complete. S0 pinned the toolchain and harvested an empirical rule-ID
inventory over a vendored corpus. S1 authored the five specification artifacts the
runtime and the harness are built against:

- `src/iacrisk/data/taxonomy.json` — 28 issue classes over the five tested
  categories, plus one mapping row per observed `(scanner, rule_id)`. All 255
  rule IDs in corpus v0 map; an unseen rule takes an explicit
  `unmapped:<scanner>:<rule_id>` class rather than a guess.
- `src/iacrisk/data/rubric.json` — the six source-anchored factors, the frozen
  1–28 bounds and priority bands, the per-scanner severity-normalization table,
  and the four coherence rules from the design spec.
- `eval/ground_truth.schema.json` + `eval/ground_truth.py` — the three
  ground-truth record types and a validator that hard-rejects a malformed case
  rather than skipping it.
- `src/iacrisk/identity.py` — canonical Terraform and Kubernetes identity, path
  normalization, and the dedupe key.

**Factor ranges and priority bands are frozen** as of S1, before any scoring
output exists. Later movement is reported as sensitivity analysis (PLAN Q10),
never tuned to fit the test data. `tests/test_s1_gates.py` holds the five
acceptance gates and the freeze.

S3 is next: the scanner adapters under `src/iacrisk/scanners/`, the bounded
context extractor, and the scoring engine that enforces the coherence rules S1
carries as data.
```

- [ ] **Step 5: Correct two verified errata in the spec**

**Erratum 1 — §2.2 twin example.** The spec illustrates `canonical_id` with a twin pair that corpus v0 does not contain. Measured against `artifacts/rule-inventory.json`: there are exactly 45 trivy/tfsec twin pairs, and `AWS-0057`, `AWS-0082` and `AWS-0088` are the three tfsec-only rules — trivy never emits `AWS-0088`. The canonicalization rule itself is correct and unchanged; only the example is wrong. Leaving it is precisely the §G3 defect class the spec defines.

In `docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md` §2.2, replace:

```markdown
`canonical_id` strips a leading `AVD-`: trivy emits `AWS-0088`, tfsec emits `AVD-AWS-0088`, both are the same Aqua rule → `canonical_id = AWS-0088`.
```

with:

```markdown
`canonical_id` strips a leading `AVD-`: trivy emits `AWS-0026`, tfsec emits `AVD-AWS-0026`, both are the same Aqua rule → `canonical_id = AWS-0026`. (Corpus v0 holds 45 such twin pairs; `AWS-0057`, `AWS-0082` and `AWS-0088` are tfsec-only and have no trivy counterpart, so they canonicalize without pairing.)
```

**Erratum 2 — §3.4 misattributes a warning to phase0.** The spec's first §3.4 bullet calls the severity-level-1 defect "grave, and exactly the phase0 warning". Phase0 issued no such warning. Its §A.3 item 4 records that only four levels were observed across the 566 severity-carrying rows and then *hands the decision to S1*: "S1's normalization spec has to say what the fifth level is for, or drop to four." The defect was real and the correction stands; only the attribution is wrong — a citation the cited artifact does not support, which is §G3.

In §3.4, replace:

```markdown
- **Severity level-1 "informational" → UNKNOWN (grave, and exactly the phase0 warning).**
```

with:

```markdown
- **Severity level-1 "informational" → UNKNOWN (grave, and the question phase0 left to S1).** Phase0 §A.3 item 4 recorded only four observed levels and required S1 to "say what the fifth level is for, or drop to four"; it did not itself warn against reading the fifth level as informational. This bullet is that answer.
```

- [ ] **Step 6: Mark the spec approved**

In `docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md`, change the status line:

```markdown
**Status:** design, awaiting review-gate approval
```

to:

```markdown
**Status:** approved at the review gate; implemented by `docs/superpowers/plans/2026-09-19-s1-preimplementation-artifacts.md`
```

- [ ] **Step 7: Commit**

```bash
git add tests/test_s1_gates.py CLAUDE.md docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md
git commit -m "S1: close the five acceptance gates and freeze the model

Each gate from the design spec asserted as a test rather than claimed in prose,
with the three items that need a scoring engine named as deferred to S3/S4
rather than counted as met. Ranges and bands are frozen from here."
```

---

## Self-Review

Run against the spec with fresh eyes, as the writing-plans skill prescribes.

**1. Spec coverage.** Walked each spec section:

| Spec section | Covered by |
|---|---|
| §0 global constraints | Plan Global Constraints (verbatim) |
| §1.1–1.3 taxonomy structure, 28 classes, three rulings | Task 1 (the rulings are already baked into `s1_final.json`; Task 1 transcribes and Task 1's tests pin the counts) |
| §1.4 gate | Task 1 tests + Task 6 gate 1 |
| §2.1 mapping structure | Task 1 generator row schema |
| §2.2 `canonical_id`, co-location, dedupe key | Task 1 `canonical_rule_id` + twin test; dedupe in Task 5 |
| §2.3 provenance | Task 1 generator `provenance` block + per-row `confidence`/`note` |
| §2.4 `unmapped:` fallback | Task 1 `class_for`/`is_unmapped`/`fallback_contract` + the synthetic-unknown test |
| §3.1 verification provenance | Task 2 anchor test (the pass's output is the level text itself) |
| §3.2 six factors + unresolved policies | Task 2 |
| §3.3 severity normalization | Task 3 |
| §3.4 citation corrections | Carried in the level text Task 2 transcribes; the UNKNOWN correction is asserted in Task 3 |
| §3.5 three coherence resolutions | Task 2 `coherence_rules` block; enforcement deferred and named in Task 6 |
| §3.6 gate | Task 2 tests + Task 6 gate 2 |
| §4.1–4.4 three record types, ordering-primary | Task 4 schema |
| §4.5 gate | Task 4 reject tests + Task 6 gate 4 |
| §5.1–5.4 TF/K8s identity, path norm, dedupe | Task 5 |
| §5.5 gate | Task 5 tests + Task 6 gate 5 |
| §6 freeze | Task 6 |
| §7 open items | Resolved at the review gate (user approved); no task needed |

One gap found and closed during review: §3.5's three resolutions had no home, since enforcing them needs a scoring engine. Added the `coherence_rules` block to Task 2's generator so S1 ships them as data, and `test_deferred_gate_items_are_named` in Task 6 so the split is recorded rather than silently dropped.

**2. Placeholder scan.** No "TBD", no "add error handling", no "similar to Task N". Every code step carries runnable code; every test step carries the assertions. The two bulk data files are produced by complete generator scripts rather than hand-transcribed, which is a transformation, not a placeholder — the content's source (`scratch/s1_final.json`) is named, the transformation is fully specified, and the output's invariants are pinned by tests against a committed file.

**3. Type consistency.** Checked every name used across task boundaries:

- `canonical_rule_id(rule_id)` — one argument, no `scanner` parameter. Used consistently in Task 1's module, Task 1's tests, and nowhere else.
- `taxonomy.classes()` / `taxonomy.mapping()` return `MappingProxyType`, and the tests use only `len`, `in`, `.values()`, `[]` — all supported.
- `rubric.factors()[key]` returns `Factor` with `minimum`/`maximum` (not `min`/`max`, which would shadow builtins) — spelled the same in the generator's JSON keys, the dataclass, and the tests.
- `rubric.normalize_severity` returns `int | str`; every test compares against either an `int` or `rubric.UNKNOWN`, never assumes one branch.
- `rubric.unresolved_default(key)` (function) vs `Factor.unresolved_default` (attribute) — same name, different surfaces, both used in Task 2's and Task 3's tests. Intentional and consistent.
- `identity.UNRESOLVED` is the sentinel in both `terraform_identity` and `kubernetes_identity`; `DEFAULT_NAMESPACE` is used by the caller, not applied implicitly.
- `eval.ground_truth.validate` raises; `load_and_validate` returns the document. Task 6 uses both in the shapes Task 4 defines.
- Task 3 appends to `rubric.py` and `rubric.json` created in Task 2 — the only cross-task file modification, and it is additive, so Task 2's tests stay green (asserted explicitly in Task 3 Step 5).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-19-s1-preimplementation-artifacts.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.
