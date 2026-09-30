# S3b — Context Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach the five contextual attributes to every context-eligible normalized finding, each resolved to a level the frozen rubric defines or to an explicit unresolved state, with per-factor provenance and the reporting that makes the resolution rate measurable.

**Architecture:** A new package `src/iacrisk/context/`, mirroring the `scanners/` precedent. One module per factor, a shared Terraform reader, a shared `FactorValue` type that makes the unresolved branch unforgettable, an orchestrator, and a coverage reporter. Nothing S3a wrote is modified; the contextualized record wraps a `NormalizedFinding` rather than replacing it. No scoring — S3b resolves levels and records provenance; S4 does arithmetic.

**Tech Stack:** Python 3.12 (pinned by `.python-version`), uv, `python-hcl2>=8.1.4` (newly added), `pyyaml`, pytest, ruff, mypy (strict). Windows-native host.

**Spec:** `docs/superpowers/specs/2026-09-30-s3b-context-extraction-design.md` — read it before Task 1. It is the authority; this plan argues from it. Its §13 records eight decisions with cost-if-wrong, and its §10 holds the seven acceptance gates Task 9 implements.

## Global Constraints

Copied verbatim from the spec's §0.1. Every task's requirements implicitly include this section.

- **The rubric is the single source of truth for levels.** Resolve a factor *to a level the rubric defines*. Never invent a level, never interpolate between levels, never adjust a level's meaning. A construct the rubric's levels do not cover resolves to `unresolved`, not to the nearest-looking number.
- **The class routes; it never scores.** `severity_context_fencing`: the five context factors are instance-level deltas scored **only from resolved instance evidence** and are **never re-derived from the rule**; `class_id` is never a term in the score. Never set a factor level because of the `issue_class`. Gate 5 enforces this by mutation.
- **Literals only.** Interpolated, variable or computed values are `unresolved`. No graph resolve, no variable evaluation, no module instantiation.
- **`context_eligible = False` means skip extraction entirely** — no defaults, no unresolved markers, no context block at all.
- **`defaulted_factors` and `unresolved_factors` are never merged.** `sensitivity` and `criticality` can only be defaulted; `exposure`, `privilege` and `encryption` can only be unresolved.
- **Explicit-state discipline.** Nothing is ever silently defaulted to low or safe.
- **`python-hcl2` quirks, both silent if missed.** Block keys and string values **retain surrounding quotes** (`'"aws_security_group"'`, `'"0.0.0.0/0"'`) — strip them or match nothing. Interpolations arrive as literal `${...}` strings, so detecting unresolved is a `"${" in value` substring check.
- **Checkov stays an isolated `uv tool`** and must never become a project dependency.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — docstrings, comments, test names, commit messages. Measured facts carry their source.
- **Windows-native.** Always `uv run python`, never bare `python`. `uv run mypy` takes **no** path argument.
- **Judge pytest by exit code, never by grepping for `FAILED`.** `addopts` carries `-q --strict-markers -rs`, under which a failing test prints `F` and a traceback and emits no `FAILED` line.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/iacrisk/context/__init__.py` | Package marker; re-exports `FactorValue`, `FactorState`, `ContextualizedFinding`, `contextualize` |
| `src/iacrisk/context/value.py` | `FactorState`, `FactorValue`, and `scored_level` reading the rubric's `unresolved_default` |
| `src/iacrisk/context/terraform.py` | HCL loading, quote stripping, literal detection, and a Terraform resource index keyed on canonical identity |
| `src/iacrisk/context/declared.py` | The Q4 declared-context join and the IAM-governed-resource inheritance rule |
| `src/iacrisk/context/exposure.py` | The four supported exposure patterns, the precedence rule, target-not-rule attribution, enumerated bucket publicness |
| `src/iacrisk/context/privilege.py` | Policy-document parsing (heredoc and `jsonencode`), the action × resource level mapping, Kubernetes RBAC |
| `src/iacrisk/context/encryption.py` | Encryption-attribute reads, bounded at 2 for non-literal reads |
| `src/iacrisk/context/extract.py` | `ContextualizedFinding`, the orchestrator, the frozen low-confidence threshold |
| `src/iacrisk/context/coverage.py` | Per-factor defaulted and unresolved rates, resolution-rate distribution, per-class factor coverage |
| `tests/context/test_value.py` … `test_coverage.py` | One test module per source module |
| `tests/test_s3b_gates.py` | The seven acceptance gates from spec §10 |

`tests/context/__init__.py` is **not** created — `tests/paircand/` has none and must not gain one (see `tests/paircand/test_generate.py`'s header comment).

---

### Task 1: `FactorValue` — making the unresolved branch unforgettable

**Files:**
- Create: `src/iacrisk/context/__init__.py`, `src/iacrisk/context/value.py`
- Test: `tests/context/test_value.py`

**Interfaces:**
- Consumes: `iacrisk.rubric` — `rubric.factors()` returns a mapping keyed by factor `key` (`severity`, `exposure`, `privilege`, `sensitivity`, `criticality`, `encryption`), each with `.unresolved_default`, `.minimum`, `.maximum`.
- Produces: `FactorState` (StrEnum: `RESOLVED`, `DEFAULTED`, `UNRESOLVED`), `FactorValue` frozen dataclass with `key: str`, `level: int | None`, `state: FactorState`, `evidence: str`, a `scored_level: int` property, and three constructors `resolved()`, `defaulted()`, `unresolved()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_value.py
import pytest

from iacrisk.context.value import FactorState, FactorValue


def test_a_resolved_value_scores_its_own_level() -> None:
    v = FactorValue.resolved("exposure", 4, "cidr_blocks=0.0.0.0/0 at ec2.tf:77")
    assert v.state is FactorState.RESOLVED
    assert v.level == 4
    assert v.scored_level == 4


def test_an_unresolved_value_scores_the_rubric_default_and_keeps_level_none() -> None:
    """The rubric's exposure unresolved_default is 3. `level` stays None because no
    level was read; `scored_level` is what S4 does arithmetic on. Keeping them
    distinct is what lets the coverage report count unresolved factors without
    re-deriving them from a magic number.
    """
    v = FactorValue.unresolved("exposure", "cidr_blocks is ${aws_vpc.web_vpc.cidr_block}")
    assert v.state is FactorState.UNRESOLVED
    assert v.level is None
    assert v.scored_level == 3


def test_a_defaulted_value_scores_the_rubric_default() -> None:
    v = FactorValue.defaulted("criticality", "no declared-context match")
    assert v.state is FactorState.DEFAULTED
    assert v.level is None
    assert v.scored_level == 4


def test_every_factor_default_comes_from_the_rubric_not_a_literal() -> None:
    """Guards against a future hand-typed constant drifting from rubric.json. The
    five context defaults sum to 16, which is the washout spec section 1.1 measures.
    """
    keys = ("exposure", "privilege", "sensitivity", "criticality", "encryption")
    totals = sum(FactorValue.unresolved(k, "x").scored_level for k in keys)
    assert totals == 16


def test_a_level_outside_the_rubric_range_is_a_hard_error() -> None:
    with pytest.raises(ValueError, match="outside"):
        FactorValue.resolved("encryption", 4, "x")  # encryption maximum is 3


def test_an_unknown_factor_key_is_a_hard_error() -> None:
    with pytest.raises(KeyError):
        FactorValue.unresolved("not_a_factor", "x")


def test_evidence_is_required_and_non_empty() -> None:
    """Every factor value must say what it read and from where. An empty evidence
    string is how an unexplained level reaches the output JSON.
    """
    with pytest.raises(ValueError, match="evidence"):
        FactorValue.resolved("exposure", 4, "   ")
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `uv run pytest tests/context/test_value.py`
Expected: collection error — `ModuleNotFoundError: No module named 'iacrisk.context'`.

- [ ] **Step 3: Write the implementation**

```python
# src/iacrisk/context/value.py
"""The one type every factor resolution returns.

S1 handoff item 5 and S3a handoff item 2 both record the same trap: `normalize_severity`
returns `int | str`, so every call site must branch before arithmetic or a single
unguarded `+` concatenates or raises at runtime. S3b has five such factors, so the trap
is five times larger. This module is the boundary conversion both handoffs recommended:
callers read `scored_level` for arithmetic and `state` for reporting, and no call site
can accidentally add a string.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from iacrisk import rubric

__all__ = ["FactorState", "FactorValue"]


class FactorState(StrEnum):
    """Why a factor holds the value it holds.

    DEFAULTED and UNRESOLVED are deliberately distinct: PLAN Q4's missing declared
    value and PLAN Q9's extractor failure are reported as separate rates, and the
    ground-truth schema carries them as separate fields. Merging them makes that
    report impossible to reconstruct afterwards.
    """

    RESOLVED = "resolved"
    DEFAULTED = "defaulted"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class FactorValue:
    key: str
    level: int | None
    state: FactorState
    evidence: str

    @property
    def scored_level(self) -> int:
        """What S4 does arithmetic on: the read level, or the rubric's documented default.

        Never raises and never returns None, so an unguarded `+` at a scoring call site
        is impossible by construction rather than by discipline.
        """
        if self.level is not None:
            return self.level
        return int(rubric.factors()[self.key].unresolved_default)

    @staticmethod
    def _check(key: str, evidence: str) -> None:
        rubric.factors()[key]  # KeyError on an unknown factor key
        if not evidence.strip():
            raise ValueError(f"evidence is required for factor {key!r}")

    @classmethod
    def resolved(cls, key: str, level: int, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        factor = rubric.factors()[key]
        if not factor.minimum <= level <= factor.maximum:
            raise ValueError(
                f"level {level} is outside {key} range "
                f"{factor.minimum}-{factor.maximum}"
            )
        return cls(key=key, level=level, state=FactorState.RESOLVED, evidence=evidence)

    @classmethod
    def defaulted(cls, key: str, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        return cls(key=key, level=None, state=FactorState.DEFAULTED, evidence=evidence)

    @classmethod
    def unresolved(cls, key: str, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        return cls(key=key, level=None, state=FactorState.UNRESOLVED, evidence=evidence)
```

```python
# src/iacrisk/context/__init__.py
"""Layer 3 — context extraction (S3b, declared-context path only)."""

from iacrisk.context.value import FactorState, FactorValue

__all__ = ["FactorState", "FactorValue"]
```

- [ ] **Step 4: Confirm the rubric accessor (already verified — this is a regression guard)**

Run: `uv run python -c "from iacrisk import rubric; print(sorted(rubric.factors()))"`
Expected, measured on this tree 2026-09-30: `['criticality', 'encryption', 'exposure', 'privilege', 'sensitivity', 'severity']`. So `rubric.factors()` **is** keyed by factor `key`, and each factor carries `.key`, `.minimum`, `.maximum`, `.unresolved_default`, `.precedence_rule`, `.sensitivity_sweep`, `.unresolved_policy` and `.levels`. Task 1's implementation indexes it directly; no `by_key()` accessor is needed. If this ever prints human-readable names instead, stop and report rather than indexing by name.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_value.py`
Expected: 7 passed.

- [ ] **Step 6: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context tests/context/test_value.py
git commit -m "feat(s3b): FactorValue, converting the unresolved branch at the boundary"
```

---

### Task 2: The Terraform reader

**Files:**
- Create: `src/iacrisk/context/terraform.py`
- Test: `tests/context/test_terraform.py`

**Interfaces:**
- Consumes: `hcl2` (`hcl2.load(fileobj)`, `hcl2.loads(text)`); `iacrisk.identity` for canonical Terraform identity; `iacrisk.input` for file discovery.
- Produces: `unquote(value: str) -> str`; `is_literal(value: object) -> bool`; `TerraformResource` frozen dataclass with `identity: str`, `type: str`, `name: str`, `body: dict[str, object]`, `file_path: str`; `build_index(files: Iterable[Path], scan_root: Path) -> dict[str, TerraformResource]`; `attribute(resource, name) -> object | None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_terraform.py
from pathlib import Path

from iacrisk.context.terraform import (
    TerraformResource,
    attribute,
    build_index,
    is_literal,
    unquote,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def test_unquote_strips_the_quotes_python_hcl2_leaves_on() -> None:
    """Measured on python-hcl2 8.1.4 against this corpus: block keys and string
    values retain their surrounding quotes, so `'"aws_security_group"'` is what a
    caller actually receives. Every read strips them or matches nothing, silently.
    """
    assert unquote('"aws_security_group"') == "aws_security_group"
    assert unquote('"0.0.0.0/0"') == "0.0.0.0/0"
    assert unquote("already-bare") == "already-bare"
    assert unquote('"') == '"'  # a lone quote is not a quoted string


def test_is_literal_rejects_interpolation_anywhere_in_a_nested_value() -> None:
    """Literals-only (PLAN Q9). The nested-list case is the one that matters: the
    corpus case sgr-ingress-vpc-interpolated carries its interpolation inside a
    one-element list, so a top-level-only check would pass it as literal and score
    a resolved exposure from a value nobody resolved.
    """
    assert is_literal('"0.0.0.0/0"') is True
    assert is_literal(['"0.0.0.0/0"']) is True
    assert is_literal('"${aws_vpc.web_vpc.cidr_block}"') is False
    assert is_literal(['"${aws_vpc.web_vpc.cidr_block}"']) is False
    assert is_literal({"a": ['"${var.x}"']}) is False
    assert is_literal(True) is True
    assert is_literal(None) is True


def test_the_index_is_keyed_on_canonical_identity_over_the_real_corpus() -> None:
    files = sorted(TERRAGOAT.glob("*.tf"))
    index = build_index(files, TERRAGOAT)
    assert "aws_security_group.default" in index
    assert "aws_security_group_rule.ingress" in index
    assert "aws_security_group_rule.egress" in index
    sg = index["aws_security_group.default"]
    assert isinstance(sg, TerraformResource)
    assert sg.type == "aws_security_group"
    assert sg.name == "default"
    assert sg.file_path.endswith("db-app.tf")


def test_the_two_corpus_cidr_cases_are_distinguished_exactly_as_the_ground_truth_says() -> None:
    """corpus-v1.json's networking scenario rests on precisely this distinction:
    sgr-ingress-vpc-interpolated must be unresolved and sgr-egress-unrestricted must
    be a resolved 0.0.0.0/0. If this test fails, that scenario's expected ordering is
    unreproducible.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)

    ingress = attribute(index["aws_security_group_rule.ingress"], "cidr_blocks")
    assert is_literal(ingress) is False

    egress = attribute(index["aws_security_group_rule.egress"], "cidr_blocks")
    assert is_literal(egress) is True
    assert [unquote(c) for c in egress] == ["0.0.0.0/0"]


def test_attribute_returns_none_for_an_absent_attribute() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    assert attribute(index["aws_security_group.default"], "no_such_attribute") is None


def test_an_unparseable_file_is_skipped_and_named_not_raised(tmp_path: Path) -> None:
    """S3a's retention report already counts unparseable files as an unresolved cause.
    A parse failure here must not abort the whole index, or one malformed file in a
    corpus removes every resource in it from context extraction.
    """
    good = tmp_path / "good.tf"
    good.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n', encoding="utf-8")
    bad = tmp_path / "bad.tf"
    bad.write_text('resource "aws_s3_bucket" {{{ \n', encoding="utf-8")

    index = build_index([good, bad], tmp_path)
    assert "aws_s3_bucket.b" in index
    assert len(index) == 1
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_terraform.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.terraform'`.

- [ ] **Step 3: Write the implementation**

```python
# src/iacrisk/context/terraform.py
"""Reading Terraform resource bodies, literals only.

Two measured properties of python-hcl2 8.1.4 on this corpus drive this module:

1. Block keys and string values retain their surrounding quotes, so a caller gets
   `'"aws_security_group"'` and `'"0.0.0.0/0"'`. `unquote` is therefore applied on
   every read, not occasionally.
2. Interpolations arrive as literal `${...}` strings rather than being evaluated,
   which is exactly what PLAN Q9's literals-only rule needs: an unresolved value is
   a substring check, not an inference.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2

__all__ = ["TerraformResource", "attribute", "build_index", "is_literal", "unquote"]

INTERPOLATION = "${"


def unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def is_literal(value: object) -> bool:
    """False if an interpolation appears anywhere inside `value`, at any depth."""
    if isinstance(value, str):
        return INTERPOLATION not in value
    if isinstance(value, dict):
        return all(is_literal(k) and is_literal(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(is_literal(v) for v in value)
    return True


@dataclass(frozen=True, slots=True)
class TerraformResource:
    identity: str
    type: str
    name: str
    body: dict[str, Any]
    file_path: str


def build_index(
    files: Iterable[Path], scan_root: Path
) -> dict[str, TerraformResource]:
    """Map canonical Terraform identity to its resource body.

    A file that will not parse is skipped rather than raised, so one malformed file
    does not remove every other resource from context extraction. Its absence shows
    up as unresolved factors, which the coverage report counts.
    """
    index: dict[str, TerraformResource] = {}
    for path in files:
        try:
            with path.open(encoding="utf-8") as handle:
                document = hcl2.load(handle)
        except Exception:  # noqa: BLE001 - any parse failure is the same outcome here
            continue
        try:
            relative = path.relative_to(scan_root).as_posix()
        except ValueError:
            relative = path.name
        for block in document.get("resource", []):
            if not isinstance(block, dict):
                continue
            for raw_type, bodies in block.items():
                rtype = unquote(str(raw_type))
                if not isinstance(bodies, dict):
                    continue
                for raw_name, body in bodies.items():
                    rname = unquote(str(raw_name))
                    index[f"{rtype}.{rname}"] = TerraformResource(
                        identity=f"{rtype}.{rname}",
                        type=rtype,
                        name=rname,
                        body=body if isinstance(body, dict) else {},
                        file_path=relative,
                    )
    return index


def attribute(resource: TerraformResource, name: str) -> object | None:
    """One attribute off a resource body, or None when absent.

    Returns the raw hcl2 value, quotes and all. Callers decide whether to `unquote`
    a scalar or check `is_literal` first, because those are different questions.
    """
    if name in resource.body:
        return resource.body[name]
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_terraform.py`
Expected: 6 passed. If `test_an_unparseable_file_is_skipped` fails because `bad.tf` happens to parse, replace its content with a deliberately broken heredoc (`policy = <<EOF` with no terminator) and re-run.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/terraform.py tests/context/test_terraform.py
git commit -m "feat(s3b): Terraform reader with quote stripping and literal detection"
```

---

### Task 3: The declared-context join

**Files:**
- Create: `src/iacrisk/context/declared.py`
- Test: `tests/context/test_declared.py`

**Interfaces:**
- Consumes: `FactorValue` (Task 1); `TerraformResource`, `attribute`, `unquote`, `is_literal` (Task 2).
- Produces: `load_declared(path: Path) -> dict[str, dict[str, int]]`; `governed_target(resource: TerraformResource) -> str | None`; `join(identity: str, declared: Mapping[str, Mapping[str, int]], tf_index: Mapping[str, TerraformResource]) -> tuple[FactorValue, FactorValue]` returning `(sensitivity, criticality)` in that order.

**Requirements** (spec §3): exact match on canonical identity, no fuzzy matching, no fallback to a shorter key. A declared value outside 0–5 is a hard error, never a clamp. On no match both factors are `defaulted`. Resource-attached IAM findings inherit from the governed resource per the rubric's `iam_governed_resource_inheritance`; a pure account-level policy with no attachment does **not** inherit and defaults like any other unmatched resource.

The attachment attributes in scope, and nothing beyond them: `bucket` on `aws_s3_bucket_policy` / `aws_s3_bucket_acl` / `aws_s3_bucket_public_access_block`, and `role` on `aws_iam_role_policy`. An interpolated attachment value does not resolve.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_declared.py
import json
from pathlib import Path

import pytest

from iacrisk.context.declared import governed_target, join, load_declared
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.value import FactorState

DECLARED = {"aws_s3_bucket.data": {"sensitivity": 5, "criticality": 4}}


def _res(rtype: str, name: str, **body: object) -> TerraformResource:
    return TerraformResource(
        identity=f"{rtype}.{name}", type=rtype, name=name, body=dict(body), file_path="x.tf"
    )


def test_an_exact_identity_match_takes_the_declared_values() -> None:
    sensitivity, criticality = join("aws_s3_bucket.data", DECLARED, {})
    assert (sensitivity.state, sensitivity.level) == (FactorState.RESOLVED, 5)
    assert (criticality.state, criticality.level) == (FactorState.RESOLVED, 4)


def test_no_match_defaults_both_and_never_resolves() -> None:
    sensitivity, criticality = join("aws_s3_bucket.other", DECLARED, {})
    assert sensitivity.state is FactorState.DEFAULTED
    assert criticality.state is FactorState.DEFAULTED
    assert sensitivity.scored_level == 3
    assert criticality.scored_level == 4


def test_a_near_match_is_not_a_match() -> None:
    """No fuzzy matching and no fallback to a shorter key: a near-match join would
    attach one resource's business context to a different resource.
    """
    sensitivity, _ = join("aws_s3_bucket.data_2", DECLARED, {})
    assert sensitivity.state is FactorState.DEFAULTED


def test_a_declared_value_outside_the_rubric_range_is_a_hard_error() -> None:
    with pytest.raises(ValueError):
        join("aws_s3_bucket.x", {"aws_s3_bucket.x": {"sensitivity": 9, "criticality": 1}}, {})


def test_a_resource_attached_iam_finding_inherits_from_the_governed_resource() -> None:
    """The rubric's iam_governed_resource_inheritance rule. A bucket policy carries no
    business sensitivity of its own; the bucket it governs does.
    """
    tf = {"aws_s3_bucket_policy.p": _res("aws_s3_bucket_policy", "p", bucket='"data"')}
    sensitivity, criticality = join("aws_s3_bucket_policy.p", DECLARED, tf)
    assert (sensitivity.state, sensitivity.level) == (FactorState.RESOLVED, 5)
    assert (criticality.state, criticality.level) == (FactorState.RESOLVED, 4)
    assert "aws_s3_bucket.data" in sensitivity.evidence


def test_a_pure_account_level_policy_does_not_inherit_and_defaults() -> None:
    """Spec section 3.1: it keeps the band cap and is a stated limitation of the
    additive model. It gets no special value - it defaults like any unmatched resource.
    """
    tf = {"aws_iam_policy.admin": _res("aws_iam_policy", "admin", policy='"{}"')}
    sensitivity, _ = join("aws_iam_policy.admin", DECLARED, tf)
    assert sensitivity.state is FactorState.DEFAULTED


def test_an_interpolated_attachment_does_not_resolve() -> None:
    tf = {"aws_s3_bucket_policy.p": _res("aws_s3_bucket_policy", "p", bucket='"${var.b}"')}
    assert governed_target(tf["aws_s3_bucket_policy.p"]) is None
    sensitivity, _ = join("aws_s3_bucket_policy.p", DECLARED, tf)
    assert sensitivity.state is FactorState.DEFAULTED


def test_governed_target_builds_a_canonical_identity_not_a_bare_name() -> None:
    assert governed_target(_res("aws_s3_bucket_policy", "p", bucket='"data"')) == (
        "aws_s3_bucket.data"
    )
    assert governed_target(_res("aws_iam_role_policy", "rp", role='"ec2role"')) == (
        "aws_iam_role.ec2role"
    )
    assert governed_target(_res("aws_s3_bucket", "b")) is None


def test_load_declared_reads_the_corpus_shape(tmp_path: Path) -> None:
    """corpus-v1.json carries declared_context as identity -> {sensitivity, criticality}."""
    path = tmp_path / "declared.json"
    path.write_text(json.dumps(DECLARED), encoding="utf-8")
    assert load_declared(path) == DECLARED
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_declared.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.declared'`.

- [ ] **Step 3: Write the implementation**

```python
# src/iacrisk/context/declared.py
"""The PLAN Q4 declared-context join.

Sensitivity and criticality are not recoverable from IaC source, so they enter by
declaration. A missing declared value takes a documented default and is counted in the
default-fallback rate - which is PLAN Q4's path and is deliberately distinct from
PLAN Q9's extractor `unresolved` state.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from iacrisk.context.terraform import TerraformResource, attribute, is_literal, unquote
from iacrisk.context.value import FactorValue

__all__ = ["governed_target", "join", "load_declared"]

# Attachment attributes in scope, and nothing beyond them (spec section 3.1): the
# attribute naming the governed resource, and the resource type that name refers to.
_ATTACHMENTS: dict[str, tuple[str, str]] = {
    "aws_s3_bucket_policy": ("bucket", "aws_s3_bucket"),
    "aws_s3_bucket_acl": ("bucket", "aws_s3_bucket"),
    "aws_s3_bucket_public_access_block": ("bucket", "aws_s3_bucket"),
    "aws_iam_role_policy": ("role", "aws_iam_role"),
}


def load_declared(path: Path) -> dict[str, dict[str, int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"declared context at {path} is not an object")
    return data


def governed_target(resource: TerraformResource) -> str | None:
    """The canonical identity of the resource this one governs, or None.

    Returns None for a type with no attachment in scope, for an absent attribute, and
    for an interpolated value - the last because a literals-only read cannot know what
    `${var.b}` names.
    """
    entry = _ATTACHMENTS.get(resource.type)
    if entry is None:
        return None
    attr_name, target_type = entry
    raw = attribute(resource, attr_name)
    if raw is None or not is_literal(raw):
        return None
    if isinstance(raw, list):
        if len(raw) != 1:
            return None
        raw = raw[0]
    if not isinstance(raw, str):
        return None
    return f"{target_type}.{unquote(raw)}"


def join(
    identity: str,
    declared: Mapping[str, Mapping[str, int]],
    tf_index: Mapping[str, TerraformResource],
) -> tuple[FactorValue, FactorValue]:
    """Resolve (sensitivity, criticality) for one finding's resource identity."""
    entry = declared.get(identity)
    source = identity
    if entry is None:
        resource = tf_index.get(identity)
        if resource is not None:
            target = governed_target(resource)
            if target is not None and target in declared:
                entry = declared[target]
                source = target

    if entry is None:
        reason = f"no declared-context match for {identity}"
        return (
            FactorValue.defaulted("sensitivity", reason),
            FactorValue.defaulted("criticality", reason),
        )

    evidence = f"declared context for {source}"
    values: list[FactorValue] = []
    for key in ("sensitivity", "criticality"):
        raw = entry.get(key)
        if raw is None:
            values.append(FactorValue.defaulted(key, f"{key} absent in {evidence}"))
            continue
        if not isinstance(raw, int) or isinstance(raw, bool):
            raise ValueError(f"declared {key} for {source} is not an integer: {raw!r}")
        values.append(FactorValue.resolved(key, raw, evidence))
    return (values[0], values[1])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_declared.py`
Expected: 9 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/declared.py tests/context/test_declared.py
git commit -m "feat(s3b): declared-context join with IAM-governed inheritance"
```

---

### Task 4: The exposure extractor

**Files:**
- Create: `src/iacrisk/context/exposure.py`
- Test: `tests/context/test_exposure.py`

**Interfaces:**
- Consumes: `FactorValue` (Task 1); `TerraformResource`, `attribute`, `is_literal`, `unquote` (Task 2); `iacrisk.finding.NormalizedFinding`; `iacrisk.rubric` for the `precedence_rule` text.
- Produces: `ANY_SOURCE_CIDRS: frozenset[str]`; `is_public_cidr(cidr: str) -> bool`; `extract(finding: NormalizedFinding, tf_index: Mapping[str, TerraformResource]) -> FactorValue`.

**Requirements** (spec §4). Read §4.1–§4.5 before starting; the rulings there are not re-derivable from the rubric alone.

- The closed pattern list is exactly four patterns. Anything outside → `unresolved`, never low.
- **Precedence (§4.2):** a `0.0.0.0/0` or `::/0` **ingress** opening forces level ≥ 4, asserted after resolution inside the extractor. **Correction:** an earlier version of this line said the extractor reads the rule from `rubric.json` "so the rule cannot drift from the artifact". It does not — `exposure.py` imports no rubric, and the threshold is a module literal. Only gate 4 reads `precedence_rule`, and spec §4.2 was amended during implementation to drop the same claim. Treat drift between the artifact and the extractor's literal as a real risk that nothing currently catches.
- **Attribution (§4.3):** exposure is attributed to the target, not the rule resource. **Attribution changes the factor, never the identity** — do not rewrite `resource_identity`, or S3a's dedupe separation of rule-level from target-level findings is undone.
- **NodePort → 2** (§4.5), firewall assumption in the evidence string.
- **CIDR (§4.5):** any public non-RFC1918 CIDR with a non-zero prefix → 2; `0.0.0.0/0` or `::/0` → 4; RFC1918-only ingress → 1.
- **Bucket publicness (§4.4):** level 5 requires public-access-block disabled **plus** a public ACL or public policy statement. A partial or cross-resource combination outside the enumeration → `unresolved`, not private.

> **Corrected 2026-09-30 during implementation.** The test below originally asserted
> that `aws_security_group_rule.egress` forces exposure >= 4, and that was wrong: that
> rule's `type` is `"egress"`, exposure is inbound reachability, and corpus-v1's
> networking scenario places the case in its bottom tier. Two further states the original
> did not distinguish are now spec **decisions 10 and 11** (resolved-negative versus
> unresolved, and structural resolution of resource-address references). Read spec
> **section 4.2, 4.6 and 4.7** before implementing this task; the committed
> `tests/context/test_exposure.py` is the corrected form.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_exposure.py
from pathlib import Path

from iacrisk.context.exposure import extract, is_public_cidr
from iacrisk.context.terraform import build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def _finding(identity: str, issue_class: str = "networking-ingress-exposure") -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=3,
        platform="terraform",
        resource_identity=identity,
        identity_kind="terraform",
        file_path="db-app.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )


def test_is_public_cidr_separates_rfc1918_from_internet_routable() -> None:
    assert is_public_cidr("0.0.0.0/0") is True
    assert is_public_cidr("203.0.113.0/24") is True
    assert is_public_cidr("10.0.0.0/16") is False
    assert is_public_cidr("192.168.1.0/24") is False
    assert is_public_cidr("172.16.0.0/12") is False
    assert is_public_cidr("not-a-cidr") is False


def test_an_any_source_opening_forces_at_least_four() -> None:
    """Spec section 4.2's precedence rule, the one constraint identity-gating may
    never cross.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_security_group_rule.egress"), index)
    assert value.state is FactorState.RESOLVED
    assert value.level is not None and value.level >= 4


def test_an_interpolated_cidr_is_unresolved_and_never_low() -> None:
    """The corpus case sgr-ingress-vpc-interpolated. Unresolved routes to the rubric
    default 3, never to 0 or 1 - PLAN Q9's hard rule.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_security_group_rule.ingress"), index)
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 3


def test_an_unsupported_pattern_is_unresolved_not_zero() -> None:
    """A resource with no attribute in the closed pattern list. Scoring it 0 would
    assert 'no exposure surface', which the extractor has not established.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_db_parameter_group.default"), index)
    assert value.state is FactorState.UNRESOLVED


def test_a_missing_resource_is_unresolved() -> None:
    value = extract(_finding("aws_s3_bucket.not_in_the_index"), {})
    assert value.state is FactorState.UNRESOLVED


def test_extraction_never_rewrites_the_findings_identity() -> None:
    """Spec section 4.3: attribution changes the factor, never the identity. Rewriting
    it would undo S3a's dedupe separation of rule-level from target-level findings.
    """
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    finding = _finding("aws_security_group_rule.egress")
    extract(finding, index)
    assert finding.resource_identity == "aws_security_group_rule.egress"


def test_the_level_does_not_depend_on_the_issue_class() -> None:
    """severity_context_fencing, at the unit level. Gate 5 runs the corpus-wide form."""
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    a = extract(_finding("aws_security_group_rule.egress", "networking-ingress-exposure"), index)
    b = extract(_finding("aws_security_group_rule.egress", "networking-config-hygiene"), index)
    assert a.level == b.level
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_exposure.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.exposure'`.

- [ ] **Step 3: Write the implementation**

Write `src/iacrisk/context/exposure.py` implementing spec §4.1–§4.5. The core shape, with the pattern dispatch left to the implementer to complete against the spec's four patterns:

```python
# src/iacrisk/context/exposure.py
"""Public exposure, resolved only over PLAN Q9's closed supported-pattern list.

Exposure is the one factor whose unresolved policy is `sensitivity-analysed` rather
than conservative-scored: unresolved routes to 3 in the frozen primary model, and S5
sweeps [2, 5]. Everything outside the four supported patterns is unresolved, never low -
scoring 0 would assert "no exposure surface", which this extractor cannot establish.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping

from iacrisk.context.terraform import TerraformResource, attribute, is_literal, unquote
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding

__all__ = ["ANY_SOURCE_CIDRS", "extract", "is_public_cidr"]

ANY_SOURCE_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def is_public_cidr(cidr: str) -> bool:
    """True when `cidr` is internet-routable. Malformed input is not public."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return not network.is_private


def _cidr_level(cidrs: list[str]) -> tuple[int, str] | None:
    """(level, evidence) from a literal CIDR list, per spec section 4.5."""
    if any(c in ANY_SOURCE_CIDRS for c in cidrs):
        return 4, f"any-source opening {sorted(set(cidrs) & ANY_SOURCE_CIDRS)}"
    if any(is_public_cidr(c) for c in cidrs):
        public = [c for c in cidrs if is_public_cidr(c)]
        return 2, f"narrow public CIDR {public}"
    if cidrs:
        return 1, f"RFC1918-only ingress {cidrs}"
    return None
```

Complete the module with:

1. A `_from_cidr_attributes` branch reading `cidr_blocks` on `aws_security_group_rule` and nested `ingress` blocks on `aws_security_group`. A non-literal value returns `FactorValue.unresolved`.
2. A `_from_public_flag` branch for `publicly_accessible`, `associate_public_ip_address`, and `map_public_ip_on_launch` → level 3.
3. A `_from_bucket_publicness` branch implementing §4.4's enumeration: level 5 only on public-access-block disabled **plus** a public ACL or policy; a partial combination → `unresolved`.
4. `extract()` dispatching over the branches in a fixed order, returning the **highest** resolved level found, and asserting the §4.2 precedence invariant before returning: if any evidence names an any-source CIDR, `level >= 4` or raise `AssertionError`.
5. `FactorValue.unresolved(...)` when no branch resolves, with evidence naming which patterns were tried.

Kubernetes `Service` and `Ingress` handling is a separate branch taking the Kubernetes index; add it in this task with `NodePort → 2` (evidence must record the node-firewall assumption per §4.5), `LoadBalancer → 3`, `ClusterIP → 1`, and `Ingress → 3`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_exposure.py`
Expected: 7 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/exposure.py tests/context/test_exposure.py
git commit -m "feat(s3b): exposure extractor over the closed pattern list"
```

---

### Task 5: The privilege extractor

**Files:**
- Create: `src/iacrisk/context/privilege.py`
- Test: `tests/context/test_privilege.py`

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: `parse_policy_document(raw: object) -> dict[str, object] | None`; `action_services(actions: list[str]) -> set[str]`; `privilege_level(actions: list[str], resources: list[str]) -> int`; `extract(finding, tf_index) -> FactorValue`.

**Requirements** (spec §5). **Read §5.4 before writing any code** — the action × resource mapping table is a correctness requirement, not a preference, and getting it wrong silently costs the corpus one of its two privilege mechanism pairs.

Two policy-document forms exist in this corpus and neither is plain JSON. Both were measured:

- **Heredoc** (`aws_iam_role_policy.ec2policy`): the value is `'"<<EOF\n{...}\nEOF"'`. Strip the outer quotes, match `^<<-?(\w+)\n(.*)\n\1\s*$` with `re.S`, then `json.loads` the body. Yields clean unquoted values.
- **`jsonencode`** (`corpus/authored/iam_privilege.tf`): the value is `'${jsonencode({Version = "2012-10-17", Statement = [...]})}'`. This is HCL object syntax, not JSON, so `json.loads` fails. Match `^\$\{\s*jsonencode\((.*)\)\s*\}$` with `re.S` and re-parse the inner text with `hcl2.loads("x = " + inner)["x"]`. Values come back **with quotes retained**, so `unquote` every action and resource string.

Anything else — a bare `${var.policy}`, a `data.aws_iam_policy_document` reference, a managed-policy ARN — returns `None`, which the caller turns into `FactorValue.unresolved`.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_privilege.py
from pathlib import Path

from iacrisk.context.privilege import (
    action_services,
    extract,
    parse_policy_document,
    privilege_level,
)
from iacrisk.context.terraform import build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
AUTHORED = REPO_ROOT / "corpus" / "authored"

HEREDOC = (
    '"<<EOF\n{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n'
    '      "Action": [\n        "s3:*",\n        "ec2:*",\n        "rds:*"\n      ],\n'
    '      "Effect": "Allow",\n      "Resource": "*"\n    }\n  ]\n}\nEOF"'
)
JSONENCODE = (
    '${jsonencode({Version = "2012-10-17", Statement = '
    '[{Effect = "Allow", Action = ["s3:*"], Resource = "*"}]})}'
)


def _finding(identity: str, issue_class: str = "iam-overpermissive-policy") -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1", issue_class=issue_class,
        title="t", remediation=None, native_severity=None, severity_level=3,
        platform="terraform", resource_identity=identity, identity_kind="terraform",
        file_path="x.tf", line_range=None, fingerprint=None, context_eligible=True,
    )


def test_a_heredoc_policy_parses_to_clean_unquoted_values() -> None:
    document = parse_policy_document(HEREDOC)
    assert document is not None
    statement = document["Statement"][0]
    assert statement["Action"] == ["s3:*", "ec2:*", "rds:*"]
    assert statement["Resource"] == "*"


def test_a_jsonencode_policy_parses_via_hcl2_reparse() -> None:
    """jsonencode carries HCL object syntax, not JSON, so json.loads fails on it."""
    document = parse_policy_document(JSONENCODE)
    assert document is not None
    statement = document["Statement"][0]
    assert statement["Action"] == ["s3:*"]
    assert statement["Resource"] == "*"


def test_an_opaque_policy_reference_does_not_parse() -> None:
    assert parse_policy_document('"${var.policy_json}"') is None
    assert parse_policy_document('"${data.aws_iam_policy_document.d.json}"') is None
    assert parse_policy_document(None) is None


def test_action_services_collapses_wildcards_and_prefixes() -> None:
    assert action_services(["s3:*"]) == {"s3"}
    assert action_services(["s3:GetObject", "s3:PutObject"]) == {"s3"}
    assert action_services(["s3:*", "ec2:*", "rds:*"]) == {"s3", "ec2", "rds"}
    assert action_services(["*"]) == {"*"}


def test_the_level_mapping_matches_spec_section_5_4_exactly() -> None:
    """Every corpus IAM case lands on a distinct level. If the first two collapse to
    one level, the pair privilege-iam-bucket-to-account stops isolating its factor -
    it would still pass on rank, for a reason fencing forbids.
    """
    assert privilege_level(["s3:*"], ["arn:aws:s3:::bucket/*"]) == 2
    assert privilege_level(["s3:*"], ["*"]) == 3
    assert privilege_level(["s3:*", "ec2:*", "rds:*"], ["*"]) == 4
    assert privilege_level(["*"], ["*"]) == 5


def test_the_three_authored_iam_cases_resolve_to_two_three_and_five() -> None:
    index = build_index(sorted(AUTHORED.glob("*.tf")), AUTHORED)
    levels = {
        name: extract(_finding(f"aws_iam_policy.{name}"), index).level
        for name in ("s3_bucket_scope", "s3_account_scope", "unrestricted_scope")
    }
    assert levels == {"s3_bucket_scope": 2, "s3_account_scope": 3, "unrestricted_scope": 5}


def test_the_vendored_heredoc_policy_resolves_to_four() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_iam_role_policy.ec2policy"), index)
    assert value.level == 4


def test_a_non_iam_resource_has_no_privilege_dimension() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_db_parameter_group.default"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_an_unparseable_policy_is_unresolved_and_scores_four() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_iam_role.ec2role"), index)
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 4


def test_an_unevaluated_condition_never_reduces_the_level() -> None:
    """Spec section 5.3. Treating a condition the extractor cannot evaluate as
    mitigating is the false-reassurance failure mode PLAN Q9 forbids.
    """
    with_condition = (
        '${jsonencode({Version = "2012-10-17", Statement = [{Effect = "Allow", '
        'Action = ["*"], Resource = "*", Condition = {StringEquals = {"aws:x" = "y"}}}]})}'
    )
    document = parse_policy_document(with_condition)
    assert document is not None
    statement = document["Statement"][0]
    assert privilege_level(statement["Action"], [statement["Resource"]]) == 5
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_privilege.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.privilege'`.

- [ ] **Step 3: Write the implementation**

Write `src/iacrisk/context/privilege.py`. `privilege_level` is the load-bearing function and its mapping is fixed by spec §5.4:

```python
def privilege_level(actions: list[str], resources: list[str]) -> int:
    """Action breadth AND resource breadth, jointly - spec section 5.4.

    Reading action breadth alone collapses an `s3:*`-on-one-bucket policy and an
    `s3:*`-on-`*` policy to the same level, which costs the corpus one of its two
    privilege mechanism pairs with no test failing. The rubric's L2 says "bounded
    resource set within a single service" and L3 says "full control of one service",
    so both clauses are read.
    """
    services = action_services(actions)
    unbounded_resource = any(r == "*" for r in resources)
    if "*" in services:
        return 5 if unbounded_resource else 4
    if not unbounded_resource:
        return 2 if any(a.endswith(":*") for a in actions) else 1
    return 4 if len(services) > 1 else 3
```

Complete the module with `parse_policy_document` (both forms per the Requirements above, `unquote`-ing every string it returns from the `jsonencode` branch), `action_services`, and `extract` which:

1. Returns `FactorValue.resolved(key="privilege", level=0, ...)` when the resource type has no privilege dimension — no `policy`, `assume_role_policy`, or RBAC `rules`.
2. Returns `FactorValue.unresolved` when a policy attribute exists but `parse_policy_document` returns `None`, and for a managed-policy ARN attachment (spec §5.2, decision 6).
3. Collects `Action` and `Resource` across all `Statement` entries with `Effect == "Allow"`, normalizes each to a list, and returns the **maximum** `privilege_level` over the statements.
4. Handles Kubernetes RBAC in the same shape: `verbs: ["*"]` with `resources: ["*"]` → 5; `cluster-admin` in a `ClusterRoleBinding` `roleRef` → 5; `secrets` read cluster-wide, `pods/exec`, or `create`/`bind` on RBAC resources → 4.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_privilege.py`
Expected: 10 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/privilege.py tests/context/test_privilege.py
git commit -m "feat(s3b): privilege extractor reading action and resource breadth jointly"
```

---

### Task 6: The encryption extractor

**Files:**
- Create: `src/iacrisk/context/encryption.py`
- Test: `tests/context/test_encryption.py`

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: `extract(finding, tf_index) -> FactorValue`.

**Requirements** (spec §6). Two constraints dominate:

- **A non-literal read can never reach 3** — level 3 needs positively-established mandate evidence, which a non-literal read cannot supply. It is bounded at 2.
- **The fencing constraint bites hardest here (§6.2).** Resolve from the resource's own `encrypted` / `kms_key_id` / `server_side_encryption_configuration` attributes, **never** from the fact that a rule named `storage-encryption-at-rest` fired. Where the attribute is absent, the answer is the platform's documented default if literal and knowable, and `unresolved` otherwise — not 2-because-the-scanner-complained.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_encryption.py
from pathlib import Path

from iacrisk.context.encryption import extract
from iacrisk.context.terraform import TerraformResource, build_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TERRAGOAT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"


def _finding(identity: str, issue_class: str = "storage-encryption-at-rest") -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1", issue_class=issue_class,
        title="t", remediation=None, native_severity=None, severity_level=3,
        platform="terraform", resource_identity=identity, identity_kind="terraform",
        file_path="x.tf", line_range=None, fingerprint=None, context_eligible=True,
    )


def _res(rtype: str, name: str, **body: object) -> TerraformResource:
    return TerraformResource(
        identity=f"{rtype}.{name}", type=rtype, name=name, body=dict(body), file_path="x.tf"
    )


def test_an_explicitly_encrypted_volume_scores_zero() -> None:
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=True)}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_an_explicitly_unencrypted_volume_scores_two() -> None:
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=False)}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 2)


def test_an_interpolated_encryption_flag_is_unresolved_and_scores_two() -> None:
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted='"${var.enc}"')}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert value.state is FactorState.UNRESOLVED
    assert value.scored_level == 2


def test_a_non_literal_read_never_reaches_three() -> None:
    """Spec section 6.1: level 3 requires positively-established mandate evidence."""
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted='"${var.enc}"')}
    value = extract(_finding("aws_ebs_volume.v"), index)
    assert value.level != 3
    assert value.scored_level <= 2


def test_the_level_does_not_come_from_the_issue_class() -> None:
    """Spec section 6.2, the fencing constraint's sharpest case. An encrypted volume
    scores 0 even when the finding's class is storage-encryption-at-rest.
    """
    index = {"aws_ebs_volume.v": _res("aws_ebs_volume", "v", encrypted=True)}
    a = extract(_finding("aws_ebs_volume.v", "storage-encryption-at-rest"), index)
    b = extract(_finding("aws_ebs_volume.v", "storage-logging-audit"), index)
    assert a.level == b.level == 0


def test_a_resource_with_no_data_at_rest_dimension_scores_zero() -> None:
    index = build_index(sorted(TERRAGOAT.glob("*.tf")), TERRAGOAT)
    value = extract(_finding("aws_security_group.default"), index)
    assert (value.state, value.level) == (FactorState.RESOLVED, 0)


def test_a_missing_resource_is_unresolved() -> None:
    value = extract(_finding("aws_ebs_volume.absent"), {})
    assert value.state is FactorState.UNRESOLVED
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_encryption.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.encryption'`.

- [ ] **Step 3: Write the implementation**

Write `src/iacrisk/context/encryption.py` with a table of data-bearing resource types mapped to the attribute that carries their encryption state — at minimum `aws_ebs_volume.encrypted`, `aws_db_instance.storage_encrypted`, `aws_s3_bucket.server_side_encryption_configuration`, `aws_sqs_queue.kms_master_key_id`. A type absent from the table has no data-at-rest dimension and resolves to 0. A type in the table whose attribute is absent or non-literal is `unresolved`. A literal truthy value is 0; a literal falsy value is 2.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_encryption.py`
Expected: 7 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/encryption.py tests/context/test_encryption.py
git commit -m "feat(s3b): encryption extractor reading instance attributes, not the class"
```

---

### Task 7: The orchestrator and the frozen low-confidence threshold

**Files:**
- Create: `src/iacrisk/context/extract.py`
- Modify: `src/iacrisk/context/__init__.py` (re-export `ContextualizedFinding`, `contextualize`)
- Test: `tests/context/test_extract.py`

**Interfaces:**
- Consumes: Tasks 1–6.
- Produces: `LOW_CONFIDENCE_THRESHOLD: int = 3`; `ContextualizedFinding` frozen dataclass with `finding`, the five `FactorValue` fields, and properties `defaulted_factors: tuple[str, ...]`, `unresolved_factors: tuple[str, ...]`, `low_confidence: bool`; `contextualize(findings, declared, tf_index) -> list[ContextualizedFinding]`.

**Requirements** (spec §2, §8.1). `context_eligible = False` findings are returned **without** a context block — represented as `ContextualizedFinding` with all five factors `None`, not as defaults or unresolved markers. `defaulted_factors` and `unresolved_factors` must be disjoint.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_extract.py
from iacrisk.context.extract import LOW_CONFIDENCE_THRESHOLD, contextualize
from iacrisk.finding import NormalizedFinding


def _finding(identity: str, *, eligible: bool = True) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1",
        issue_class="storage-encryption-at-rest", title="t", remediation=None,
        native_severity=None, severity_level=3, platform="terraform",
        resource_identity=identity, identity_kind="terraform", file_path="x.tf",
        line_range=None, fingerprint=None, context_eligible=eligible,
    )


def test_the_threshold_is_three_and_is_frozen() -> None:
    """Spec section 8.1, fixed 2026-09-30 before any scoring output existed. Later
    movement is reported as sensitivity analysis, never tuned to fit.
    """
    assert LOW_CONFIDENCE_THRESHOLD == 3


def test_a_context_ineligible_finding_gets_no_context_block_at_all() -> None:
    """Not defaults, not unresolved markers - nothing. Defaulting these re-opens the
    washout S3a closed with context_eligible.
    """
    (result,) = contextualize([_finding("aws_s3_bucket.x", eligible=False)], {}, {})
    assert result.exposure is None
    assert result.privilege is None
    assert result.sensitivity is None
    assert result.defaulted_factors == ()
    assert result.unresolved_factors == ()
    assert result.low_confidence is False


def test_defaulted_and_unresolved_are_disjoint_and_cover_what_did_not_resolve() -> None:
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    assert set(result.defaulted_factors) & set(result.unresolved_factors) == set()
    assert set(result.defaulted_factors) <= {"sensitivity", "criticality"}
    assert set(result.unresolved_factors) <= {"exposure", "privilege", "encryption"}


def test_a_finding_with_nothing_resolved_is_low_confidence() -> None:
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], {}, {})
    assert len(result.defaulted_factors) + len(result.unresolved_factors) >= 3
    assert result.low_confidence is True


def test_declared_context_removes_two_factors_from_the_defaulted_list() -> None:
    declared = {"aws_ebs_volume.absent": {"sensitivity": 5, "criticality": 5}}
    (result,) = contextualize([_finding("aws_ebs_volume.absent")], declared, {})
    assert result.defaulted_factors == ()
    assert result.sensitivity is not None and result.sensitivity.level == 5
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_extract.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.extract'`.

- [ ] **Step 3: Write the implementation**

Write `src/iacrisk/context/extract.py`. `LOW_CONFIDENCE_THRESHOLD = 3` carries a docstring naming spec §8.1, the freeze date, and the majority-of-evidence rationale. The five factor fields are `FactorValue | None`, with `None` meaning "not eligible for context" rather than "unresolved". `low_confidence` is `len(defaulted) + len(unresolved) >= LOW_CONFIDENCE_THRESHOLD`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/context/test_extract.py`
Expected: 5 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context tests/context/test_extract.py
git commit -m "feat(s3b): orchestrator and the frozen low-confidence threshold of 3"
```

---

### Task 8: Coverage reporting

**Files:**
- Create: `src/iacrisk/context/coverage.py`
- Test: `tests/context/test_coverage.py`

**Interfaces:**
- Consumes: Task 7.
- Produces: `ContextCoverage` frozen dataclass with `per_factor_defaulted: dict[str, int]`, `per_factor_unresolved: dict[str, int]`, `resolution_distribution: dict[int, int]` (keys 0–5), `low_confidence_count: int`, `per_class_coverage: dict[str, tuple[int, int]]` (findings, resolved-factor total); `build(results) -> ContextCoverage`; `to_json(coverage) -> dict[str, object]`.

**Requirements** (spec §8.2–§8.4). Per-factor rates are **never aggregated into one number**. `resolution_distribution` must have all six keys 0–5 present even when zero, so a consumer cannot mistake an absent key for an unmeasured one. `per_class_coverage` covers all 28 taxonomy classes — including classes with zero findings — because §8.4's purpose is to let S4 rule on the three classes that map to no rubric factor, and a class missing from the report is indistinguishable from a class with no findings.

- [ ] **Step 1: Write the failing test**

```python
# tests/context/test_coverage.py
from iacrisk import taxonomy
from iacrisk.context.coverage import build, to_json
from iacrisk.context.extract import contextualize
from iacrisk.finding import NormalizedFinding


def _finding(identity: str, issue_class: str, *, eligible: bool = True) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1", issue_class=issue_class,
        title="t", remediation=None, native_severity=None, severity_level=3,
        platform="terraform", resource_identity=identity, identity_kind="terraform",
        file_path="x.tf", line_range=None, fingerprint=None, context_eligible=eligible,
    )


def test_the_resolution_distribution_has_every_key_from_zero_to_five() -> None:
    """An absent key is indistinguishable from an unmeasured one."""
    results = contextualize([_finding("aws_ebs_volume.absent", "storage-encryption-at-rest")], {}, {})
    coverage = build(results)
    assert sorted(coverage.resolution_distribution) == [0, 1, 2, 3, 4, 5]


def test_per_factor_rates_are_separate_and_never_summed() -> None:
    results = contextualize([_finding("aws_ebs_volume.absent", "storage-encryption-at-rest")], {}, {})
    coverage = build(results)
    assert set(coverage.per_factor_defaulted) == {"sensitivity", "criticality"}
    assert set(coverage.per_factor_unresolved) == {"exposure", "privilege", "encryption"}


def test_every_taxonomy_class_appears_even_with_no_findings() -> None:
    """Spec section 8.4: S4 rules on the three classes that map to no rubric factor
    from this report, and a missing class reads as a class with no findings.
    """
    coverage = build([])
    assert set(coverage.per_class_coverage) == set(taxonomy.classes())
    assert len(coverage.per_class_coverage) == 28


def test_context_ineligible_findings_are_excluded_from_the_distribution() -> None:
    results = contextualize(
        [_finding("aws_s3_bucket.x", "storage-encryption-at-rest", eligible=False)], {}, {}
    )
    coverage = build(results)
    assert sum(coverage.resolution_distribution.values()) == 0


def test_to_json_is_serialisable_with_string_keys() -> None:
    import json

    coverage = build([])
    json.dumps(to_json(coverage))  # must not raise
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/context/test_coverage.py`
Expected: `ModuleNotFoundError: No module named 'iacrisk.context.coverage'`.

- [ ] **Step 3: Confirm the taxonomy accessor (already verified — this is a regression guard)**

Run: `uv run python -c "from iacrisk import taxonomy; print(len(taxonomy.classes()))"`
Expected, measured on this tree 2026-09-30: `28`. `taxonomy.classes()` exists and returns a mapping keyed by class id (for example `compute-instance-metadata-hardening`), so the test's `set(taxonomy.classes())` form is correct as written.

- [ ] **Step 4: Write the implementation, run tests, verify they pass**

Run: `uv run pytest tests/context/test_coverage.py`
Expected: 5 passed.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format . && uv run ruff check . && uv run mypy
git add src/iacrisk/context/coverage.py tests/context/test_coverage.py
git commit -m "feat(s3b): context coverage reporting, per-factor and per-class"
```

---

### Task 9: The seven acceptance gates

**Files:**
- Create: `tests/test_s3b_gates.py`
- Test: itself

**Interfaces:**
- Consumes: every prior task, plus `tests/harvest/fixtures/` (corpus v0 captures) and `tests/harvest/fixtures/authored/` (the three captures over `corpus/authored`).

Implement spec §10's seven gates. Follow `tests/test_s3a_gates.py` for structure and naming.

- [ ] **Step 1: Write the gates**

Gates 1–4, 6 and 7 are direct assertions. Gate 5 is the mutation gate and is the one that needs care:

```python
def test_gate_5_no_resolved_factor_level_depends_on_the_issue_class() -> None:
    """severity_context_fencing, by mutation rather than assertion.

    The constraint is that a change *cannot* have an effect, which a positive
    assertion cannot demonstrate. Substituting each finding's issue_class for another
    class in the same taxonomy category must leave every resolved factor level
    untouched. A difference is a fencing violation: the extractor read the class
    rather than the resource.
    """
    findings = _all_corpus_findings()
    baseline = contextualize(findings, _declared(), _tf_index())

    mutated_findings = [
        replace(f, issue_class=_other_class_in_same_category(f.issue_class))
        for f in findings
    ]
    mutated = contextualize(mutated_findings, _declared(), _tf_index())

    assert len(baseline) == len(mutated)
    for before, after in zip(baseline, mutated, strict=True):
        for key in ("exposure", "privilege", "sensitivity", "criticality", "encryption"):
            b = getattr(before, key)
            a = getattr(after, key)
            if b is None or a is None:
                assert b is None and a is None
                continue
            assert b.level == a.level, (
                f"{before.finding.resource_identity} {key}: {b.level} -> {a.level} "
                f"after class mutation - the extractor read the class, not the resource"
            )
```

`_other_class_in_same_category` must return a *different* class or the mutation is vacuous — assert that inside the helper, since a helper that silently returns the same class makes this gate pass unconditionally. That failure mode has occurred in this project before (S2's vacuous exclusion test).

- [ ] **Step 2: Run the gates**

Run: `uv run pytest tests/test_s3b_gates.py`
Expected: 7 passed. If gate 7 fails on `iam-s3-bucket-scope` and `iam-s3-account-scope` both resolving to 3, `privilege_level` is reading action breadth only — re-read spec §5.4.

- [ ] **Step 3: Run the whole suite and every gate command**

```bash
uv run pytest                     # judge by EXIT CODE, not by grepping for FAILED
uv run ruff check .
uv run ruff format --check .      # must report 0 files to reformat
uv run mypy                       # BARE, no path arguments
```

- [ ] **Step 4: Measure and record the resolution rate**

Run the coverage report over the committed fixtures and record the actual numbers in the commit message: the resolution distribution over 0–5, the low-confidence population, and the per-factor unresolved rates. **This is the number that says whether the framework can rank at all** (spec §1.1). If most findings land at 3 or more defaulted-or-unresolved factors, say so plainly in the report rather than reporting the gate as simply green — a green suite with a collapsed resolution rate is the outcome §1.1 warns about.

- [ ] **Step 5: Commit**

```bash
git add tests/test_s3b_gates.py
git commit -m "test(s3b): the seven acceptance gates, with fencing checked by mutation"
```

---

## Self-Review

**Spec coverage.** §2 → Tasks 1 and 7; §2.2 → Task 1; §2.3 → Tasks 4, 5, 6 unit tests plus gate 5; §3 and §3.1 → Task 3; §4.1–§4.5 → Task 4; §5.1–§5.4 → Task 5; §6.1–§6.2 → Task 6; §7 (no extraction for declared factors) → Task 3, and Task 7 asserts no tag logic exists by containing none; §8.1 → Task 7; §8.2–§8.4 → Task 8; §10's seven gates → Task 9. §0.1's global constraints are copied into this plan's Global Constraints and bind every task.

**Placeholder scan.** Tasks 4, 5, 6 and 8 give the load-bearing function bodies and tables in full and describe the remaining branches by their exact inputs and outputs rather than in prose. Every expected value in every test is a literal. No step says "similar to Task N".

**Type consistency.** `FactorValue` is constructed only through `resolved()`/`defaulted()`/`unresolved()` in every task. `build_index(files, scan_root)` keeps that signature in Tasks 2, 4, 5, 6 and 9. `extract(finding, tf_index)` is the signature in Tasks 4, 5 and 6; `join` returns `(sensitivity, criticality)` in that order in Tasks 3 and 7. The five factor fields are `FactorValue | None` in Task 7 and every consumer of them in Tasks 8 and 9 handles `None`.

**Three assumptions about code this plan did not write were verified before the plan was committed**, rather than left for an implementer to discover: `rubric.factors()` is keyed by factor `key` and exposes `.minimum`/`.maximum`/`.unresolved_default`/`.precedence_rule`/`.sensitivity_sweep`; `taxonomy.classes()` returns 28 entries keyed by class id; and `NormalizedFinding` is a frozen dataclass whose fields are exactly `scanner, rule_id, canonical_rule_id, issue_class, title, remediation, native_severity, severity_level, platform, resource_identity, identity_kind, file_path, line_range, fingerprint, context_eligible` — which is what every test constructor in this plan passes, and which makes `dataclasses.replace` available for gate 5's mutation. Task 1 Step 4 and Task 8 Step 3 remain as cheap regression guards with the measured answers recorded.

**One check this plan does not make, deliberately.** Nothing here verifies that the corpus's expected factor levels are *correct* — only that they are what spec §5.4 and the ground truth say. The privilege mapping was validated against all four corpus IAM cases before the spec was amended, but single-factor purity remains an authored judgement (S2 handoff), and gate 7 pins the mapping rather than proving it.
