# S3a — Detection & Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build pipeline layers 1–2 plus Q8 deduplication, producing a normalized, deduplicated finding set carrying an issue-class and normalized severity for every finding the three pinned scanners emit — with no contextual attributes, which are S3b's.

**Architecture:** Layer 1 discovers IaC files and classifies platform. A Kubernetes resource index is built by parsing manifests directly, because trivy supplies no resource identity for Kubernetes (0/332 measured) and checkov omits `apiVersion`. Three scanner adapters behind one protocol turn raw JSON into `NormalizedFinding`, joining S1's committed taxonomy and severity table without adding judgement. Dedupe is two-tier: only findings with both fingerprints resolved and equal collapse into the reported number; the rest are surfaced as candidate overlap, never merged. A retention report accounts for every input finding.

**Tech Stack:** Python 3.12, uv, pyyaml (already a dependency — no new ones), pytest, ruff, mypy strict. Windows-native.

**Spec:** `docs/superpowers/specs/2026-09-22-s3a-detection-normalization-design.md`

## Global Constraints

Copied from spec §0.1. Every task's requirements implicitly include this section.

- **Explicit-state discipline.** `unresolved`, `unmapped:`, `unknown`, `None` are first-class states in the record and output JSON. None is ever silently defaulted to low or safe (PLAN Q9). S3a adds one more: an **unresolved violation fingerprint** (`fingerprint is None`).
- **The taxonomy is the single source of truth.** Join against S1's committed `taxonomy.json` via `taxonomy.class_for`; never reclassify, extend or second-guess it. A rule absent from the table takes the `unmapped:` fallback.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — docstrings, comments, test names, commit messages. **This was the most common defect in S1: nine instances, every one inherited from the plan rather than introduced by an implementer.** If a test name claims more than its body checks, say so rather than shipping it.
- **Windows-native host.** Always `uv run python`. Path handling is explicit character work, never a path-library assumption.
- **Corpus v0 is a corpus observation, not a scanner contract.** Every count in this plan was measured against the committed fixtures on this host.
- **Harvest is not reusable.** `tools/harvest/` deliberately does not construct a normalized finding, and `tests/test_architecture.py::test_harvest_does_not_define_a_normalized_finding` enforces it. Do not import from it; re-derive anything shared.

Operational constraints:

- **Always `uv run python`** — bare `python` resolves to a broken Microsoft Store stub.
- **`uv run mypy` takes no path argument.** A path overrides `[tool.mypy] files` and silently drops the test files.
- **`git commit -m` with a multi-line message breaks in PowerShell 5.1** when the message contains double quotes. Write it to a file under the session scratchpad and use `git commit -F`.
- **Write files with LF and no BOM.** `path.write_text(text, encoding="utf-8", newline="\n")`, or from PowerShell `[System.IO.File]::WriteAllText(p, t, (New-Object System.Text.UTF8Encoding($false)))`. Plain `Set-Content -Encoding utf8` injects a BOM on PS 5.1 and has bitten this project twice.
- **Use Write/Edit, not Bash heredocs, for anything containing backslashes.** The Bash tool strips one backslash level even inside quoted heredocs, and this sub-project is full of Windows path literals.
- Ruff: line-length 100, rules `E,F,I,N,UP,B,SIM,PTH,RUF`. Mypy: `strict = true`, tests included.
- **Adapters are tested against `tests/harvest/fixtures/`**, the golden captures phase0 §4.5 designates for exactly this purpose. Never against live scanners.

## Measured facts the plan is built on

All from `tests/harvest/fixtures/`. **Drive assertions from the fixtures, never from these literals** — a test that restates a number cannot detect the number changing.

| Scanner / platform | Findings | Identity present | Attribute path | Notes |
|---|---|---|---|---|
| checkov / terraform | 221 | 221/221 | 208/221 | 6 non-resource (4 secret, 2 Dockerfile) |
| checkov / kubernetes | 268 | 268/268 | 165/268 | 10 use a 4-component form that is a **label**, not a container; 2 secret |
| trivy / terraform | 115 | 113/115 | 0 | one Target is `.` |
| trivy / kubernetes | 332 | **0/332** | 0 | 328/332 have StartLine |
| tfsec / terraform | 119 | 119/119 | via `resource` suffix | **119/119 absolute Windows paths** |

Kubernetes manifests: 22 files, **18 parse, 4 fail** (all `metadata-db/templates/*`, the Helm chart), **35 kind-bearing documents**, 17 container names, **13/35 with no namespace**. (An earlier revision said 37 and 15/37; those figures counted `Chart.yaml` and `values.yaml`, which parse but carry no `kind` and are not manifests. Corrected from Task 3's measurement.)

## File Structure

| Path | Responsibility | Task |
|---|---|---|
| `src/iacrisk/finding.py` | `NormalizedFinding`, identity kinds, the explicit states | 1 |
| `src/iacrisk/input.py` | Discover IaC files, classify platform | 2 |
| `src/iacrisk/resources.py` | Kubernetes resource index (by line, by address) | 3 |
| `src/iacrisk/scanners/base.py` | Adapter protocol, scan-root path rebasing, `AdapterResult` | 4 |
| `src/iacrisk/scanners/checkov.py` | Checkov adapter | 5 |
| `src/iacrisk/scanners/trivy.py` | Trivy adapter | 6 |
| `src/iacrisk/scanners/tfsec.py` | tfsec adapter | 7 |
| `src/iacrisk/dedupe.py` | Two-tier deduplication | 8 |
| `src/iacrisk/report.py` | Retention-coverage report | 9 |
| `src/iacrisk/scanners/invoke.py` | Subprocess invocation from the lockfile matrix | 10 |
| `tests/test_s3a_gates.py` | The six acceptance gates as tests | 11 |

Tests mirror the source: `tests/test_finding.py`, `tests/test_input.py`, `tests/test_resources.py`, `tests/scanners/test_base.py`, `tests/scanners/test_{checkov,trivy,tfsec}.py`, `tests/test_dedupe.py`, `tests/test_report.py`, `tests/scanners/test_invoke.py`. The `tests/scanners/` subdirectory follows the existing `tests/harvest/` precedent.

---

## Task 1: The normalized finding record

Implements spec §2 and §2.1. This is the record S0 deliberately refused to define; everything downstream depends on its shape, so it lands first and alone.

**Files:**
- Create: `src/iacrisk/finding.py`
- Test: `tests/test_finding.py`

**Interfaces — produced, relied on by every later task:**
- `IDENTITY_KINDS: tuple[str, ...]` = `("terraform", "kubernetes", "file", "provider", "secret", "unresolved")`
- `PLATFORMS: tuple[str, ...]` = `("terraform", "kubernetes")`
- `NormalizedFinding` frozen dataclass with the fields in spec §2, in this order: `scanner, rule_id, canonical_rule_id, issue_class, title, remediation, native_severity, severity_level, platform, resource_identity, identity_kind, file_path, line_range, fingerprint, context_eligible`
- `NormalizedFinding.is_unmapped` property → `bool`
- `NormalizedFinding.has_resolved_fingerprint` property → `bool`

- [ ] **Step 1: Write the failing test**

Create `tests/test_finding.py`:

```python
"""The record S0 refused to define, because it depends on a taxonomy that did not exist.

Every explicit state S1 established has to survive into this record: unmapped
classes, unknown severity, unresolved identity. S3a adds one more - an unresolved
violation fingerprint - and the tests below are what stop any of them being
collapsed into a convenient default.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from iacrisk.finding import IDENTITY_KINDS, PLATFORMS, NormalizedFinding

BASE: dict[str, Any] = {
    "scanner": "checkov",
    "rule_id": "CKV_AWS_133",
    "canonical_rule_id": "CKV_AWS_133",
    "issue_class": "storage-data-recoverability",
    "title": "Ensure that RDS instances has backup policy",
    "remediation": None,
    "native_severity": None,
    "severity_level": "unknown",
    "platform": "terraform",
    "resource_identity": "aws_db_instance.default",
    "identity_kind": "terraform",
    "file_path": "db-app.tf",
    "line_range": (1, 42),
    "fingerprint": "backup_retention_period",
    "context_eligible": True,
}


def test_the_record_is_frozen_and_hashes_by_value() -> None:
    """Later tasks put findings in sets to count distinct ones, so value hashing is load-bearing."""
    a = NormalizedFinding(**BASE)
    b = NormalizedFinding(**BASE)

    assert a == b
    assert len({a, b}) == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.scanner = "trivy"  # type: ignore[misc]


@pytest.mark.parametrize("field", list(BASE))
def test_every_field_discriminates(field: str) -> None:
    """No field may be excluded from equality - that would silently merge distinct findings."""
    varied = dict(BASE)
    current = varied[field]
    varied[field] = "varied" if isinstance(current, str) else (
        None if current is not None else "was-none"
    )
    if field == "context_eligible":
        varied[field] = False
    if field == "line_range":
        varied[field] = (9, 9)

    assert NormalizedFinding(**BASE) != NormalizedFinding(**varied), (
        f"{field} does not participate in equality"
    )


def test_unknown_severity_is_the_literal_string_not_a_number() -> None:
    """PLAN Q9: an undetermined severity is a state, not a low score."""
    finding = NormalizedFinding(**BASE)

    assert finding.severity_level == "unknown"
    assert not isinstance(finding.severity_level, int)


def test_a_numeric_severity_is_allowed_too() -> None:
    finding = NormalizedFinding(**{**BASE, "severity_level": 4})

    assert finding.severity_level == 4


def test_is_unmapped_reads_the_class_not_a_separate_flag() -> None:
    """One source of truth: the class id carries the state, so the two cannot disagree."""
    mapped = NormalizedFinding(**BASE)
    unmapped = NormalizedFinding(**{**BASE, "issue_class": "unmapped:checkov:CKV_AWS_9999"})

    assert not mapped.is_unmapped
    assert unmapped.is_unmapped


def test_an_unresolved_fingerprint_is_none_and_is_reported_as_such() -> None:
    """Dedupe tier 1 turns on this property; a sentinel string would collapse wrongly."""
    resolved = NormalizedFinding(**BASE)
    unresolved = NormalizedFinding(**{**BASE, "fingerprint": None})

    assert resolved.has_resolved_fingerprint
    assert not unresolved.has_resolved_fingerprint
    assert unresolved.fingerprint is None


def test_the_vocabularies_are_closed() -> None:
    """A new identity kind or platform should be a deliberate edit, not an accident."""
    assert IDENTITY_KINDS == ("terraform", "kubernetes", "file", "provider", "secret", "unresolved")
    assert PLATFORMS == ("terraform", "kubernetes")


def test_a_non_resource_finding_is_marked_context_ineligible() -> None:
    """Spec 2.1: no resource means nothing for S3b to contextualize.

    Without the flag these findings would reach S4 with all five context factors
    defaulted, and the defaults sum to 16 - landing every one of them at 17-21,
    always High, for structural reasons rather than on merit.
    """
    secret = NormalizedFinding(**{
        **BASE,
        "issue_class": "iam-hardcoded-secrets",
        "resource_identity": "fc3f784491eba6121c3bfcc1652a2c57d27b16cb",
        "identity_kind": "secret",
        "context_eligible": False,
    })

    assert secret.identity_kind == "secret"
    assert secret.context_eligible is False
```

- [ ] **Step 2: Run the test to verify it fails**

```
uv run pytest tests/test_finding.py -q
```

Expected: `ImportError: cannot import name 'finding' from 'iacrisk'` (the package exists, the module does not).

- [ ] **Step 3: Write the implementation**

Create `src/iacrisk/finding.py`. Document to the repo's established standard — say *why*, not *what*, and do not claim more than the code does:

```python
"""The normalized finding record (design spec section 2)."""

from __future__ import annotations

from dataclasses import dataclass

IDENTITY_KINDS = ("terraform", "kubernetes", "file", "provider", "secret", "unresolved")
PLATFORMS = ("terraform", "kubernetes")
UNMAPPED_PREFIX = "unmapped:"


@dataclass(frozen=True)
class NormalizedFinding:
    scanner: str
    rule_id: str
    canonical_rule_id: str
    issue_class: str
    title: str
    remediation: str | None
    native_severity: str | None
    severity_level: int | str
    platform: str
    resource_identity: str
    identity_kind: str
    file_path: str
    line_range: tuple[int, int] | None
    fingerprint: str | None
    context_eligible: bool

    @property
    def is_unmapped(self) -> bool:
        return self.issue_class.startswith(UNMAPPED_PREFIX)

    @property
    def has_resolved_fingerprint(self) -> bool:
        return self.fingerprint is not None
```

- [ ] **Step 4: Verify**

```
uv run pytest tests/test_finding.py -q
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

- [ ] **Step 5: Commit**

```
git add src/iacrisk/finding.py tests/test_finding.py
git commit -F <message file>
```
Subject: `S3a: the normalized finding record`

---

## Task 2: Input discovery and platform classification

Implements spec §3.

**Files:**
- Create: `src/iacrisk/input.py`
- Test: `tests/test_input.py`

**Interfaces:**
- `DiscoveredFile` frozen dataclass: `path: Path`, `relative_path: str`, `platform: str`
- `DiscoveryResult` frozen dataclass: `files: tuple[DiscoveredFile, ...]`, `ignored: tuple[str, ...]`, `unparseable: tuple[str, ...]`
- `discover(scan_root: Path) -> DiscoveryResult`
- `is_manifest_document(doc: object) -> bool`

- [ ] **Step 1: Write the failing test**

Create `tests/test_input.py`:

```python
"""Discovery decides which scanners are applicable, so misclassifying a file is not cosmetic.

The corpus makes both edges real: Chart.yaml and values.yaml parse cleanly but are
not manifests, and the metadata-db Helm templates are manifests that do not parse.
Neither may be silently ignored.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacrisk.input import DiscoveryResult, discover, is_manifest_document

REPO_ROOT = Path(__file__).resolve().parent.parent
TF_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
K8S_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def test_terraform_files_are_discovered_and_classified() -> None:
    result = discover(TF_ROOT)

    assert result.files, "no terraform files discovered"
    assert all(f.platform == "terraform" for f in result.files)
    assert all(f.relative_path.endswith(".tf") for f in result.files)


def test_relative_paths_are_scan_root_relative_and_posix() -> None:
    """The join key is the scan root, and separators are normalized (spec 5.1)."""
    result = discover(K8S_ROOT)

    for f in result.files:
        assert not f.relative_path.startswith("/")
        assert "\\" not in f.relative_path
        assert not Path(f.relative_path).is_absolute()


def test_a_yaml_without_apiversion_and_kind_is_not_a_manifest() -> None:
    """Chart.yaml parses cleanly and is not a manifest; this is what excludes it."""
    assert not is_manifest_document({"apiVersion": "v1", "description": "a chart"})
    assert not is_manifest_document({"kind": "Deployment"})
    assert not is_manifest_document(["not", "a", "mapping"])
    assert not is_manifest_document(None)
    assert is_manifest_document({"apiVersion": "apps/v1", "kind": "Deployment"})


def test_the_helm_templates_are_recorded_as_unparseable_not_ignored() -> None:
    """Four of the corpus's 22 manifests do not parse. Silence would hide them.

    They are the reason S1's <unresolved> identity path is exercised rather than
    theoretical, so discovery has to surface them as a distinct outcome from
    'this file was not YAML we care about'.
    """
    result = discover(K8S_ROOT)

    assert result.unparseable, "no unparseable files recorded"
    assert all("metadata-db" in p for p in result.unparseable), (
        f"unexpected unparseable files: {result.unparseable}"
    )


def test_kubernetes_manifests_are_discovered() -> None:
    result = discover(K8S_ROOT)

    manifests = [f for f in result.files if f.platform == "kubernetes"]
    assert manifests, "no kubernetes manifests discovered"
    names = {Path(f.relative_path).name for f in manifests}
    assert "Chart.yaml" not in names, "Chart.yaml is not a manifest"
    assert "values.yaml" not in names, "values.yaml is not a manifest"


def test_every_file_under_the_root_is_accounted_for() -> None:
    """in = discovered + ignored + unparseable. A file that vanishes is a coverage lie."""
    result = discover(K8S_ROOT)
    on_disk = {
        p.relative_to(K8S_ROOT).as_posix()
        for p in K8S_ROOT.rglob("*")
        if p.is_file()
    }
    accounted = (
        {f.relative_path for f in result.files}
        | set(result.ignored)
        | set(result.unparseable)
    )

    assert accounted == on_disk, f"unaccounted: {on_disk - accounted}"


def test_a_missing_scan_root_raises_rather_than_returning_empty() -> None:
    """An empty result for a bad path would read as 'a clean scan'."""
    with pytest.raises(FileNotFoundError):
        discover(REPO_ROOT / "no" / "such" / "root")


def test_discovery_result_is_frozen() -> None:
    result = discover(TF_ROOT)
    assert isinstance(result, DiscoveryResult)
    assert isinstance(result.files, tuple)
```

- [ ] **Step 2: Run the test — expect `ImportError` on `iacrisk.input`**

- [ ] **Step 3: Write the implementation**

Create `src/iacrisk/input.py`:

```python
"""Layer 1: discover IaC files under a scan root and classify their platform."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TERRAFORM_SUFFIXES = (".tf",)
MANIFEST_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    relative_path: str
    platform: str


@dataclass(frozen=True)
class DiscoveryResult:
    files: tuple[DiscoveredFile, ...]
    ignored: tuple[str, ...]
    unparseable: tuple[str, ...]


def is_manifest_document(doc: object) -> bool:
    """A Kubernetes manifest document carries both `apiVersion` and `kind`.

    This is what separates a manifest from Chart.yaml and values.yaml, which
    parse cleanly and are not manifests.
    """
    return isinstance(doc, dict) and bool(doc.get("apiVersion")) and bool(doc.get("kind"))


def discover(scan_root: Path) -> DiscoveryResult:
    """Walk `scan_root`, classifying every file.

    Raises `FileNotFoundError` for a missing root rather than returning an empty
    result, which would be indistinguishable from a clean scan.
    """
    if not scan_root.is_dir():
        raise FileNotFoundError(f"scan root does not exist or is not a directory: {scan_root}")

    files: list[DiscoveredFile] = []
    ignored: list[str] = []
    unparseable: list[str] = []

    for path in sorted(p for p in scan_root.rglob("*") if p.is_file()):
        rel = path.relative_to(scan_root).as_posix()
        suffix = path.suffix.lower()

        if suffix in TERRAFORM_SUFFIXES:
            files.append(DiscoveredFile(path=path, relative_path=rel, platform="terraform"))
            continue

        if suffix not in MANIFEST_SUFFIXES:
            ignored.append(rel)
            continue

        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
        except yaml.YAMLError:
            unparseable.append(rel)
            continue

        if any(is_manifest_document(d) for d in docs):
            files.append(DiscoveredFile(path=path, relative_path=rel, platform="kubernetes"))
        else:
            ignored.append(rel)

    return DiscoveryResult(
        files=tuple(files), ignored=tuple(ignored), unparseable=tuple(unparseable)
    )
```

- [ ] **Step 4: Verify** — focused tests, then `ruff check`, `ruff format --check`, bare `mypy`.

- [ ] **Step 5: Commit.** Subject: `S3a: IaC input discovery and platform classification`

---

## Task 3: The Kubernetes resource index

Implements spec §4. This module exists because trivy supplies no Kubernetes resource identity at all (0/332 measured) and checkov omits `apiVersion`.

**Files:**
- Create: `src/iacrisk/resources.py`
- Test: `tests/test_resources.py`

**Interfaces:**
- `ResourceEntry` frozen dataclass: `api_version, kind, namespace, name, container, start_line, end_line, relative_path, namespace_defaulted: bool`
- `ResourceIndex` with `by_line(relative_path: str, line: int) -> ResourceEntry | None`, `by_address(kind: str, namespace: str, name: str, container: str | None = None) -> ResourceEntry | None`, `unparseable: tuple[str, ...]`, `entries: tuple[ResourceEntry, ...]`
- `build_index(discovery: DiscoveryResult) -> ResourceIndex`
- `ResourceEntry.to_identity() -> str` — delegates to `identity.kubernetes_identity`

- [ ] **Step 1: Write the failing test**

Create `tests/test_resources.py`:

```python
"""Kubernetes identity comes from the manifests, because the scanners do not supply it.

Trivy reports no resource for Kubernetes at all and checkov omits apiVersion, so
without this index 332 findings have no identity and every checkov identity is
incomplete. The index is also where the corpus's four unparseable Helm templates
become an explicit unresolved path rather than a silent gap.
"""

from __future__ import annotations

from pathlib import Path

from iacrisk import identity
from iacrisk.input import discover
from iacrisk.resources import ResourceIndex, build_index

REPO_ROOT = Path(__file__).resolve().parent.parent
K8S_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def _index() -> ResourceIndex:
    return build_index(discover(K8S_ROOT))


def test_the_index_covers_the_parseable_manifests() -> None:
    index = _index()

    assert index.entries, "index is empty"
    kinds = {e.kind for e in index.entries}
    assert {"Deployment", "Service", "Job"} <= kinds, f"missing expected kinds: {kinds}"


def test_cluster_scoped_kinds_are_present_and_keep_no_namespace() -> None:
    """S1 section 5.2: a cluster-scoped kind omits the namespace component."""
    index = _index()

    cluster_scoped = [e for e in index.entries if e.kind in {"Namespace", "ClusterRoleBinding"}]
    assert cluster_scoped, "corpus should contain cluster-scoped kinds"


def test_an_omitted_namespace_is_defaulted_and_flagged() -> None:
    """Defaulting silently would make a namespaced resource indistinguishable
    from a cluster-scoped one - the conflation S1 pinned apart."""
    index = _index()

    defaulted = [e for e in index.entries if e.namespace_defaulted]
    assert defaulted, "corpus has manifests with no metadata.namespace"
    assert all(e.namespace == identity.DEFAULT_NAMESPACE for e in defaulted)


def test_container_entries_exist_and_are_distinct_from_their_workload() -> None:
    index = _index()

    containers = [e for e in index.entries if e.container]
    assert containers, "no container entries indexed"
    for entry in containers[:5]:
        assert f"container={entry.container}" in entry.to_identity()


def test_by_line_returns_the_innermost_match() -> None:
    """Spans nest workload-to-container, so the container must win (spec 4).

    Returning the workload for a container's line would collapse every container
    finding onto its parent and lose the [container=...] component.
    """
    index = _index()
    container = next(e for e in index.entries if e.container)

    found = index.by_line(container.relative_path, container.start_line)

    assert found is not None
    assert found.container == container.container


def test_by_line_outside_every_span_is_none_not_the_nearest() -> None:
    """A guess presented as a lookup is worse than an explicit unresolved."""
    index = _index()

    assert index.by_line("no/such/file.yaml", 1) is None
    assert index.by_line(index.entries[0].relative_path, 10_000) is None


def test_by_address_resolves_checkov_style_addresses() -> None:
    """Checkov gives Kind.namespace.name; its four-component form is a label, not a container."""
    index = _index()
    workload = next(e for e in index.entries if e.kind == "Deployment" and not e.container)

    found = index.by_address(workload.kind, workload.namespace, workload.name)

    assert found is not None
    assert found.name == workload.name
    assert found.api_version, "apiVersion is what the index adds over checkov's address"


def test_unparseable_files_are_recorded_and_yield_no_entries() -> None:
    """The four Helm templates: findings landing there take <unresolved>."""
    index = _index()

    assert index.unparseable, "unparseable files should be recorded"
    assert all("metadata-db" in p for p in index.unparseable)
    for path in index.unparseable:
        assert index.by_line(path, 1) is None


def test_to_identity_matches_the_s1_formatter() -> None:
    """The index must not invent its own identity spelling."""
    index = _index()
    entry = next(e for e in index.entries if not e.container)

    assert entry.to_identity() == identity.kubernetes_identity(
        entry.api_version, entry.kind, entry.name, namespace=entry.namespace
    )
```

- [ ] **Step 2: Run — expect `ImportError` on `iacrisk.resources`**

- [ ] **Step 3: Write the implementation**

Create `src/iacrisk/resources.py`. Build entries by scanning each parseable manifest for document spans, then container spans within them. Use `yaml.compose_all` to obtain node line numbers, or track spans by re-scanning text for `---` separators plus container `- name:` keys — choose one and document the choice. Key points:

```python
"""The Kubernetes resource index (design spec section 4)."""

from __future__ import annotations

from dataclasses import dataclass

import yaml

from iacrisk import identity
from iacrisk.input import DiscoveryResult


@dataclass(frozen=True)
class ResourceEntry:
    api_version: str
    kind: str
    namespace: str
    name: str
    container: str | None
    start_line: int
    end_line: int
    relative_path: str
    namespace_defaulted: bool

    def to_identity(self) -> str:
        return identity.kubernetes_identity(
            self.api_version,
            self.kind,
            self.name,
            namespace=self.namespace,
            container=self.container,
        )


class ResourceIndex:
    def __init__(
        self, entries: tuple[ResourceEntry, ...], unparseable: tuple[str, ...]
    ) -> None:
        self.entries = entries
        self.unparseable = unparseable

    def by_line(self, relative_path: str, line: int) -> ResourceEntry | None:
        """The innermost entry whose span contains `line`.

        Container spans sit inside workload spans, so the narrowest match wins;
        returning the workload would drop the container component.
        """
        matches = [
            e
            for e in self.entries
            if e.relative_path == relative_path and e.start_line <= line <= e.end_line
        ]
        if not matches:
            return None
        return min(matches, key=lambda e: e.end_line - e.start_line)

    def by_address(
        self, kind: str, namespace: str, name: str, container: str | None = None
    ) -> ResourceEntry | None:
        for e in self.entries:
            if (
                e.kind == kind
                and e.namespace == namespace
                and e.name == name
                and e.container == container
            ):
                return e
        return None
```

`build_index(discovery)` iterates `discovery.files` where `platform == "kubernetes"`, composes each with `yaml.compose_all` to get node start/end lines, emits one entry per manifest document plus one per container and initContainer, and carries `discovery.unparseable` through unchanged.

- [ ] **Step 4: Verify.** If `compose_all` proves awkward for container spans, fall back to locating each container by its `name:` line within the workload span — but **report the choice**, do not silently approximate.

- [ ] **Step 5: Commit.** Subject: `S3a: Kubernetes resource index`

---

## Task 4: Adapter base — protocol and scan-root path rebasing

Implements spec §5 and §5.1. The path rebasing here is what makes tfsec's 119 absolute paths join with the other two scanners.

**Files:**
- Create: `src/iacrisk/scanners/__init__.py`, `src/iacrisk/scanners/base.py`
- Test: `tests/scanners/__init__.py`, `tests/scanners/test_base.py`

**Interfaces:**
- `AdapterResult` frozen dataclass: `findings: tuple[NormalizedFinding, ...]`, `dropped: tuple[tuple[str, str], ...]` (rule_id, reason)
- `rebase_to_scan_root(raw_path: str, scan_root: Path) -> str`
- `ScannerAdapter` Protocol: `name: str`, `parse(raw: object, scan_root: Path, index: ResourceIndex | None) -> AdapterResult`

- [ ] **Step 1: Write the failing test**

Create `tests/scanners/test_base.py`:

```python
"""One target path spelling, and it is scan-root-relative.

tfsec emits absolute Windows paths on all 119 of its findings while checkov and
trivy emit scan-root-relative ones. Rebasing to the repository root instead - the
intuitive wrong answer - yields corpus/vendor/terragoat/terraform/aws/ec2.tf,
which joins with neither.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacrisk.scanners.base import rebase_to_scan_root

SCAN_ROOT = Path("D:/Research/corpus/vendor/terragoat/terraform/aws")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\ec2.tf", "ec2.tf"),
        ("D:/Research/corpus/vendor/terragoat/terraform/aws/ec2.tf", "ec2.tf"),
        ("ec2.tf", "ec2.tf"),
        ("/ec2.tf", "ec2.tf"),
        ("\\ec2.tf", "ec2.tf"),
        ("/resources\\Dockerfile", "resources/Dockerfile"),
    ],
)
def test_every_observed_spelling_rebases_to_one_form(raw: str, expected: str) -> None:
    assert rebase_to_scan_root(raw, SCAN_ROOT) == expected


def test_the_three_scanners_spellings_of_one_file_converge() -> None:
    """The property that matters: this is the join key."""
    tfsec = "D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\ec2.tf"
    checkov = "/ec2.tf"
    trivy = "ec2.tf"

    assert len({rebase_to_scan_root(p, SCAN_ROOT) for p in (tfsec, checkov, trivy)}) == 1


def test_drive_letter_case_does_not_defeat_the_prefix_match() -> None:
    """The configured root and the path tfsec reports need not agree on case."""
    assert rebase_to_scan_root(
        "d:\\research\\CORPUS\\vendor\\terragoat\\terraform\\aws\\ec2.tf", SCAN_ROOT
    ) == "ec2.tf"


def test_an_absolute_path_outside_the_scan_root_raises() -> None:
    """Silently passing it through would produce a path that joins with nothing."""
    with pytest.raises(ValueError, match="outside the scan root"):
        rebase_to_scan_root("C:\\Windows\\System32\\drivers\\etc\\hosts", SCAN_ROOT)


def test_rebasing_is_idempotent() -> None:
    once = rebase_to_scan_root("D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\ec2.tf", SCAN_ROOT)

    assert rebase_to_scan_root(once, SCAN_ROOT) == once
```

- [ ] **Step 2: Run — expect `ModuleNotFoundError` on `iacrisk.scanners`**

- [ ] **Step 3: Write the implementation**

`src/iacrisk/scanners/base.py`:

```python
"""Shared adapter surface, and the one path spelling all three scanners reduce to."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from iacrisk.finding import NormalizedFinding
from iacrisk.resources import ResourceIndex


@dataclass(frozen=True)
class AdapterResult:
    findings: tuple[NormalizedFinding, ...]
    dropped: tuple[tuple[str, str], ...]


def rebase_to_scan_root(raw_path: str, scan_root: Path) -> str:
    """Reduce any scanner's path spelling to one scan-root-relative form.

    Backslashes are replaced explicitly rather than via a path library, because
    PurePosixPath does not treat a backslash as a separator even on Windows.
    An absolute path outside the scan root raises: passing it through would
    yield a path that joins with nothing, silently.
    """
    normalized = raw_path.replace("\\", "/")
    root = str(scan_root).replace("\\", "/").rstrip("/")

    if _is_absolute(normalized):
        if normalized.lower().startswith(root.lower() + "/"):
            normalized = normalized[len(root) + 1 :]
        elif normalized.lower() == root.lower():
            normalized = ""
        else:
            raise ValueError(f"absolute path is outside the scan root: {raw_path!r}")

    return normalized.lstrip("/")


def _is_absolute(posix_style: str) -> bool:
    return posix_style.startswith("/") and ":" in posix_style[:3] or (
        len(posix_style) > 1 and posix_style[1] == ":"
    )


class ScannerAdapter(Protocol):
    name: str

    def parse(
        self, raw: object, scan_root: Path, index: ResourceIndex | None
    ) -> AdapterResult: ...
```

**Note for the implementer:** `_is_absolute` above is written for drive-letter paths. Verify it against the parametrized cases — `/ec2.tf` must **not** be treated as absolute, or it would raise instead of rebasing. If the predicate is awkward, replace it with an explicit regex `^[A-Za-z]:/` and say so.

- [ ] **Step 4: Verify. Step 5: Commit.** Subject: `S3a: adapter protocol and scan-root path rebasing`

---

## Task 5: Checkov adapter

Implements spec §5 for checkov, including the polymorphic `resource` field (§2.1) and the `evaluated_keys` fingerprint (§6).

**Files:**
- Create: `src/iacrisk/scanners/checkov.py`
- Test: `tests/scanners/test_checkov.py`

**Interfaces:** `CheckovAdapter` implementing `ScannerAdapter`; `classify_resource(value, rule_id, platform) -> tuple[str, str, bool]` returning `(resource_identity, identity_kind, context_eligible)`; `fingerprint_from(evaluated_keys) -> str | None`.

- [ ] **Step 1: Write the failing test** covering, driven from `tests/harvest/fixtures/checkov-terraform.json` and `checkov-kubernetes.json`:
  - every fixture finding yields exactly one `NormalizedFinding` or one `dropped` entry, and `in == out + dropped`;
  - a Terraform address `aws_db_instance.default` → `identity_kind == "terraform"`, `context_eligible is True`;
  - a 40-hex secret value → `identity_kind == "secret"`, `context_eligible is False`;
  - a Dockerfile `resource` → `identity_kind == "file"`, `context_eligible is False`;
  - **the four-component form is a LABEL, not a container — do not feed it to `by_address(container=…)`.** `Pod.default.build-code-deployment.app-build-code` carries the pod template's label `app: build-code` rendered `key-value`, not a container name. Measured 10/10 against the manifests, and `Pod.default.internal-proxy-deployment.app-internal-proxy` proves it: that workload's containers are `info-app` and `internal-api`, neither of which is the fourth component. The synthesized `Kind` is `Pod` rather than the workload's real `Deployment`, which is the other tell. All 10 are `CKV2_K8S_6`, a pod-level check, so the **workload** identity is the correct target: assert the finding resolves to `.../build-code-deployment` with **no** `[container=…]` component;
  - `evaluated_keys == ["resource_type"]` → fingerprint `None`; `["storage_encrypted"]` → `"storage_encrypted"`; `["kms_key_id", "storage_encrypted"]` → `"kms_key_id,storage_encrypted"` (sorted, comma-joined);
  - `native_severity is None` on every checkov finding and `severity_level == "unknown"` — driven by asserting the fixture's severity field is absent, not by restating 46.4%;
  - class comes from `taxonomy.class_for` — assert one known rule maps to its known class, and that an invented rule id yields an `unmapped:` class.

- [ ] **Step 2: Run — expect `ImportError`**

- [ ] **Step 3: Implement.** `classify_resource` order matters: 40-hex → `secret`; `CKV_DOCKER_*` or a value containing a path separator → `file`; `<lower>.<name>` on terraform → `terraform`; `Kind.ns.name[.container]` on kubernetes → `kubernetes`; otherwise → `provider`. Only `terraform` and `kubernetes` are `context_eligible`.

- [ ] **Step 4: Verify. Step 5: Commit.** Subject: `S3a: checkov adapter`

---

## Task 6: Trivy adapter

Implements spec §5 for trivy. The Kubernetes path is the hard one: 0/332 findings carry a resource.

**Files:**
- Create: `src/iacrisk/scanners/trivy.py`
- Test: `tests/scanners/test_trivy.py`

- [ ] **Step 1: Write the failing test** covering:
  - Terraform: identity from `CauseMetadata.Resource` (113/115 in the fixture); the 2 without it take `<unresolved>` and are counted, not dropped;
  - Kubernetes: identity resolved via `index.by_line(target, CauseMetadata.StartLine)`, asserting a known finding lands on the right workload or container;
  - a finding whose line matches no span → `<unresolved>`, counted;
  - `Target == "."` yields an empty `file_path` and does not crash;
  - **fingerprint is `None` for every trivy finding** — assert it as a property over the whole fixture, with a docstring stating the measured reason (zero vocabulary overlap with checkov), not merely that trivy "has no attribute";
  - both `AWS-####` and `KSV-####` rule families resolve through `taxonomy.class_for` (30 KSV rows exist in the committed taxonomy);
  - severity comes from `rubric.normalize_severity("trivy", token)`.

- [ ] **Steps 2–5** as before. Subject: `S3a: trivy adapter`

---

## Task 7: tfsec adapter

Implements spec §5 for tfsec — absolute paths and the attribute-suffixed `resource`.

**Files:**
- Create: `src/iacrisk/scanners/tfsec.py`
- Test: `tests/scanners/test_tfsec.py`

- [ ] **Step 1: Write the failing test** covering:
  - **all 119 fixture findings rebase to scan-root-relative paths**, asserted as set-equality against the paths checkov and trivy report for the same files — this is acceptance gate 3 and the single most important assertion in the task;
  - `aws_db_instance.default` → terraform identity, fingerprint `None`;
  - `aws_db_instance.default.publicly_accessible` → identity `aws_db_instance.default`, fingerprint `"publicly_accessible"` — the suffix is split off, not left in the identity;
  - tfsec is terraform-only: parsing the 19-byte `tfsec-kubernetes.json` off-matrix probe yields zero findings and does not raise;
  - `canonical_rule_id` strips the `AVD-` prefix so a tfsec rule and its trivy twin share a canonical id.

- [ ] **Steps 2–5.** Subject: `S3a: tfsec adapter`

---

## Task 8: Two-tier deduplication

Implements spec §7.

**Files:**
- Create: `src/iacrisk/dedupe.py`
- Test: `tests/test_dedupe.py`

**Interfaces:**
- `DedupeGroup` frozen dataclass: `key: tuple[str, str, str]`, `findings: tuple[NormalizedFinding, ...]`, `scanners: tuple[str, ...]`
- `CandidateOverlap` frozen dataclass: `resource_identity: str`, `issue_class: str`, `findings: tuple[NormalizedFinding, ...]`, `scanners: tuple[str, ...]`
- `DedupeResult` frozen dataclass: `groups`, `candidates`, `collapsed_count: int`
- `deduplicate(findings: Iterable[NormalizedFinding]) -> DedupeResult`

- [ ] **Step 1: Write the failing test** covering:
  - two findings with the same identity, class and **resolved equal** fingerprint collapse into one group, with both scanners in `scanners`;
  - two findings with the same identity and class but **different resolved** fingerprints do **not** collapse — this is what PLAN Q8 #6 added the fingerprint for, so the test names the concrete case: two ingress rules on one security group;
  - a finding with `fingerprint is None` **never** collapses, even against an identical finding with a resolved fingerprint;
  - two findings sharing identity and class where either fingerprint is unresolved appear in `candidates` and **not** in `collapsed_count`;
  - a finding with `resource_identity == identity.UNRESOLVED` never collapses and never joins a candidate group;
  - `collapsed_count` counts findings removed by collapsing, not groups — so the reported reduction is a finding count;
  - total accounting: every input finding appears in exactly one group or stands alone.

- [ ] **Steps 2–5.** Subject: `S3a: two-tier deduplication`

---

## Task 9: Retention-coverage report

Implements spec §8. This is PLAN Q7's *normalization / retention coverage* metric.

**Files:**
- Create: `src/iacrisk/report.py`
- Test: `tests/test_report.py`

**Interfaces:** `ScannerCoverage` and `RetentionReport` frozen dataclasses; `build_report(results: Mapping[str, AdapterResult], dedupe: DedupeResult) -> RetentionReport`; `RetentionReport.to_json() -> dict[str, object]`.

Per scanner: findings in, out, dropped with reasons; identity-resolution rate with unresolved counts by cause; fingerprint-resolution rate; `unmapped:` rate; `unknown` severity rate. Globally: Tier 1 collapses and Tier 2 candidates, **as separate numbers, never summed**.

- [ ] **Step 1: Write the failing test** covering:
  - `in == out + dropped` for every scanner, asserted as an invariant over the real fixture run;
  - the four rates are computed, not stored — feed a synthetic set with known counts and assert the arithmetic;
  - `to_json()` carries Tier 1 and Tier 2 as distinct keys, and a test asserts no key sums them;
  - a scanner with zero findings reports rates as `None`, not `0.0` — a rate over no findings is undefined, and reporting 0.0 would read as "nothing unresolved".

- [ ] **Steps 2–5.** Subject: `S3a: retention-coverage report`

---

## Task 10: Scanner invocation

Implements spec §3's lockfile-driven dispatch.

**Files:**
- Create: `src/iacrisk/scanners/invoke.py`
- Test: `tests/scanners/test_invoke.py`

**Interfaces:** `applicable_scanners(platform: str) -> tuple[str, ...]` reading `tools/scanners.lock.json`; `ScanInvocation` frozen dataclass; `build_invocations(discovery, scan_root) -> tuple[ScanInvocation, ...]`; `run(invocation) -> object` (raw parsed JSON).

- [ ] **Step 1: Write the failing test** covering:
  - `applicable_scanners("terraform")` returns all three and `applicable_scanners("kubernetes")` excludes tfsec — **read from the lockfile, not hardcoded**, so the platform matrix stays data as S0 established;
  - no scanner name appears as a literal in a conditional in `invoke.py` — assert by AST inspection, mirroring `tests/test_architecture.py`'s approach;
  - `build_invocations` emits nothing for a platform with no files;
  - `run` is **not** exercised against live scanners; test only that a non-zero exit with parseable JSON is returned rather than raising, and that an unparseable stdout raises with the scanner named.

- [ ] **Steps 2–5.** Subject: `S3a: lockfile-driven scanner invocation`

---

## Task 11: Close the S3a acceptance gates

Implements spec §10.

**Files:**
- Create: `tests/test_s3a_gates.py`
- Modify: `CLAUDE.md` (Current state)

- [ ] **Step 1: Write the six gates as tests**, one per spec §10 item, each docstring quoting its gate:
  1. every fixture finding yields exactly one `NormalizedFinding` or one counted drop;
  2. every finding carries a class (real or `unmapped:`) and a severity level or `"unknown"`;
  3. all 119 tfsec paths join string-equal with checkov's and trivy's for the same files;
  4. Kubernetes identity resolves for every finding in a parseable manifest; findings in the four Helm templates take `<unresolved>` and are counted;
  5. Tier 1 never collapses different resolved fingerprints, and never collapses an unresolved one;
  6. the retention report accounts for every input finding: `in == out + dropped` per scanner.

- [ ] **Step 2: Run the gates.** A failing gate is a real miss — fix the artifact, never the gate.

- [ ] **Step 3: Full verification** — `uv run pytest`, `ruff check`, `ruff format --check`, bare `mypy`.

- [ ] **Step 4: Update `CLAUDE.md`** — S3a complete; S3b is next and takes layer 3; note that the deduplication number reported is Tier 1 only and that cross-scanner attribute normalization is named future work (spec §13).

- [ ] **Step 5: Commit.** Subject: `S3a: close the six acceptance gates`

---

## Self-Review

**1. Spec coverage.** §2 → Task 1; §2.1 → Tasks 1 and 5; §3 → Tasks 2 and 10; §4 → Task 3; §5 → Tasks 4–7; §5.1 → Tasks 4 and 7; §6 → Tasks 5–7; §7 → Task 8; §8 → Task 9; §10 → Task 11; §11 and §13 are deferral statements needing no task. **No spec section is unimplemented.**

**2. Placeholder scan.** Tasks 1–4 carry complete code. Tasks 5–10 specify tests as enumerated behavioural requirements with the exact values and fixtures named, rather than transcribed code — a deliberate departure from S1's style, where verbatim plan code was the vector for all nine §G3 defects. Implementers write the assertions and the docstrings; reviewers check that names match bodies. Every enumerated item names its fixture, its expected value, and why it matters.

**3. Type consistency.** `AdapterResult` (Task 4) is consumed by Tasks 5–7 and 9. `ResourceIndex` (Task 3) by Tasks 4, 6, 5. `NormalizedFinding` (Task 1) by everything. `DedupeResult` (Task 8) by Task 9. `DiscoveryResult` (Task 2) by Tasks 3 and 10. Names and shapes are spelled identically in each. `rebase_to_scan_root` returns `str`, used as `file_path` in all three adapters.

**One risk recorded rather than resolved:** Task 3's container-span extraction via `yaml.compose_all` is the least certain step in this plan. The fallback (locate each container by its `name:` line inside the workload span) is named in the task, and the implementer is instructed to report the choice rather than silently approximate. If both prove unworkable, that is a `BLOCKED` report, not a quiet degradation to workload-only identity — which would lose every `[container=…]` component and silently inflate dedupe.

---

## Execution Handoff

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session with checkpoints.
