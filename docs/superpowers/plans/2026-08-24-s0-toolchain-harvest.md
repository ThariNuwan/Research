# S0 — Toolchain & Rule-Inventory Harvest: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a pinned, checksum-verified scanner toolchain and an empirical rule-ID inventory harvested from corpus v0, so that Phase 1's taxonomy can be authored against observed scanner output instead of guessed catalogues.

**Architecture:** A `uv`-managed Python 3.12 project. Checkov installs as an isolated `uv tool` so it can never enter the framework's dependency graph; Trivy and tfsec install as SHA256-verified GitHub release binaries into a gitignored `tools/bin/`, pinned by a committed `tools/scanners.lock.json`. A deliberately narrow research instrument, `tools/harvest.py`, invokes each scanner over vendored corpus v0, stores the raw JSON as committed golden fixtures, and tallies rule IDs plus native-severity coverage into `artifacts/rule-inventory.json`.

**Tech Stack:** Python 3.12 (uv-managed), uv 0.11.26, pytest, ruff, mypy, PowerShell 5.1, GNU tar 1.35, Checkov 3.3.12, Trivy 0.74.0, tfsec 1.28.14.

**Spec:** [`docs/superpowers/specs/2026-08-24-implementation-phase0-design.md`](../specs/2026-08-24-implementation-phase0-design.md)

## Global Constraints

- **Python is pinned to 3.12**, not the system 3.13.5. Checkov 3.3.12's classifiers stop at 3.12 and its docs self-contradict on 3.13. `pyproject.toml` declares `requires-python = ">=3.12,<3.13"`.
- **Bare `python` is broken on this machine** (Microsoft Store alias stub). Never invoke `python` directly — always `uv run python` or `py`.
- **Checkov is NEVER a project dependency.** It is installed only via `uv tool install`. No file under `src/`, `tools/`, `eval/`, or `tests/` may `import checkov`.
- **`eval/` may not import from `src/iacrisk/scoring/`.** The evaluation harness must not share code with the thing it grades (PLAN.md Q7).
- **`tools/harvest.py` must NOT build the normalized finding record.** That is S3 and depends on the taxonomy, which does not exist yet. Harvest emits `InventoryRow` only.
- **No Terraform binary.** Literals-only scope (PLAN.md Q9); `terraform init` is out of scope by design.
- **Exact pins, copied verbatim:**
  - Checkov `3.3.12` (PyPI)
  - Trivy `0.74.0` — `trivy_0.74.0_windows-64bit.zip`, SHA256 `94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842`
  - tfsec `1.28.14` — `tfsec_1.28.14_windows_amd64.tar.gz`, SHA256 `a53c4d7c6c85029378c8895ffbf9b23ea04a887d20136dc1d24d1307cf1a0491`
  - TerraGoat — `bridgecrewio/terragoat` @ `729f8da62c6a85ce4af5ad3d123de97776d954c4`, Apache-2.0
  - KubeGoat — `madhuakula/kubernetes-goat` @ `723a0db478f050d173d23b4ce5044b65bce0bdd0`, MIT
- **Platform-scanner matrix** (PLAN.md Q3 / R3-#3): tfsec is Terraform-only. Kubernetes coverage is Checkov + Trivy. Encode this as data in `scanners.lock.json`, never as an `if` in code.
- **Unknown severity is never silently "low."** A scanner emitting no usable severity yields `native_severity=None`, and the rate is reported (R3-#4).
- **The tfsec `.exe` asset has no published SHA256** — only a GPG `.sig`. Use the `.tar.gz`, which is in `tfsec_1.28.14_checksums.txt`.

---

## File Structure

| File | Responsibility |
|---|---|
| `.gitattributes` | Force LF for hashed research artifacts; CRLF for `.ps1`. Prevents renormalization from invalidating provenance hashes. |
| `pyproject.toml` | uv project, dependency groups, ruff/mypy/pytest config. |
| `.python-version` | `3.12` — written by `uv python pin`. |
| `src/iacrisk/__init__.py` | Package marker + `__version__`. Nothing else in S0. |
| `eval/__init__.py` | Stub. Exists only so the isolation guard has something to assert about. |
| `tests/test_architecture.py` | Structural guardrails: no `import checkov`, `eval/` ↛ `scoring/`. |
| `tools/scanners.lock.json` | **Committed.** Version + SHA256 + URL + applicable platforms per scanner. Single source of truth. |
| `tools/bootstrap.ps1` | Download, verify, extract, resolve. `-Verify` re-asserts without downloading. |
| `tools/resolved.json` | **Gitignored.** Machine-specific absolute exe paths, written by bootstrap. |
| `tools/corpus.lock.json` | **Committed.** Corpus v0 sources: URL, commit SHA, license, category mapping. |
| `tools/vendor_corpus.ps1` | Fetch corpus v0 at pinned commits; write `corpus/vendor/SOURCES.md`. |
| `tools/harvest/__init__.py` | Package marker. |
| `tools/harvest/model.py` | `InventoryRow` — the only record type harvest produces. |
| `tools/harvest/walkers.py` | One walker per scanner JSON schema. Pure functions, no I/O. |
| `tools/harvest/provenance.py` | Provenance block builder (spec §4.4). |
| `tools/harvest/tally.py` | Aggregate rows → inventory dict, incl. missing-severity rate. |
| `tools/harvest/run.py` | Orchestration + CLI. The only module here that touches subprocesses or disk. |
| `tests/harvest/fixtures/` | **Committed** captured raw scanner JSON — golden fixtures for S3. |
| `artifacts/raw/<scanner>/<case>.json` | **Committed** full raw dumps. |
| `artifacts/rule-inventory.json` | **Committed** the S0 deliverable. |

Walkers are pure and separated from `run.py` so schema handling is unit-testable without installing a scanner.

---

## Task 1: Line-ending discipline and project scaffold

**Files:**
- Create: `.gitattributes`, `pyproject.toml`, `src/iacrisk/__init__.py`, `eval/__init__.py`
- Test: `tests/test_package.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `iacrisk.__version__` (`str`); a working `uv run pytest` command for all later tasks.

- [ ] **Step 1: Create `.gitattributes`**

Do this first, before any file whose hash will later appear in a provenance block.

```gitattributes
# Normalize everything to LF in the repository.
# Research-integrity requirement: specs/ hashes and artifacts/ fixtures appear
# in provenance blocks (spec §4.4). CRLF renormalization would silently change
# those hashes and invalidate reproducibility claims.
* text=auto eol=lf

specs/**       text eol=lf
artifacts/**   text eol=lf
corpus/**      text eol=lf
tools/*.json   text eol=lf

# PowerShell is the one exception - keep CRLF on Windows.
*.ps1 text eol=crlf

*.png  binary
*.zip  binary
*.gz   binary
*.exe  binary
*.tar  binary
```

- [ ] **Step 2: Renormalize existing files**

The baseline commit predates `.gitattributes`, so already-committed files may hold CRLF. Fix before any hashing:

```bash
git add --renormalize .
git status --short
```

- [ ] **Step 3: Create `pyproject.toml`**

```toml
[project]
name = "iacrisk"
version = "0.1.0"
description = "Risk-aware prioritization layer for IaC security misconfiguration findings"
requires-python = ">=3.12,<3.13"
dependencies = [
    "pyyaml>=6.0.2",
    "jsonschema>=4.23.0",
]

[dependency-groups]
dev = [
    "pytest>=8.3.0",
    "pytest-cov>=6.0.0",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
    "types-pyyaml>=6.0.12",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/iacrisk"]

[tool.ruff]
line-length = 100
src = ["src", "tests", "tools", "eval"]

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "B", "SIM", "PTH", "RUF"]

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src", "tools", "eval"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q --strict-markers"
pythonpath = ["src", "."]
```

`pythonpath = ["src", "."]` lets tests import both `iacrisk` and `tools.harvest` without an editable install of `tools/`.

- [ ] **Step 4: Pin the interpreter and sync**

```powershell
uv python install 3.12
uv python pin 3.12
uv sync
```

Expected: `.python-version` contains `3.12`; `uv.lock` is created. If `uv python pin` reports an unknown subcommand, run `uv --version` and use `uv venv --python 3.12` plus a hand-written `.python-version` instead — record whichever worked, because Task 8 copies the working command into CLAUDE.md.

- [ ] **Step 5: Write the failing test**

`tests/test_package.py`:

```python
"""Smoke test: the package imports and the interpreter is the pinned one."""

import sys


def test_package_exposes_version() -> None:
    import iacrisk

    assert isinstance(iacrisk.__version__, str)
    assert iacrisk.__version__ == "0.1.0"


def test_interpreter_is_pinned_to_312() -> None:
    # Checkov 3.3.12 classifiers stop at 3.12; running 3.13 is unsupported.
    assert sys.version_info[:2] == (3, 12), (
        f"expected Python 3.12, got {sys.version_info[:2]}; "
        "run 'uv python pin 3.12' then 'uv sync'"
    )
```

- [ ] **Step 6: Run it and confirm it fails**

```powershell
uv run pytest tests/test_package.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'iacrisk'`.

- [ ] **Step 7: Create the package files**

`src/iacrisk/__init__.py`:

```python
"""Risk-aware prioritization layer for IaC security misconfiguration findings."""

__version__ = "0.1.0"
```

`eval/__init__.py`:

```python
"""Independent evaluation harness.

Deliberately empty in S0. This package MUST NOT import from
iacrisk.scoring - the harness may not share code with what it grades
(PLAN.md Q7). tests/test_architecture.py enforces this.
"""
```

- [ ] **Step 8: Run tests to verify they pass**

```powershell
uv run pytest tests/test_package.py -v
```

Expected: 2 passed.

- [ ] **Step 9: Lint and type-check**

```powershell
uv run ruff check .
uv run ruff format .
uv run mypy src
```

Expected: all clean.

- [ ] **Step 10: Commit**

```bash
git add .gitattributes pyproject.toml uv.lock .python-version src/ eval/ tests/
git commit -m "build: uv project scaffold on pinned Python 3.12 + LF discipline"
```

---

## Task 2: Architectural guardrail tests

**Files:**
- Create: `tests/test_architecture.py`

**Interfaces:**
- Consumes: the repo tree from Task 1.
- Produces: nothing importable. A standing structural gate for S1–S6.

Written now, while `eval/` is still a stub — the guardrail should exist before there is anything to violate it (spec §6).

- [ ] **Step 1: Write the failing test**

`tests/test_architecture.py`:

```python
"""Structural guardrails from PLAN.md, enforced as tests rather than convention.

These fail loudly the moment a later sub-project blurs a boundary the
research design depends on.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEARCH_ROOTS = ("src", "tools", "eval", "tests")


def _python_files() -> list[Path]:
    files: list[Path] = []
    for root in SEARCH_ROOTS:
        files.extend((REPO_ROOT / root).rglob("*.py"))
    return files


def _imported_modules(path: Path) -> set[str]:
    """Every module name imported by `path`, as dotted strings."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module)
    return names


def test_no_module_imports_checkov() -> None:
    """Checkov is a subprocess-invoked tool, never a library (PLAN.md Q3).

    It is installed via `uv tool install` into its own venv. An import here
    would mean its dependency tree had leaked into the framework's.
    """
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _python_files()
        if any(m == "checkov" or m.startswith("checkov.") for m in _imported_modules(path))
    ]
    assert offenders == [], f"checkov imported as a library in: {offenders}"


def test_eval_does_not_import_scoring() -> None:
    """The harness may not share code with what it grades (PLAN.md Q7)."""
    offenders = []
    for path in (REPO_ROOT / "eval").rglob("*.py"):
        leaked = {
            m
            for m in _imported_modules(path)
            if m.startswith("iacrisk.scoring") or m == "iacrisk.scoring"
        }
        if leaked:
            offenders.append((path.relative_to(REPO_ROOT).as_posix(), sorted(leaked)))
    assert offenders == [], f"eval/ imports scoring internals: {offenders}"


def test_harvest_does_not_define_a_normalized_finding() -> None:
    """Harvest is a research instrument, not pipeline layer 2 (spec §4.5).

    The normalized finding record belongs to S3 and depends on the
    issue-class taxonomy, which does not exist yet. Catching the name here
    prevents harvest from quietly growing into a duplicate layer 2.
    """
    harvest_dir = REPO_ROOT / "tools" / "harvest"
    if not harvest_dir.exists():
        return  # created in Task 5

    banned = {"Finding", "NormalizedFinding", "FindingRecord"}
    offenders = []
    for path in harvest_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in banned:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{node.name}")
    assert offenders == [], f"harvest defines a normalized-finding type: {offenders}"
```

- [ ] **Step 2: Run and confirm the tests pass trivially**

```powershell
uv run pytest tests/test_architecture.py -v
```

Expected: 3 passed. They pass because nothing violates the rules yet — that is the point. Prove they can *fail*: temporarily add `import checkov` to `src/iacrisk/__init__.py`, re-run, confirm `test_no_module_imports_checkov` FAILS, then remove it.

- [ ] **Step 3: Commit**

```bash
git add tests/test_architecture.py
git commit -m "test: enforce checkov-is-not-a-library and eval/-scoring isolation"
```

---

## Task 3: Scanner lockfile and bootstrap

**Files:**
- Create: `tools/scanners.lock.json`, `tools/bootstrap.ps1`
- Modify: `.gitignore`
- Test: `tests/test_scanners_lock.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `tools/resolved.json` with shape `{"<scanner>": {"exe": "<abs path>", "version": "<verified string>"}}`, read by Task 7's provenance builder and Task 8's runner.

- [ ] **Step 1: Write the failing test**

`tests/test_scanners_lock.py`:

```python
"""The lockfile is the single source of truth for pins and platform applicability."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "tools" / "scanners.lock.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED = {"checkov": "3.3.12", "trivy": "0.74.0", "tfsec": "1.28.14"}


def _lock() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def test_all_three_scanners_pinned_to_exact_versions() -> None:
    scanners = _lock()["scanners"]
    assert set(scanners) == set(EXPECTED)
    for name, version in EXPECTED.items():
        assert scanners[name]["version"] == version


def test_downloaded_binaries_carry_a_sha256() -> None:
    """A pin without a checksum is not a pin (spec §4.2)."""
    for name, entry in _lock()["scanners"].items():
        if entry["channel"] != "github-release":
            continue
        assert SHA256_RE.match(entry["sha256"]), f"{name} sha256 malformed"
        assert entry["url"].startswith("https://github.com/"), f"{name} url not https github"
        assert entry["version"] in entry["url"], f"{name} url does not contain its pinned version"


def test_platform_matrix_is_data_not_code() -> None:
    """PLAN.md Q3 / R3-#3: tfsec is Terraform-only; K8s is Checkov + Trivy."""
    scanners = _lock()["scanners"]
    assert scanners["tfsec"]["platforms"] == ["terraform"]
    assert set(scanners["checkov"]["platforms"]) == {"terraform", "kubernetes"}
    assert set(scanners["trivy"]["platforms"]) == {"terraform", "kubernetes"}


def test_kubernetes_has_at_least_two_applicable_scanners() -> None:
    scanners = _lock()["scanners"]
    k8s = [n for n, e in scanners.items() if "kubernetes" in e["platforms"]]
    assert len(k8s) >= 2, f"K8s coverage requires Checkov + Trivy, got {k8s}"
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/test_scanners_lock.py -v
```

Expected: FAIL — `FileNotFoundError` for `tools/scanners.lock.json`.

- [ ] **Step 3: Create `tools/scanners.lock.json`**

Checksums below are copied from the upstream `checksums.txt` of each release, verified 2026-08-24.

```json
{
  "schema_version": 1,
  "recorded_utc": "2026-08-24",
  "host_platform": "windows-amd64",
  "scanners": {
    "checkov": {
      "version": "3.3.12",
      "channel": "uv-tool",
      "package": "checkov==3.3.12",
      "python": "3.12",
      "exe": "checkov.exe",
      "version_args": ["--version"],
      "platforms": ["terraform", "kubernetes"],
      "note": "Isolated uv tool. Never a project dependency (PLAN.md Q3)."
    },
    "trivy": {
      "version": "0.74.0",
      "channel": "github-release",
      "url": "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_windows-64bit.zip",
      "sha256": "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842",
      "archive": "zip",
      "exe": "trivy.exe",
      "version_args": ["--version"],
      "platforms": ["terraform", "kubernetes"]
    },
    "tfsec": {
      "version": "1.28.14",
      "channel": "github-release",
      "url": "https://github.com/aquasecurity/tfsec/releases/download/v1.28.14/tfsec_1.28.14_windows_amd64.tar.gz",
      "sha256": "a53c4d7c6c85029378c8895ffbf9b23ea04a887d20136dc1d24d1307cf1a0491",
      "archive": "targz",
      "exe": "tfsec.exe",
      "version_args": ["--version"],
      "platforms": ["terraform"],
      "note": "Last upstream release 2025-05-02, 15 months before capture. Retained as legacy/comparative per PLAN.md R1-#19. The .exe asset publishes only a GPG .sig, so the checksummed .tar.gz is used instead."
    }
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```powershell
uv run pytest tests/test_scanners_lock.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Extend `.gitignore`**

Append:

```gitignore
# --- S0 toolchain (binaries and machine-specific paths are not artifacts) ---
tools/bin/
tools/cache/
tools/resolved.json
```

- [ ] **Step 6: Create `tools/bootstrap.ps1`**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Install and verify the pinned scanner toolchain from tools/scanners.lock.json.
.DESCRIPTION
    Downloads Trivy and tfsec release archives, verifies SHA256 against the
    lockfile, extracts them into tools/bin/, installs Checkov as an isolated
    uv tool, then resolves absolute executable paths into tools/resolved.json.

    Verifies rather than trusts: a checksum mismatch is a hard failure.
.PARAMETER Verify
    Re-assert an existing install without downloading. Fails if any scanner is
    missing, mismatched, or reports a version other than its pin.
#>
[CmdletBinding()]
param([switch]$Verify)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ToolsDir = Join-Path $RepoRoot 'tools'
$BinDir = Join-Path $ToolsDir 'bin'
$CacheDir = Join-Path $ToolsDir 'cache'
$LockPath = Join-Path $ToolsDir 'scanners.lock.json'
$ResolvedPath = Join-Path $ToolsDir 'resolved.json'

function Write-Step($Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok($Message) { Write-Host "    OK   $Message" -ForegroundColor Green }
function Die($Message) { Write-Host "    FAIL $Message" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $LockPath)) { Die "lockfile not found: $LockPath" }
$lock = Get-Content $LockPath -Raw | ConvertFrom-Json

foreach ($dir in @($BinDir, $CacheDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

function Get-Sha256($Path) {
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Invoke-VersionCheck($ExePath, $VersionArgs, $Expected, $Name) {
    $raw = & $ExePath @VersionArgs 2>&1 | Out-String
    if ($raw -notmatch [regex]::Escape($Expected)) {
        Die "$Name reports a version not matching pin '$Expected'. Raw output: $($raw.Trim())"
    }
    Write-Ok "$Name $Expected"
    return $raw.Trim()
}

function Install-ReleaseBinary($Name, $Entry) {
    $exePath = Join-Path $BinDir $Entry.exe
    $archiveName = Split-Path $Entry.url -Leaf
    $archivePath = Join-Path $CacheDir $archiveName

    if (-not (Test-Path $exePath)) {
        if ($Verify) { Die "$Name not installed at $exePath (run bootstrap without -Verify)" }

        if (-not (Test-Path $archivePath)) {
            Write-Step "downloading $Name $($Entry.version)"
            # TLS 1.2 is not the PS 5.1 default on all hosts.
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $Entry.url -OutFile $archivePath -UseBasicParsing
        }

        $actual = Get-Sha256 $archivePath
        if ($actual -ne $Entry.sha256.ToLower()) {
            Remove-Item $archivePath -Force
            Die "$Name checksum mismatch. expected $($Entry.sha256) got $actual (archive deleted)"
        }
        Write-Ok "$Name checksum verified"

        Write-Step "extracting $Name"
        if ($Entry.archive -eq 'zip') {
            Expand-Archive -Path $archivePath -DestinationPath $BinDir -Force
        }
        elseif ($Entry.archive -eq 'targz') {
            & tar -xzf $archivePath -C $BinDir
            if ($LASTEXITCODE -ne 0) { Die "tar failed to extract $archiveName" }
        }
        else { Die "unknown archive type '$($Entry.archive)' for $Name" }

        if (-not (Test-Path $exePath)) { Die "$Name extracted but $($Entry.exe) not found in $BinDir" }
    }
    else {
        # Re-verify the cached archive when it is still present.
        if (Test-Path $archivePath) {
            $actual = Get-Sha256 $archivePath
            if ($actual -ne $Entry.sha256.ToLower()) { Die "$Name cached archive checksum drifted" }
            Write-Ok "$Name checksum verified"
        }
    }

    $raw = Invoke-VersionCheck $exePath $Entry.version_args $Entry.version $Name
    return @{ exe = (Resolve-Path $exePath).Path; version = $Entry.version; version_output = $raw }
}

function Install-UvTool($Name, $Entry) {
    $cmd = Get-Command $Entry.exe -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        # uv tool shims land in %USERPROFILE%\.local\bin, often absent from PATH.
        $candidate = Join-Path $env:USERPROFILE ".local\bin\$($Entry.exe)"
        if (Test-Path $candidate) { $cmd = Get-Item $candidate }
    }

    if ($null -eq $cmd) {
        if ($Verify) { Die "$Name not installed (run bootstrap without -Verify)" }
        Write-Step "installing $Name $($Entry.version) as an isolated uv tool"
        & uv tool install $Entry.package --python $Entry.python
        if ($LASTEXITCODE -ne 0) { Die "uv tool install $($Entry.package) failed" }
        $candidate = Join-Path $env:USERPROFILE ".local\bin\$($Entry.exe)"
        if (-not (Test-Path $candidate)) { Die "$Name installed but shim not found at $candidate" }
        $cmd = Get-Item $candidate
    }

    $exePath = $cmd.Source
    if ([string]::IsNullOrEmpty($exePath)) { $exePath = $cmd.FullName }
    $raw = Invoke-VersionCheck $exePath $Entry.version_args $Entry.version $Name
    return @{ exe = (Resolve-Path $exePath).Path; version = $Entry.version; version_output = $raw }
}

$resolved = @{}
foreach ($name in $lock.scanners.PSObject.Properties.Name) {
    $entry = $lock.scanners.$name
    Write-Step "$name ($($entry.channel))"
    if ($entry.channel -eq 'github-release') {
        $resolved[$name] = Install-ReleaseBinary $name $entry
    }
    elseif ($entry.channel -eq 'uv-tool') {
        $resolved[$name] = Install-UvTool $name $entry
    }
    else { Die "unknown channel '$($entry.channel)' for $name" }
}

$resolved | ConvertTo-Json -Depth 5 | Out-File -FilePath $ResolvedPath -Encoding utf8
Write-Host ""
Write-Host "All scanners verified. Resolved paths -> tools/resolved.json" -ForegroundColor Green
```

- [ ] **Step 7: Run the bootstrap**

```powershell
.\tools\bootstrap.ps1
```

Expected: three `OK` lines with the pinned versions, and `tools/resolved.json` created. If Checkov's `--version` prints something that does not literally contain `3.3.12`, capture the real output and relax `Invoke-VersionCheck` for that scanner only — do not weaken it globally.

- [ ] **Step 8: Verify idempotence**

```powershell
.\tools\bootstrap.ps1 -Verify
```

Expected: same three `OK` lines, no downloads.

- [ ] **Step 9: Prove the checksum guard actually fires**

A verification that never fails is not a verification. Corrupt the cached archive and confirm the hard failure, then restore:

```powershell
$p = "tools\cache\trivy_0.74.0_windows-64bit.zip"
Copy-Item $p "$p.bak"
Add-Content -Path $p -Value "corrupt"
Remove-Item tools\bin\trivy.exe
.\tools\bootstrap.ps1        # expect: FAIL checksum mismatch, exit 1
Move-Item "$p.bak" $p -Force
.\tools\bootstrap.ps1        # expect: recovers, OK
```

- [ ] **Step 10: Commit**

```bash
git add tools/scanners.lock.json tools/bootstrap.ps1 tests/test_scanners_lock.py .gitignore
git commit -m "build: pin and checksum-verify Checkov 3.3.12, Trivy 0.74.0, tfsec 1.28.14"
```

---

## Task 4: Vendor corpus v0

**Files:**
- Create: `tools/corpus.lock.json`, `tools/vendor_corpus.ps1`, `corpus/vendor/SOURCES.md`
- Test: `tests/test_corpus_lock.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `corpus/vendor/terragoat/`, `corpus/vendor/kubernetes-goat/`, and `tools/corpus.lock.json` — whose `cases` array Task 8's runner iterates.

Corpus v0 is the vendored public repos only. Contrastive pairs and scenarios are S2 (spec §1).

- [ ] **Step 1: Write the failing test**

`tests/test_corpus_lock.py`:

```python
"""Corpus v0 must be pinned, licensed, and span all five tested categories."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "tools" / "corpus.lock.json"

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
CATEGORIES = {"storage", "networking", "iam", "compute", "containers"}


def _lock() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def test_sources_pinned_to_a_commit_and_licensed() -> None:
    sources = _lock()["sources"]
    assert set(sources) == {"terragoat", "kubernetes-goat"}
    for name, entry in sources.items():
        assert SHA1_RE.match(entry["commit"]), f"{name} commit is not a full SHA"
        assert entry["license"], f"{name} license not recorded"
        assert entry["url"].startswith("https://github.com/"), f"{name} url"


def test_cases_declare_a_platform_and_category() -> None:
    for case in _lock()["cases"]:
        assert case["platform"] in {"terraform", "kubernetes"}
        assert case["category"] in CATEGORIES, f"{case['id']} bad category"
        assert case["path"], f"{case['id']} missing path"


def test_case_ids_are_unique() -> None:
    ids = [c["id"] for c in _lock()["cases"]]
    assert len(ids) == len(set(ids)), "duplicate case ids"


def test_all_five_categories_are_represented() -> None:
    """PLAN.md Q6 requires coverage across all five domains."""
    covered = {c["category"] for c in _lock()["cases"]}
    assert covered == CATEGORIES, f"missing categories: {sorted(CATEGORIES - covered)}"


def test_containers_come_from_kubernetes() -> None:
    for case in _lock()["cases"]:
        if case["category"] == "containers":
            assert case["platform"] == "kubernetes", f"{case['id']} containers must be k8s"
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/test_corpus_lock.py -v
```

Expected: FAIL — `FileNotFoundError` for `tools/corpus.lock.json`.

- [ ] **Step 3: Create `tools/corpus.lock.json`**

Commit SHAs and licenses verified against the GitHub API on 2026-08-24. Scope to TerraGoat's **AWS** tree only — it already covers storage, networking, IAM, and compute, and adding four more clouds would inflate the inventory without adding categories.

```json
{
  "schema_version": 1,
  "recorded_utc": "2026-08-24",
  "note": "Corpus v0: vendored public repos only. Contrastive pairs and scenario configs are authored in S2, after the taxonomy exists.",
  "sources": {
    "terragoat": {
      "url": "https://github.com/bridgecrewio/terragoat",
      "commit": "729f8da62c6a85ce4af5ad3d123de97776d954c4",
      "ref": "master",
      "license": "Apache-2.0",
      "retrieved_utc": "2026-08-24",
      "subtree": "terraform/aws",
      "scope_note": "AWS only. alicloud/azure/gcp/oracle omitted - they add rule volume, not category coverage."
    },
    "kubernetes-goat": {
      "url": "https://github.com/madhuakula/kubernetes-goat",
      "commit": "723a0db478f050d173d23b4ce5044b65bce0bdd0",
      "ref": "master",
      "license": "MIT",
      "retrieved_utc": "2026-08-24",
      "subtree": "scenarios"
    }
  },
  "cases": [
    {
      "id": "tg-aws-s3",
      "platform": "terraform",
      "category": "storage",
      "path": "corpus/vendor/terragoat/terraform/aws/s3.tf"
    },
    {
      "id": "tg-aws-networking",
      "platform": "terraform",
      "category": "networking",
      "path": "corpus/vendor/terragoat/terraform/aws/vpc.tf"
    },
    {
      "id": "tg-aws-iam",
      "platform": "terraform",
      "category": "iam",
      "path": "corpus/vendor/terragoat/terraform/aws/iam.tf"
    },
    {
      "id": "tg-aws-compute",
      "platform": "terraform",
      "category": "compute",
      "path": "corpus/vendor/terragoat/terraform/aws/ec2.tf"
    },
    {
      "id": "kg-scenarios",
      "platform": "kubernetes",
      "category": "containers",
      "path": "corpus/vendor/kubernetes-goat/scenarios"
    }
  ]
}
```

The four TerraGoat filenames are the expected layout, not a verified fact. Step 5 checks them and corrects this file if upstream differs — the test in Step 7 will catch any path that does not exist.

- [ ] **Step 4: Create `tools/vendor_corpus.ps1`**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Vendor corpus v0 at the commits pinned in tools/corpus.lock.json.
.DESCRIPTION
    Clones each source into tools/cache, checks out the exact pinned commit,
    then copies the declared subtree into corpus/vendor/<name>/ as a plain
    directory - not a submodule, so the dissertation artifact stays complete
    when archived. Upstream .git is not copied. Writes SOURCES.md attribution.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CacheDir = Join-Path $RepoRoot 'tools\cache'
$VendorDir = Join-Path $RepoRoot 'corpus\vendor'
$LockPath = Join-Path $RepoRoot 'tools\corpus.lock.json'

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m) { Write-Host "    OK   $m" -ForegroundColor Green }
function Die($m) { Write-Host "    FAIL $m" -ForegroundColor Red; exit 1 }

$lock = Get-Content $LockPath -Raw | ConvertFrom-Json
foreach ($d in @($CacheDir, $VendorDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Corpus v0 - vendored sources')
$lines.Add('')
$lines.Add('Generated by `tools/vendor_corpus.ps1` from `tools/corpus.lock.json`. Do not edit by hand.')
$lines.Add('')
$lines.Add('These are third-party deliberately-insecure IaC repositories, vendored at')
$lines.Add('exact commits for evaluation reproducibility. Original licenses apply and')
$lines.Add('each upstream LICENSE file is retained alongside the vendored tree.')
$lines.Add('')

foreach ($name in $lock.sources.PSObject.Properties.Name) {
    $src = $lock.sources.$name
    $clone = Join-Path $CacheDir "$name.git"
    $dest = Join-Path $VendorDir $name

    if (-not (Test-Path $clone)) {
        Write-Step "cloning $name"
        & git clone --quiet $src.url $clone
        if ($LASTEXITCODE -ne 0) { Die "git clone $($src.url) failed" }
    }

    Write-Step "checking out $name @ $($src.commit.Substring(0,12))"
    & git -C $clone fetch --quiet origin
    & git -C $clone checkout --quiet $src.commit
    if ($LASTEXITCODE -ne 0) { Die "checkout $($src.commit) failed for $name" }

    $actual = (& git -C $clone rev-parse HEAD).Trim()
    if ($actual -ne $src.commit) { Die "$name HEAD is $actual, expected $($src.commit)" }
    Write-Ok "$name pinned at $actual"

    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $subtreeSrc = Join-Path $clone ($src.subtree -replace '/', '\')
    if (-not (Test-Path $subtreeSrc)) { Die "$name subtree '$($src.subtree)' not found upstream" }
    $subtreeDest = Join-Path $dest ($src.subtree -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $subtreeDest) | Out-Null
    Copy-Item $subtreeSrc $subtreeDest -Recurse -Force

    $licenseSrc = Join-Path $clone 'LICENSE'
    if (Test-Path $licenseSrc) { Copy-Item $licenseSrc (Join-Path $dest 'LICENSE') -Force }
    else { Write-Host "    WARN no LICENSE file found upstream for $name" -ForegroundColor Yellow }

    $fileCount = (Get-ChildItem $dest -Recurse -File).Count
    Write-Ok "$name vendored ($fileCount files)"

    $lines.Add("## $name")
    $lines.Add('')
    $lines.Add("- Upstream: <$($src.url)>")
    $lines.Add("- Commit: ``$($src.commit)`` (ref ``$($src.ref)``)")
    $lines.Add("- License: $($src.license)")
    $lines.Add("- Retrieved: $($src.retrieved_utc)")
    $lines.Add("- Vendored subtree: ``$($src.subtree)``")
    if ($src.PSObject.Properties.Name -contains 'scope_note') {
        $lines.Add("- Scope: $($src.scope_note)")
    }
    $lines.Add('')
}

$outPath = Join-Path $VendorDir 'SOURCES.md'
[IO.File]::WriteAllText($outPath, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding $false))
Write-Host ""
Write-Host "Wrote $outPath" -ForegroundColor Green
```

- [ ] **Step 5: Run it, then correct the case paths against reality**

```powershell
.\tools\vendor_corpus.ps1
Get-ChildItem corpus\vendor\terragoat\terraform\aws -Filter *.tf | Select-Object Name
Get-ChildItem corpus\vendor\kubernetes-goat\scenarios -Recurse -Include *.yaml,*.yml | Measure-Object
```

Compare the real `.tf` filenames against the four `path` values in `corpus.lock.json` and edit that file to match. TerraGoat may name them differently (e.g. `s3.tf` vs `s3_bucket.tf`), or split networking across several files — if a category needs more than one file, point `path` at the directory and record which resources cover it.

- [ ] **Step 6: Add a path-existence test**

Append to `tests/test_corpus_lock.py`:

```python
def test_every_case_path_exists_on_disk() -> None:
    """A pinned case that is not vendored would silently drop a category."""
    missing = [
        case["id"] for case in _lock()["cases"] if not (REPO_ROOT / case["path"]).exists()
    ]
    assert missing == [], (
        f"vendored paths missing for {missing}; run tools/vendor_corpus.ps1 "
        "and correct tools/corpus.lock.json to match the real upstream layout"
    )
```

- [ ] **Step 7: Run tests to verify they pass**

```powershell
uv run pytest tests/test_corpus_lock.py -v
```

Expected: 6 passed. If `test_every_case_path_exists_on_disk` fails, the lockfile still disagrees with upstream — fix the lockfile, not the test.

- [ ] **Step 8: Commit**

```bash
git add tools/corpus.lock.json tools/vendor_corpus.ps1 tests/test_corpus_lock.py corpus/
git commit -m "corpus: vendor TerraGoat + KubeGoat at pinned commits with attribution"
```

---

## Task 5: Capture real scanner JSON

**Files:**
- Create: `tools/harvest/__init__.py`, `tools/harvest/model.py`, `tools/capture_fixtures.ps1`
- Create (captured output): `tests/harvest/fixtures/<scanner>.json`
- Test: `tests/harvest/test_model.py`

**Interfaces:**
- Consumes: `tools/resolved.json` (Task 3), `corpus/vendor/` (Task 4).
- Produces: `InventoryRow` frozen dataclass with fields `scanner: str`, `rule_id: str`, `native_severity: str | None`, `target: str`, `case_id: str`; plus real captured JSON fixtures that Task 6's walkers are written against.

Spec §5 requires the JSON schemas be **established, not assumed**. So the fixtures are captured *before* the walkers are written.

- [ ] **Step 1: Write the failing test**

`tests/harvest/test_model.py`:

```python
"""InventoryRow is deliberately minimal - it is not S3's normalized finding."""

from __future__ import annotations

import dataclasses

import pytest

from tools.harvest.model import InventoryRow


def test_row_is_frozen_and_hashable() -> None:
    row = InventoryRow(
        scanner="trivy", rule_id="AVD-AWS-0001", native_severity="HIGH",
        target="s3.tf", case_id="tg-aws-s3",
    )
    assert dataclasses.is_dataclass(row)
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.scanner = "checkov"  # type: ignore[misc]
    assert len({row, row}) == 1


def test_missing_severity_is_none_never_a_default_level() -> None:
    """PLAN.md R3-#4: absent severity is an explicit state, never silently low."""
    row = InventoryRow(
        scanner="checkov", rule_id="CKV_AWS_1", native_severity=None,
        target="s3.tf", case_id="tg-aws-s3",
    )
    assert row.native_severity is None


def test_row_has_no_scored_or_normalized_fields() -> None:
    """Guards the S0/S3 boundary: no context, no score, no issue-class here."""
    fields = {f.name for f in dataclasses.fields(InventoryRow)}
    assert fields == {"scanner", "rule_id", "native_severity", "target", "case_id"}
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/harvest/test_model.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.harvest'`.

- [ ] **Step 3: Create the harvest package and model**

`tools/__init__.py` — create it empty so `tools.harvest` is importable.

`tools/harvest/__init__.py`:

```python
"""Rule-ID inventory harvest - a research instrument, NOT pipeline code.

Invokes each pinned scanner over corpus v0, stores raw JSON, and tallies
observed rule IDs and native severities.

This package deliberately does NOT build the normalized finding record of
PLAN.md layer 2. That is sub-project S3 and depends on the issue-class
taxonomy, which does not exist yet. `InventoryRow` is named to keep that
boundary visible; tests/test_architecture.py enforces it.
"""
```

`tools/harvest/model.py`:

```python
"""The only record type harvest produces."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InventoryRow:
    """One scanner rule firing, recorded verbatim.

    Deliberately shallow: no issue-class, no context, no score. Those belong
    to S3/S4 and depend on specs that do not exist yet.
    """

    scanner: str
    """Which scanner produced this: "checkov" | "trivy" | "tfsec"."""

    rule_id: str
    """The scanner's own rule identifier, unmodified."""

    native_severity: str | None
    """The scanner's own severity string, or None when it emitted none.

    None is a first-class state, never coerced to a default level
    (PLAN.md R3-#4). The rate of None is a reported metric.
    """

    target: str
    """File path exactly as the scanner reported it - separators unmodified.

    Preserved raw so S1's canonical-identity spec can be written against
    real observed path formats, including Windows backslashes.
    """

    case_id: str
    """The corpus.lock.json case that produced this row."""
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
uv run pytest tests/harvest/test_model.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Create `tools/capture_fixtures.ps1`**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Capture one real JSON output per scanner for use as a test fixture.
.DESCRIPTION
    Spec section 5 requires each scanner's JSON schema be established
    empirically rather than assumed. This runs each scanner against a single
    small corpus target and writes the raw stdout to tests/harvest/fixtures/.
    It also records observed exit codes and whether tfsec, pointed at
    Kubernetes YAML, fails or silently reports nothing.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'   # scanners exit non-zero on findings by design
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$FixtureDir = Join-Path $RepoRoot 'tests\harvest\fixtures'
$Resolved = Get-Content (Join-Path $RepoRoot 'tools\resolved.json') -Raw | ConvertFrom-Json
$Lock = Get-Content (Join-Path $RepoRoot 'tools\corpus.lock.json') -Raw | ConvertFrom-Json

if (-not (Test-Path $FixtureDir)) { New-Item -ItemType Directory -Force -Path $FixtureDir | Out-Null }

$tfCase = ($Lock.cases | Where-Object { $_.platform -eq 'terraform' })[0]
$k8sCase = ($Lock.cases | Where-Object { $_.platform -eq 'kubernetes' })[0]
$tfDir = Join-Path $RepoRoot (Split-Path -Parent $tfCase.path)
$k8sDir = Join-Path $RepoRoot $k8sCase.path

$observations = @()

function Capture($Name, $Exe, $ScannerArgs, $Label) {
    Write-Host "==> $Name on $Label" -ForegroundColor Cyan
    $out = & $Exe @ScannerArgs 2>&1 | Out-String
    $code = $LASTEXITCODE
    $path = Join-Path $FixtureDir "$Name-$Label.json"
    [IO.File]::WriteAllText($path, $out, (New-Object Text.UTF8Encoding $false))
    $isJson = $true
    try { $out | ConvertFrom-Json | Out-Null } catch { $isJson = $false }
    Write-Host "    exit=$code json=$isJson bytes=$($out.Length) -> $path"
    return [pscustomobject]@{
        scanner = $Name; input_platform = $Label; exit_code = $code
        parses_as_json = $isJson; bytes = $out.Length
    }
}

$observations += Capture 'checkov' $Resolved.checkov.exe @('-d', $tfDir, '-o', 'json', '--compact') 'terraform'
$observations += Capture 'checkov' $Resolved.checkov.exe @('-d', $k8sDir, '-o', 'json', '--compact') 'kubernetes'
$observations += Capture 'trivy'   $Resolved.trivy.exe   @('config', '--format', 'json', $tfDir) 'terraform'
$observations += Capture 'trivy'   $Resolved.trivy.exe   @('config', '--format', 'json', $k8sDir) 'kubernetes'
$observations += Capture 'tfsec'   $Resolved.tfsec.exe   @('--format', 'json', $tfDir) 'terraform'
# Deliberate off-platform probe: spec section 5.2. Records what tfsec ACTUALLY
# does on K8s YAML, which decides the fail-loudly logic in S3.
$observations += Capture 'tfsec'   $Resolved.tfsec.exe   @('--format', 'json', $k8sDir) 'kubernetes'

$obsPath = Join-Path $RepoRoot 'artifacts\scanner-behavior.json'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $obsPath) | Out-Null
$observations | ConvertTo-Json -Depth 5 | Out-File $obsPath -Encoding utf8
Write-Host ""
Write-Host "Observed behavior -> artifacts/scanner-behavior.json" -ForegroundColor Green
$observations | Format-Table -AutoSize
```

- [ ] **Step 6: Run the capture**

```powershell
.\tools\capture_fixtures.ps1
```

Expected: six fixture files in `tests/harvest/fixtures/`, plus `artifacts/scanner-behavior.json`. If a scanner's flags are wrong, run it with `--help` and fix the argument array. Read each fixture before moving on — Task 6's walkers are written from these, not from assumption.

- [ ] **Step 7: Record the observed facts in the spec**

Append an `## Appendix — observed scanner behaviour (S0)` section to `docs/superpowers/specs/2026-08-24-implementation-phase0-design.md` answering spec §5 items 1, 2 and 4 concretely: the rule-ID and severity JSON field path per scanner; tfsec's exit code and output on Kubernetes input; and whether Checkov emits backslash paths.

- [ ] **Step 8: Commit**

```bash
git add tools/__init__.py tools/harvest/ tools/capture_fixtures.ps1 tests/harvest/ artifacts/scanner-behavior.json docs/superpowers/specs/
git commit -m "harvest: capture real scanner JSON fixtures and observed platform behaviour"
```

---

## Task 6: Per-scanner JSON walkers

**Files:**
- Create: `tools/harvest/walkers.py`
- Test: `tests/harvest/test_walkers.py`

**Interfaces:**
- Consumes: `InventoryRow` (Task 5); the captured fixtures (Task 5).
- Produces: `walk(scanner: str, doc: object, case_id: str) -> list[InventoryRow]` and `WALKERS: dict[str, Callable[[object, str], list[InventoryRow]]]`, used by Task 8's runner.

The field paths below are the **starting hypothesis**. Correct them against the fixtures captured in Task 5 — the fixture is the authority.

- [ ] **Step 1: Write the failing test**

`tests/harvest/test_walkers.py`:

```python
"""Walkers turn each scanner's own JSON shape into InventoryRows.

Two layers of test: hand-written minimal documents that pin the contract, and
a golden-fixture test that runs against the real captured output so schema
drift between pinned versions is caught (PLAN.md risk: scanner schema drift).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.harvest.walkers import WALKERS, walk

FIXTURES = Path(__file__).parent / "fixtures"


def test_unknown_scanner_raises() -> None:
    with pytest.raises(KeyError):
        walk("nessus", {}, "case-1")


def test_checkov_failed_checks_become_rows() -> None:
    doc = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "severity": None,
                    "file_path": "\\terraform\\aws\\s3.tf",
                    "resource": "aws_s3_bucket.data",
                },
                {
                    "check_id": "CKV_AWS_21",
                    "severity": "HIGH",
                    "file_path": "\\terraform\\aws\\s3.tf",
                    "resource": "aws_s3_bucket.data",
                },
            ],
            "passed_checks": [
                {"check_id": "CKV_AWS_99", "file_path": "\\x.tf", "resource": "r"}
            ],
        },
    }
    rows = walk("checkov", doc, "tg-aws-s3")

    assert [r.rule_id for r in rows] == ["CKV_AWS_18", "CKV_AWS_21"], "passed checks are not findings"
    assert rows[0].native_severity is None, "absent severity stays None, never defaulted"
    assert rows[1].native_severity == "HIGH"
    assert rows[0].target == "\\terraform\\aws\\s3.tf", "path separators preserved verbatim"
    assert all(r.scanner == "checkov" and r.case_id == "tg-aws-s3" for r in rows)


def test_checkov_accepts_a_list_of_run_documents() -> None:
    """Checkov emits a JSON array when more than one check_type runs."""
    doc = [
        {"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": "CKV_AWS_18", "severity": "LOW", "file_path": "a.tf", "resource": "r"}]}},
        {"check_type": "kubernetes", "results": {"failed_checks": [
            {"check_id": "CKV_K8S_20", "severity": "MEDIUM", "file_path": "b.yaml", "resource": "r"}]}},
    ]
    rows = walk("checkov", doc, "mixed")
    assert {r.rule_id for r in rows} == {"CKV_AWS_18", "CKV_K8S_20"}


def test_trivy_misconfigurations_become_rows() -> None:
    doc = {
        "Results": [
            {
                "Target": "terraform/aws/s3.tf",
                "Misconfigurations": [
                    {"ID": "AVD-AWS-0088", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "AVD-AWS-0089", "Severity": "LOW", "Status": "FAIL"},
                ],
            },
            {"Target": "terraform/aws/empty.tf"},  # no Misconfigurations key at all
        ]
    }
    rows = walk("trivy", doc, "tg-aws-s3")
    assert [r.rule_id for r in rows] == ["AVD-AWS-0088", "AVD-AWS-0089"]
    assert rows[0].target == "terraform/aws/s3.tf"
    assert all(r.scanner == "trivy" for r in rows)


def test_trivy_tolerates_a_null_results_key() -> None:
    """Trivy emits "Results": null when it finds nothing scannable."""
    assert walk("trivy", {"Results": None}, "empty") == []
    assert walk("trivy", {}, "empty") == []


def test_tfsec_results_become_rows() -> None:
    doc = {
        "results": [
            {
                "rule_id": "aws-s3-enable-bucket-logging",
                "severity": "MEDIUM",
                "location": {"filename": "terraform/aws/s3.tf", "start_line": 12},
            }
        ]
    }
    rows = walk("tfsec", doc, "tg-aws-s3")
    assert rows[0].rule_id == "aws-s3-enable-bucket-logging"
    assert rows[0].native_severity == "MEDIUM"
    assert rows[0].target == "terraform/aws/s3.tf"


def test_tfsec_tolerates_a_null_results_key() -> None:
    """tfsec emits "results": null on a clean or unparseable target."""
    assert walk("tfsec", {"results": None}, "empty") == []


def test_every_scanner_in_the_registry_has_a_walker() -> None:
    assert set(WALKERS) == {"checkov", "trivy", "tfsec"}


@pytest.mark.parametrize("fixture", sorted(FIXTURES.glob("*.json")))
def test_walker_handles_the_real_captured_output(fixture: Path) -> None:
    """Golden-fixture test: the pinned versions' real output must still parse.

    This is the schema-drift tripwire PLAN.md names as the mitigation for
    scanner output-schema change between pinned versions.
    """
    scanner = fixture.stem.split("-")[0]
    text = fixture.read_text(encoding="utf-8").strip()
    if not text:
        pytest.skip(f"{fixture.name} is empty - see artifacts/scanner-behavior.json")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        pytest.skip(f"{fixture.name} is not JSON - recorded in artifacts/scanner-behavior.json")

    rows = walk(scanner, doc, fixture.stem)
    for row in rows:
        assert row.rule_id, f"empty rule_id in {fixture.name}"
        assert row.scanner == scanner
        assert row.case_id == fixture.stem
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/harvest/test_walkers.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.harvest.walkers'`.

- [ ] **Step 3: Write `tools/harvest/walkers.py`**

```python
"""One walker per scanner JSON schema. Pure functions - no I/O, no subprocess.

Field paths were derived from real captured output (tests/harvest/fixtures/,
see artifacts/scanner-behavior.json). Keep them keyed to the pinned versions in
tools/scanners.lock.json; the golden-fixture test is the drift tripwire.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from tools.harvest.model import InventoryRow

Walker = Callable[[Any, str], list[InventoryRow]]


def _clean(value: Any) -> str | None:
    """Normalize an absent-or-blank severity to None.

    Scanners variously emit null, "", or "UNKNOWN". All three mean the same
    thing: no usable native severity. Never substitute a level here
    (PLAN.md R3-#4) - the rate of None is a reported metric.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.upper() in {"UNKNOWN", "NONE", "NULL"}:
        return None
    return text


def walk_checkov(doc: Any, case_id: str) -> list[InventoryRow]:
    """Checkov: {"results": {"failed_checks": [...]}}, or a list of those.

    Only failed_checks are findings; passed_checks are not.
    """
    documents: Iterable[Any] = doc if isinstance(doc, list) else [doc]
    rows: list[InventoryRow] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        results = document.get("results") or {}
        for check in results.get("failed_checks") or []:
            rule_id = check.get("check_id")
            if not rule_id:
                continue
            rows.append(
                InventoryRow(
                    scanner="checkov",
                    rule_id=str(rule_id),
                    native_severity=_clean(check.get("severity")),
                    target=str(check.get("file_path") or ""),
                    case_id=case_id,
                )
            )
    return rows


def walk_trivy(doc: Any, case_id: str) -> list[InventoryRow]:
    """Trivy: {"Results": [{"Target": ..., "Misconfigurations": [...]}]}."""
    rows: list[InventoryRow] = []
    if not isinstance(doc, dict):
        return rows
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for misconf in result.get("Misconfigurations") or []:
            rule_id = misconf.get("ID") or misconf.get("AVDID")
            if not rule_id:
                continue
            rows.append(
                InventoryRow(
                    scanner="trivy",
                    rule_id=str(rule_id),
                    native_severity=_clean(misconf.get("Severity")),
                    target=target,
                    case_id=case_id,
                )
            )
    return rows


def walk_tfsec(doc: Any, case_id: str) -> list[InventoryRow]:
    """tfsec: {"results": [{"rule_id": ..., "location": {"filename": ...}}]}."""
    rows: list[InventoryRow] = []
    if not isinstance(doc, dict):
        return rows
    for result in doc.get("results") or []:
        if not isinstance(result, dict):
            continue
        rule_id = result.get("rule_id") or result.get("long_id")
        if not rule_id:
            continue
        location = result.get("location") or {}
        rows.append(
            InventoryRow(
                scanner="tfsec",
                rule_id=str(rule_id),
                native_severity=_clean(result.get("severity")),
                target=str(location.get("filename") or ""),
                case_id=case_id,
            )
        )
    return rows


WALKERS: dict[str, Walker] = {
    "checkov": walk_checkov,
    "trivy": walk_trivy,
    "tfsec": walk_tfsec,
}


def walk(scanner: str, doc: Any, case_id: str) -> list[InventoryRow]:
    """Dispatch to the walker for `scanner`. Raises KeyError if unregistered."""
    return WALKERS[scanner](doc, case_id)
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
uv run pytest tests/harvest/test_walkers.py -v
```

Expected: all pass. If a golden-fixture test fails, the hypothesized field path is wrong for the pinned version — **change `walkers.py` to match the fixture**, never edit the fixture to match the code.

- [ ] **Step 5: Lint and type-check**

```powershell
uv run ruff check . ; uv run mypy tools
```

- [ ] **Step 6: Commit**

```bash
git add tools/harvest/walkers.py tests/harvest/test_walkers.py
git commit -m "harvest: per-scanner JSON walkers with golden-fixture drift tests"
```

---

## Task 7: Tally and provenance

**Files:**
- Create: `tools/harvest/tally.py`, `tools/harvest/provenance.py`
- Test: `tests/harvest/test_tally.py`, `tests/harvest/test_provenance.py`

**Interfaces:**
- Consumes: `InventoryRow` (Task 5).
- Produces: `tally(rows: Iterable[InventoryRow]) -> dict[str, Any]` and `build_provenance(repo_root: Path) -> dict[str, Any]`, both called by Task 8's runner.

- [ ] **Step 1: Write the failing tally test**

`tests/harvest/test_tally.py`:

```python
"""The inventory is the S0 deliverable: what fired, how often, how much severity."""

from __future__ import annotations

from tools.harvest.model import InventoryRow
from tools.harvest.tally import tally


def _row(scanner: str, rule_id: str, severity: str | None, case_id: str = "c1") -> InventoryRow:
    return InventoryRow(
        scanner=scanner, rule_id=rule_id, native_severity=severity,
        target="x.tf", case_id=case_id,
    )


def test_empty_input_yields_zeroed_totals_not_a_crash() -> None:
    out = tally([])
    assert out["totals"]["rows"] == 0
    assert out["totals"]["distinct_rule_ids"] == 0
    assert out["by_scanner"] == {}


def test_counts_rows_and_distinct_rule_ids() -> None:
    rows = [
        _row("checkov", "CKV_AWS_18", "HIGH"),
        _row("checkov", "CKV_AWS_18", "HIGH", case_id="c2"),
        _row("checkov", "CKV_AWS_21", "LOW"),
        _row("trivy", "AVD-AWS-0088", "HIGH"),
    ]
    out = tally(rows)
    assert out["totals"]["rows"] == 4
    assert out["totals"]["distinct_rule_ids"] == 3
    assert out["by_scanner"]["checkov"]["rows"] == 3
    assert out["by_scanner"]["checkov"]["distinct_rule_ids"] == 2
    assert out["by_scanner"]["trivy"]["rows"] == 1


def test_missing_severity_rate_is_reported_per_scanner() -> None:
    """PLAN.md R3-#4 requires the missing-severity rate, not a silent default."""
    rows = [
        _row("checkov", "CKV_AWS_18", None),
        _row("checkov", "CKV_AWS_21", None),
        _row("checkov", "CKV_AWS_22", "HIGH"),
        _row("trivy", "AVD-AWS-0088", "HIGH"),
    ]
    out = tally(rows)
    ck = out["by_scanner"]["checkov"]
    assert ck["missing_severity_rows"] == 2
    assert ck["missing_severity_rate"] == 0.667
    assert out["by_scanner"]["trivy"]["missing_severity_rate"] == 0.0
    assert out["totals"]["missing_severity_rate"] == 0.5


def test_rule_ids_are_listed_sorted_for_stable_diffs() -> None:
    """The inventory is committed, so its ordering must be deterministic."""
    rows = [_row("trivy", "AVD-B", "LOW"), _row("trivy", "AVD-A", "LOW")]
    out = tally(rows)
    assert out["by_scanner"]["trivy"]["rule_ids"] == ["AVD-A", "AVD-B"]


def test_observed_severity_levels_are_collected() -> None:
    """S1's severity-normalization table needs the real level vocabulary."""
    rows = [
        _row("trivy", "AVD-A", "CRITICAL"),
        _row("trivy", "AVD-B", "low"),
        _row("trivy", "AVD-C", None),
    ]
    out = tally(rows)
    assert out["by_scanner"]["trivy"]["observed_severity_levels"] == ["CRITICAL", "low"]
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/harvest/test_tally.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.harvest.tally'`.

- [ ] **Step 3: Write `tools/harvest/tally.py`**

```python
"""Aggregate InventoryRows into the committed rule inventory.

Output feeds two S1 deliverables directly: the rule_ids lists become the
taxonomy's mapping domain, and observed_severity_levels becomes the
severity-normalization table's input vocabulary.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from tools.harvest.model import InventoryRow


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 3)


def tally(rows: Iterable[InventoryRow]) -> dict[str, Any]:
    """Summarize rows per scanner and overall.

    Every list in the output is sorted so the committed inventory diffs
    cleanly between runs.
    """
    materialized = list(rows)

    by_scanner_rows: dict[str, list[InventoryRow]] = defaultdict(list)
    for row in materialized:
        by_scanner_rows[row.scanner].append(row)

    by_scanner: dict[str, Any] = {}
    for scanner in sorted(by_scanner_rows):
        scanner_rows = by_scanner_rows[scanner]
        missing = sum(1 for r in scanner_rows if r.native_severity is None)
        levels = {r.native_severity for r in scanner_rows if r.native_severity is not None}
        by_scanner[scanner] = {
            "rows": len(scanner_rows),
            "distinct_rule_ids": len({r.rule_id for r in scanner_rows}),
            "rule_ids": sorted({r.rule_id for r in scanner_rows}),
            "missing_severity_rows": missing,
            "missing_severity_rate": _rate(missing, len(scanner_rows)),
            "observed_severity_levels": sorted(levels),
            "cases": sorted({r.case_id for r in scanner_rows}),
        }

    total_missing = sum(1 for r in materialized if r.native_severity is None)
    return {
        "totals": {
            "rows": len(materialized),
            "distinct_rule_ids": len({r.rule_id for r in materialized}),
            "missing_severity_rows": total_missing,
            "missing_severity_rate": _rate(total_missing, len(materialized)),
            "scanners": sorted(by_scanner),
        },
        "by_scanner": by_scanner,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
uv run pytest tests/harvest/test_tally.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Write the failing provenance test**

`tests/harvest/test_provenance.py`:

```python
"""Every output carries enough provenance to be reproduced (spec section 4.4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.harvest.provenance import build_provenance, hash_file


def test_hash_file_is_stable_and_hex(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    digest = hash_file(target)
    assert digest == hash_file(target)
    assert len(digest) == 64
    assert digest == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_provenance_records_scanner_versions_and_python(tmp_path: Path) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_text(
        json.dumps({
            "trivy": {"exe": "C:\\bin\\trivy.exe", "version": "0.74.0"},
            "checkov": {"exe": "C:\\bin\\checkov.exe", "version": "3.3.12"},
        }),
        encoding="utf-8",
    )

    prov = build_provenance(tmp_path)

    assert prov["scanners"]["trivy"]["version"] == "0.74.0"
    assert prov["scanners"]["trivy"]["exe"] == "C:\\bin\\trivy.exe"
    assert prov["python"].startswith("3.12")
    assert prov["generated_utc"].endswith("Z")
    assert prov["spec_hashes"] == {}, "no specs/ dir in this fixture yet"


def test_provenance_hashes_every_spec_file(tmp_path: Path) -> None:
    """S1's spec artifacts get hashed so a result names the rubric that made it."""
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_text("{}", encoding="utf-8")
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "rubric.yaml").write_text("factors: []\n", encoding="utf-8")
    (specs / "taxonomy.yaml").write_text("classes: []\n", encoding="utf-8")

    prov = build_provenance(tmp_path)

    assert set(prov["spec_hashes"]) == {"specs/rubric.yaml", "specs/taxonomy.yaml"}
    assert all(len(h) == 64 for h in prov["spec_hashes"].values())


def test_missing_resolved_json_is_an_explicit_error(tmp_path: Path) -> None:
    """Silently emitting a result with no scanner provenance is worse than failing."""
    with pytest.raises(FileNotFoundError, match="resolved.json"):
        build_provenance(tmp_path)
```

- [ ] **Step 6: Run and confirm it fails**

```powershell
uv run pytest tests/harvest/test_provenance.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.harvest.provenance'`.

- [ ] **Step 7: Write `tools/harvest/provenance.py`**

```python
"""Provenance block: makes every emitted artifact self-describing.

A reviewer holding only the output JSON can tell which scanner binaries,
interpreter, spec files and corpus commit produced it - which is what makes a
dissertation number reproducible from the artifact alone (spec section 4.4).
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def hash_file(path: Path) -> str:
    """SHA256 of a file's bytes, hex-encoded.

    Bytes, not text: this is why .gitattributes forces LF for specs/ and
    artifacts/. CRLF renormalization would silently change these digests.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit(repo_root: Path) -> str | None:
    """Current HEAD, or None outside a git checkout."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return result.stdout.strip() or None


def build_provenance(repo_root: Path) -> dict[str, Any]:
    """Assemble the provenance block.

    Raises FileNotFoundError if tools/resolved.json is absent - emitting a
    result with no scanner provenance would be worse than failing here.
    """
    resolved_path = repo_root / "tools" / "resolved.json"
    if not resolved_path.exists():
        raise FileNotFoundError(
            f"resolved.json not found at {resolved_path}; run tools/bootstrap.ps1 first"
        )
    resolved = json.loads(resolved_path.read_text(encoding="utf-8"))

    specs_dir = repo_root / "specs"
    spec_hashes: dict[str, str] = {}
    if specs_dir.is_dir():
        for path in sorted(specs_dir.rglob("*")):
            if path.is_file():
                spec_hashes[path.relative_to(repo_root).as_posix()] = hash_file(path)

    return {
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "host": {"system": platform.system(), "release": platform.release()},
        "repo_commit": _git_commit(repo_root),
        "scanners": {
            name: {"exe": entry.get("exe"), "version": entry.get("version")}
            for name, entry in sorted(resolved.items())
        },
        "spec_hashes": spec_hashes,
    }
```

- [ ] **Step 8: Run tests to verify they pass**

```powershell
uv run pytest tests/harvest/ -v
```

Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add tools/harvest/tally.py tools/harvest/provenance.py tests/harvest/test_tally.py tests/harvest/test_provenance.py
git commit -m "harvest: severity-aware tally and reproducibility provenance block"
```

---

## Task 8: Run the harvest and close the S0 gate

**Files:**
- Create: `tools/harvest/run.py`
- Create (generated): `artifacts/rule-inventory.json`, `artifacts/raw/<scanner>/<case>.json`
- Modify: `CLAUDE.md`
- Test: `tests/harvest/test_run.py`

**Interfaces:**
- Consumes: `walk`/`WALKERS` (Task 6), `tally` (Task 7), `build_provenance` (Task 7), `tools/resolved.json` (Task 3), `tools/corpus.lock.json` (Task 4).
- Produces: `applicable_scanners(lock, platform) -> list[str]`, `scanner_command(name, exe, platform, target) -> list[str]`, and the `artifacts/rule-inventory.json` deliverable.

- [ ] **Step 1: Write the failing test**

`tests/harvest/test_run.py`:

```python
"""Orchestration: platform applicability and command construction.

Both are pure functions so they are testable without a scanner installed.
"""

from __future__ import annotations

import pytest

from tools.harvest.run import applicable_scanners, scanner_command

LOCK = {
    "scanners": {
        "checkov": {"platforms": ["terraform", "kubernetes"]},
        "trivy": {"platforms": ["terraform", "kubernetes"]},
        "tfsec": {"platforms": ["terraform"]},
    }
}


def test_terraform_uses_all_three_scanners() -> None:
    assert applicable_scanners(LOCK, "terraform") == ["checkov", "tfsec", "trivy"]


def test_kubernetes_excludes_tfsec() -> None:
    """PLAN.md R3-#3: tfsec is Terraform-only. Absence is not a failure."""
    assert applicable_scanners(LOCK, "kubernetes") == ["checkov", "trivy"]


def test_unknown_platform_yields_no_scanners() -> None:
    assert applicable_scanners(LOCK, "cloudformation") == []


def test_commands_are_argument_lists_never_shell_strings() -> None:
    """Paths here contain spaces; a shell string would be a quoting bug."""
    for scanner in ("checkov", "trivy", "tfsec"):
        cmd = scanner_command(scanner, "C:\\b\\x.exe", "terraform", "D:\\My Research\\a")
        assert isinstance(cmd, list)
        assert all(isinstance(part, str) for part in cmd)
        assert cmd[0] == "C:\\b\\x.exe"
        assert "D:\\My Research\\a" in cmd


def test_each_command_requests_json() -> None:
    checkov = scanner_command("checkov", "c.exe", "terraform", "t")
    assert "-o" in checkov and "json" in checkov
    trivy = scanner_command("trivy", "t.exe", "terraform", "t")
    assert trivy[1] == "config" and "--format" in trivy and "json" in trivy
    tfsec = scanner_command("tfsec", "s.exe", "terraform", "t")
    assert "--format" in tfsec and "json" in tfsec


def test_unknown_scanner_command_raises() -> None:
    with pytest.raises(KeyError):
        scanner_command("nessus", "n.exe", "terraform", "t")
```

- [ ] **Step 2: Run and confirm it fails**

```powershell
uv run pytest tests/harvest/test_run.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'tools.harvest.run'`.

- [ ] **Step 3: Write `tools/harvest/run.py`**

Correct the argument arrays to whatever Task 5 proved actually works.

```python
"""Harvest orchestration and CLI. The only harvest module that does I/O.

Usage:
    uv run python -m tools.harvest.run
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.harvest.model import InventoryRow
from tools.harvest.provenance import build_provenance
from tools.harvest.tally import tally
from tools.harvest.walkers import walk

REPO_ROOT = Path(__file__).resolve().parents[2]


def applicable_scanners(lock: dict[str, Any], platform: str) -> list[str]:
    """Scanners declared applicable to `platform`, sorted.

    Applicability is data from scanners.lock.json, never an if-branch here
    (PLAN.md Q3 / R3-#3). tfsec being absent for Kubernetes is correct
    behaviour, not a missing-tool failure.
    """
    return sorted(
        name
        for name, entry in lock["scanners"].items()
        if platform in entry.get("platforms", [])
    )


def scanner_command(scanner: str, exe: str, platform: str, target: str) -> list[str]:
    """Build the argv list for one scanner run. Never a shell string."""
    builders = {
        "checkov": lambda: [exe, "-d", target, "-o", "json", "--compact"],
        "trivy": lambda: [exe, "config", "--format", "json", target],
        "tfsec": lambda: [exe, "--format", "json", target],
    }
    return builders[scanner]()


def _run_scanner(cmd: list[str]) -> tuple[str, int]:
    """Run a scanner. Non-zero exit is normal - findings cause it."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    return result.stdout, result.returncode


def harvest(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Run every applicable scanner over every corpus case; build the inventory."""
    scanners_lock = json.loads(
        (repo_root / "tools" / "scanners.lock.json").read_text(encoding="utf-8")
    )
    corpus_lock = json.loads(
        (repo_root / "tools" / "corpus.lock.json").read_text(encoding="utf-8")
    )
    resolved = json.loads((repo_root / "tools" / "resolved.json").read_text(encoding="utf-8"))

    raw_dir = repo_root / "artifacts" / "raw"
    rows: list[InventoryRow] = []
    runs: list[dict[str, Any]] = []

    for case in corpus_lock["cases"]:
        case_id, platform = case["id"], case["platform"]
        target = str(repo_root / case["path"])

        for scanner in applicable_scanners(scanners_lock, platform):
            exe = resolved[scanner]["exe"]
            cmd = scanner_command(scanner, exe, platform, target)
            print(f"==> {scanner} on {case_id} ({platform})", file=sys.stderr)

            stdout, exit_code = _run_scanner(cmd)

            out_path = raw_dir / scanner / f"{case_id}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(stdout, encoding="utf-8", newline="\n")

            record: dict[str, Any] = {
                "scanner": scanner, "case_id": case_id, "platform": platform,
                "category": case["category"], "exit_code": exit_code,
                "raw_path": out_path.relative_to(repo_root).as_posix(),
            }
            try:
                doc = json.loads(stdout) if stdout.strip() else None
            except json.JSONDecodeError as exc:
                record["error"] = f"non-JSON output: {exc}"
                record["rows"] = 0
                runs.append(record)
                continue

            case_rows = walk(scanner, doc, case_id) if doc is not None else []
            rows.extend(case_rows)
            record["rows"] = len(case_rows)
            runs.append(record)

    inventory = tally(rows)
    inventory["provenance"] = build_provenance(repo_root)
    inventory["corpus"] = {
        "sources": corpus_lock["sources"],
        "case_count": len(corpus_lock["cases"]),
        "categories": sorted({c["category"] for c in corpus_lock["cases"]}),
    }
    inventory["runs"] = runs
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="Harvest the scanner rule-ID inventory.")
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "artifacts" / "rule-inventory.json"
    )
    args = parser.parse_args()

    inventory = harvest()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" and sort_keys: the inventory is committed, so it must diff cleanly.
    args.out.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )

    totals = inventory["totals"]
    print(f"\nrows={totals['rows']} distinct_rule_ids={totals['distinct_rule_ids']}")
    print(f"missing_severity_rate={totals['missing_severity_rate']}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

```powershell
uv run pytest tests/harvest/test_run.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Run the real harvest**

```powershell
uv run python -m tools.harvest.run
```

Expected: per-scanner progress on stderr, then non-zero `rows` and `distinct_rule_ids`, and `artifacts/rule-inventory.json` written. If any run reports `"error": "non-JSON output"`, read that raw file — a scanner probably wrote a diagnostic to stdout, and its argument array needs fixing.

- [ ] **Step 6: Check the gate against the inventory**

```powershell
uv run python -c "import json,pathlib; d=json.loads(pathlib.Path('artifacts/rule-inventory.json').read_text()); print('categories:', d['corpus']['categories']); print('scanners:', d['totals']['scanners']); print('rows:', d['totals']['rows']); print('distinct:', d['totals']['distinct_rule_ids']); print('missing-sev:', {k: v['missing_severity_rate'] for k,v in d['by_scanner'].items()}); print('sev levels:', {k: v['observed_severity_levels'] for k,v in d['by_scanner'].items()})"
```

Confirm: all five categories present; all three scanners produced rows; `distinct_rule_ids` is non-trivial. If a category produced zero rows, that category's corpus case is wrong — fix `corpus.lock.json` and re-run rather than lowering the gate.

- [ ] **Step 7: Run the whole suite and the full verification chain**

```powershell
.\tools\bootstrap.ps1 -Verify
uv run pytest -v
uv run ruff check .
uv run mypy src tools eval
```

Expected: all clean. This is gate items 1 and 7.

- [ ] **Step 8: Rewrite the "Current state" section of `CLAUDE.md`**

CLAUDE.md currently says the repository is empty and instructs: *"When it's established, update this file with the real commands — do not invent them."* Replace that section with only commands you actually ran in this plan:

```markdown
## Current state

S0 complete: pinned toolchain + empirical rule-ID inventory. Phase 1 (the five
specification artifacts) is next — see `docs/superpowers/specs/` and
`docs/superpowers/plans/`.

Python is pinned to **3.12** (not the system 3.13.5): Checkov 3.3.12's
classifiers stop at 3.12. Bare `python` on this machine is the broken
Microsoft Store alias — always use `uv run python` or `py`.

### Commands

```powershell
uv sync                      # install/refresh dependencies
uv run pytest                # full test suite
uv run pytest tests/harvest  # harvest tests only
uv run ruff check .          # lint
uv run ruff format .         # format
uv run mypy src tools eval   # type-check

.\tools\bootstrap.ps1            # install + checksum-verify pinned scanners
.\tools\bootstrap.ps1 -Verify    # re-assert pins without downloading
.\tools\vendor_corpus.ps1        # re-vendor corpus v0 at pinned commits
.\tools\capture_fixtures.ps1     # re-capture golden scanner JSON fixtures

uv run python -m tools.harvest.run   # regenerate artifacts/rule-inventory.json
```

### Pinned versions

Scanners: `tools/scanners.lock.json` (Checkov 3.3.12, Trivy 0.74.0, tfsec 1.28.14).
Corpus: `tools/corpus.lock.json` (TerraGoat, KubeGoat at exact commits).
Checkov is an isolated `uv tool` and must never become a project dependency.
```

Also fix the stale line in the Architecture section — item 2's "run existing scanners" now has a concrete home in `tools/harvest/` for S0 and `src/iacrisk/scanners/` for S3.

- [ ] **Step 9: Record the gate outcome in the spec**

Append an `## S0 gate — outcome` section to `docs/superpowers/specs/2026-08-24-implementation-phase0-design.md` with a line per numbered gate item from spec §7 and the evidence for each (the inventory numbers, the observed tfsec-on-K8s behaviour, the missing-severity rates). This is the handoff S1 reads.

- [ ] **Step 10: Commit**

```bash
git add tools/harvest/run.py tests/harvest/test_run.py artifacts/ CLAUDE.md docs/superpowers/specs/
git commit -m "harvest: run corpus v0 inventory and close the S0 acceptance gate"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: §2 pins → Tasks 1, 3; §3 skeleton → Tasks 1, 5; §4.1 Checkov isolation → Tasks 2, 3; §4.2 checksums → Task 3 (incl. Step 9 proving the guard fires); §4.3 resolved paths → Task 3; §4.4 provenance → Task 7; §4.5 harvest boundary → Tasks 2, 5, 6; §4.6 vendoring → Task 4; §5 facts 1–4 → Task 5 Steps 6–7; §6 testing → all; §7 gate items 1–8 → Task 8 Steps 6–9; §8 out-of-scope → enforced by `tests/test_architecture.py`. The `.gitattributes` requirement raised after the spec was committed is Task 1 Steps 1–2.

**Placeholder scan.** No TBD/TODO. Two steps are deliberately empirical rather than prescriptive — Task 4 Step 5 (correct TerraGoat filenames against the real tree) and Task 6 Step 4 (correct walker field paths against captured fixtures). Both name the exact file to change, the authority to change it toward, and a test that fails until they agree. That is the spec's "establish, don't assume" requirement, not vagueness.

**Type consistency.** `InventoryRow(scanner, rule_id, native_severity, target, case_id)` is defined in Task 5 and used unchanged in Tasks 6–8. `walk(scanner, doc, case_id)` and `WALKERS` are defined in Task 6 and consumed in Task 8. `tally(rows) -> dict` and `build_provenance(repo_root) -> dict` are defined in Task 7 and consumed in Task 8. `applicable_scanners(lock, platform)` and `scanner_command(scanner, exe, platform, target)` are defined and tested in Task 8. `hash_file(path)` is defined and tested in Task 7. The `platforms` key is written in Task 3's lockfile and read in Task 8. No name appears in two forms.

**One known ordering hazard.** Task 5's `capture_fixtures.ps1` reads `tools/resolved.json`, so Task 3 must complete first; Task 4 must precede Task 5 because the capture targets vendored corpus paths. Tasks 1–8 are strictly sequential — do not parallelize them.
