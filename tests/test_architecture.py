"""Structural guardrails from PLAN.md, enforced as tests rather than convention.

These fail loudly the moment a later sub-project blurs a boundary the
research design depends on.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

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


def _crlf_offenders(ls_files_eol_output: str) -> list[str]:
    """Paths whose *index* blob holds CRLF or mixed line endings.

    Parses `git ls-files --eol`. Only the `i/` field matters: `eol=crlf`
    (used for `*.ps1`) affects the working tree, never the stored blob, so a
    PowerShell script correctly reports `i/lf w/crlf`. Binaries report
    `i/-text` and must be ignored rather than normalized.
    """
    offenders: list[str] = []
    for line in ls_files_eol_output.splitlines():
        fields, tab, path = line.partition("\t")
        if not tab:
            continue
        if fields.split()[0] in ("i/crlf", "i/mixed"):
            offenders.append(path)
    return offenders


def test_no_crlf_in_the_index() -> None:
    """No tracked blob may hold CRLF - Task 1's whole reason for existing.

    `specs/` hashes and the vendored `corpus/` tree feed the provenance
    block (spec §4.4); a CRLF blob would silently change a recorded SHA256
    and invalidate a reproducibility claim. `.gitattributes` declares this
    invariant; this test is what enforces it.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--eol"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        pytest.skip(f"not a usable git checkout: {exc}")
    offenders = _crlf_offenders(proc.stdout)
    assert offenders == [], f"CRLF line endings in the index: {offenders}"


def test_crlf_detector_recognizes_every_eol_state() -> None:
    """Guard the guard: prove the parser against output git can actually emit.

    The path is TAB-separated because the `attr/` field itself contains
    spaces (`attr/text=auto eol=lf`), so splitting on whitespace would break
    on the very files this protects.
    """
    sample = (
        "i/lf    w/lf    attr/text=auto eol=lf \tspecs/design.md\n"
        "i/crlf  w/crlf  attr/ \tspecs/bad.md\n"
        "i/-text w/-text attr/-text \tcorpus/vendor/logo.png\n"
        "i/mixed w/mixed attr/ \tartifacts/messy.json\n"
        "i/lf    w/crlf  attr/text eol=crlf \ttools/bootstrap.ps1\n"
        "i/lf    w/lf    attr/text=auto eol=lf \tpath with spaces/a b.md\n"
    )
    assert _crlf_offenders(sample) == ["specs/bad.md", "artifacts/messy.json"]
