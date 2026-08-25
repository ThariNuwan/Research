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
    """Every module name imported by `path`, as dotted strings.

    `from a import b` yields both `a` and `a.b`, because the imported name may
    itself be a submodule and that form - `from iacrisk import scoring` - is
    the most idiomatic way to write the violations these guards forbid.
    `alias.name` is deliberate: using `asname` would let
    `from iacrisk import scoring as s` hide as `iacrisk.s`.

    Emitting `a.b` for a plain attribute import (`from x import SOME_CONST`)
    is harmless - callers match against specific module paths, and no guard
    here forbids a name that is only ever an attribute.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _matches(module: str, root: str) -> bool:
    """Whether `module` is `root` itself or a submodule beneath it.

    The dot in the prefix is the whole point: it is what stops
    `iacrisk.scoring_utils` from matching `iacrisk.scoring`, and
    `checkov_helper` from matching `checkov`.

    Both import guards and `test_import_matcher_resolves_every_import_form`
    share this one definition deliberately. A restated copy of the matching
    logic could drift from the guards' copy, leaving the matrix test green
    while the guards it is supposed to protect matched nothing.
    """
    return module == root or module.startswith(f"{root}.")


def test_no_module_imports_checkov() -> None:
    """Checkov is a subprocess-invoked tool, never a library (PLAN.md Q3).

    It is installed via `uv tool install` into its own venv. An import here
    would mean its dependency tree had leaked into the framework's.
    """
    offenders = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _python_files()
        if any(_matches(m, "checkov") for m in _imported_modules(path))
    ]
    assert offenders == [], f"checkov imported as a library in: {offenders}"


def test_eval_does_not_import_scoring() -> None:
    """The harness may not share code with what it grades (PLAN.md Q7).

    Uses the same `_matches` predicate as the checkov guard: an exact match
    or a dotted-prefix match. A bare `startswith("iacrisk.scoring")` would
    also flag `iacrisk.scoring_utils`, which violates nothing.
    """
    offenders: list[tuple[str, list[str]]] = []
    for path in (REPO_ROOT / "eval").rglob("*.py"):
        leaked = {m for m in _imported_modules(path) if _matches(m, "iacrisk.scoring")}
        if leaked:
            offenders.append((path.relative_to(REPO_ROOT).as_posix(), sorted(leaked)))
    assert offenders == [], f"eval/ imports scoring internals: {offenders}"


# (source, matches iacrisk.scoring, matches checkov)
IMPORT_MATRIX = [
    ("import iacrisk.scoring", True, False),
    ("from iacrisk.scoring import score", True, False),
    ("from iacrisk import scoring", True, False),
    ("from iacrisk import scoring as s", True, False),
    ("from iacrisk import scoring_utils", False, False),
    ("import iacrisk.scoring_utils", False, False),
    ("from checkov import x", False, True),
    ("import checkov", False, True),
    ("from checkov.common.y import z", False, True),
    ("import checkov_helper", False, False),
]


@pytest.mark.parametrize(("source", "scoring_hit", "checkov_hit"), IMPORT_MATRIX)
def test_import_matcher_resolves_every_import_form(
    source: str, scoring_hit: bool, checkov_hit: bool, tmp_path: Path
) -> None:
    """Guard the guard: both import guards rest entirely on this one predicate.

    `_imported_modules` is the single thing `test_no_module_imports_checkov`
    and `test_eval_does_not_import_scoring` depend on. If a refactor stopped
    it emitting `a.b` for `from a import b`, both guards would keep reporting
    green while catching nothing - the dormant-guard failure mode again, but
    silent, because there would be no skip to notice.

    `from iacrisk import scoring` is the case that motivates this: it is the
    most idiomatic way to write the violation PLAN.md Q7 forbids, and it was
    invisible until `_imported_modules` began emitting imported names too.
    The `scoring_utils` and `checkov_helper` rows are the other half of the
    contract - proof the matcher is precise, not merely wide.

    Written to `tmp_path` rather than into `eval/`: a committed file holding
    `from iacrisk import scoring` would be a real architecture violation and
    would break `uv run mypy src eval`.
    """
    module_file = tmp_path / "probe.py"
    module_file.write_text(f"{source}\n", encoding="utf-8")

    modules = _imported_modules(module_file)

    assert any(_matches(m, "iacrisk.scoring") for m in modules) is scoring_hit, (
        f"iacrisk.scoring match wrong for {source!r}; emitted {sorted(modules)}"
    )
    assert any(_matches(m, "checkov") for m in modules) is checkov_hit, (
        f"checkov match wrong for {source!r}; emitted {sorted(modules)}"
    )


def test_harvest_does_not_define_a_normalized_finding() -> None:
    """Harvest is a research instrument, not pipeline layer 2 (spec §4.5).

    The normalized finding record belongs to S3 and depends on the
    issue-class taxonomy, which does not exist yet. Catching the name here
    prevents harvest from quietly growing into a duplicate layer 2.
    """
    harvest_dir = REPO_ROOT / "tools" / "harvest"
    if not harvest_dir.exists():
        pytest.skip("tools/harvest/ does not exist yet (created in Task 5)")

    banned = {"Finding", "NormalizedFinding", "FindingRecord"}
    offenders: list[str] = []
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
    # Without this, an empty stdout would make `offenders == []` hold vacuously
    # and the guard would report green having checked nothing at all.
    assert proc.stdout.strip(), "git ls-files --eol returned no entries"
    offenders = _crlf_offenders(proc.stdout)
    assert offenders == [], f"CRLF line endings in the index: {offenders}"


def test_crlf_detector_recognizes_every_eol_state() -> None:
    """Guard the guard: prove the parser against output git can actually emit.

    Covers all six eolinfo values git documents for `--eol`: `lf`, `crlf`,
    `mixed`, `-text`, `none`, and empty (a non-regular file, or one absent
    from the worktree - symlinks and gitlinks report the empty shape).

    The path is TAB-separated because the `attr/` field itself contains
    spaces (`attr/text=auto eol=lf`), so splitting on whitespace would break
    on the very files this protects. The `path with spaces` row is therefore
    an *offender* carrying a space-filled `attr/` field: it is the row that
    constrains path extraction, and it only does so by reaching the append.
    """
    sample = (
        "i/lf    w/lf    attr/text=auto eol=lf \tspecs/design.md\n"
        "i/crlf  w/crlf  attr/ \tspecs/bad.md\n"
        "i/-text w/-text attr/-text \tcorpus/vendor/logo.png\n"
        "i/mixed w/mixed attr/ \tartifacts/messy.json\n"
        "i/lf    w/crlf  attr/text eol=crlf \ttools/bootstrap.ps1\n"
        "i/none  w/none  attr/text=auto eol=lf \tspecs/single-line.txt\n"
        "i/      w/      attr/text=auto eol=lf \tcorpus/vendor/submodule\n"
        "i/crlf  w/crlf  attr/text=auto eol=lf \tpath with spaces/a b.md\n"
    )
    assert _crlf_offenders(sample) == [
        "specs/bad.md",
        "artifacts/messy.json",
        "path with spaces/a b.md",
    ]
