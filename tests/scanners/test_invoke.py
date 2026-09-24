"""Lockfile-driven scanner invocation (design spec §3, task brief Task 10).

Four things are under test, each tied to one of the four rulings the task
dispatch handed down:

- R31: binaries resolve from `tools/resolved.json` only, never PATH. Tested
  against a `tmp_path` standing in for the repo root, so these do not depend
  on whether this checkout happens to have a `resolved.json`.
- R32: the platform matrix stays data. `applicable_scanners` is checked
  against the committed lockfile - never against a hardcoded scanner-name
  literal - and an AST walk asserts `invoke.py` never branches on a scanner's
  name.
- R33: the argv table matches the vectors Task 5 already proved, with the
  scan root last, and the three flags harvest measured and rejected stay
  absent.
- R34: `run()` does not raise on a non-zero exit - that is the scanners'
  normal, successful path - and is exercised against a real Python
  subprocess standing in for a scanner, never a live one and never a mock of
  `subprocess.run`.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from iacrisk.input import DiscoveredFile, DiscoveryResult
from iacrisk.scanners import invoke

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LOCK = REPO_ROOT / "tools" / "scanners.lock.json"
INVOKE_SOURCE = REPO_ROOT / "src" / "iacrisk" / "scanners" / "invoke.py"


def _lock() -> dict[str, Any]:
    lock: dict[str, Any] = json.loads(LOCK.read_text(encoding="utf-8"))
    return lock


# --------------------------------------------------------------------------
# R32: the platform matrix is data.
# --------------------------------------------------------------------------


def test_scanner_with_no_platforms_key_is_applicable_to_nothing() -> None:
    """The safe direction: an undeclared matrix entry gets pointed at no root.

    Untestable against `applicable_scanners` itself without writing a temp
    lockfile to disk, so this exercises the pure helper directly against a
    synthetic mapping - never a lockfile on disk.
    """
    synthetic: dict[str, Any] = {"scanners": {"ghost": {"version": "9.9.9"}}}
    assert invoke._scanners_for_platform(synthetic, "terraform") == ()
    assert invoke._scanners_for_platform(synthetic, "kubernetes") == ()


def test_scanner_declaring_empty_platforms_list_is_also_applicable_to_nothing() -> None:
    """An explicit empty list is the same safe outcome as a missing key."""
    synthetic: dict[str, Any] = {"scanners": {"ghost": {"platforms": []}}}
    assert invoke._scanners_for_platform(synthetic, "terraform") == ()


def test_applicable_scanners_matches_the_committed_lockfile() -> None:
    """Real split, computed independently of `invoke.py` from the lockfile itself.

    tfsec's Terraform-only declaration (`tools/scanners.lock.json`) is what
    makes it absent from the Kubernetes list - read here, never restated as
    a hardcoded scanner name, so a widened matrix changes what this test
    expects rather than leaving it green by coincidence.
    """
    scanners = _lock()["scanners"]
    assert isinstance(scanners, dict)
    expected_terraform = tuple(
        sorted(
            name for name, entry in scanners.items() if "terraform" in entry.get("platforms", [])
        )
    )
    expected_kubernetes = tuple(
        sorted(
            name for name, entry in scanners.items() if "kubernetes" in entry.get("platforms", [])
        )
    )

    assert invoke.applicable_scanners("terraform") == expected_terraform
    assert invoke.applicable_scanners("kubernetes") == expected_kubernetes
    assert "tfsec" in expected_terraform
    assert "tfsec" not in expected_kubernetes


def test_no_scanner_name_literal_in_a_conditional() -> None:
    """No `if scanner == "checkov"` (or similar) anywhere in `invoke.py`.

    Borrows the ast.parse-plus-walk technique from `tests/test_architecture.py`'s
    `_imported_modules` - that file holds import-boundary, CRLF and
    harvest-isolation guards but no scanner-name test of its own (task brief's
    correction). Scanner names come from the lockfile, not a restated literal
    list, for the same reason the split test above does.
    """
    scanners = _lock()["scanners"]
    assert isinstance(scanners, dict)
    scanner_names = set(scanners)
    tree = ast.parse(INVOKE_SOURCE.read_text(encoding="utf-8"), filename=str(INVOKE_SOURCE))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If | ast.IfExp):
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Constant) and sub.value in scanner_names:
                    offenders.append(f"line {node.lineno}: {sub.value!r}")

    assert offenders == [], f"scanner name literal in a conditional: {offenders}"


# --------------------------------------------------------------------------
# R31: resolve binaries from tools/resolved.json only.
# --------------------------------------------------------------------------


def test_resolve_exe_raises_when_resolved_json_is_absent(tmp_path: Path) -> None:
    """A fresh clone has no `tools/resolved.json`; fail in one second, not five runs."""
    with pytest.raises(invoke.ScannerNotResolvedError, match=r"bootstrap\.ps1"):
        invoke._resolve_exe("checkov", tmp_path)


def test_resolve_exe_raises_when_scanner_key_is_missing(tmp_path: Path) -> None:
    """A `resolved.json` that exists but never resolved this particular scanner."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "resolved.json").write_text(
        json.dumps({"trivy": {"exe": "trivy.exe", "version": "0.74.0"}}),
        encoding="utf-8",
    )
    with pytest.raises(invoke.ScannerNotResolvedError, match=r"bootstrap\.ps1"):
        invoke._resolve_exe("checkov", tmp_path)


def test_resolve_exe_returns_the_pinned_path(tmp_path: Path) -> None:
    """The one field this function reads: `resolved[scanner]["exe"]`, verbatim."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "resolved.json").write_text(
        json.dumps({"checkov": {"exe": "D:\\fake\\checkov.cmd", "version": "3.3.12"}}),
        encoding="utf-8",
    )
    assert invoke._resolve_exe("checkov", tmp_path) == "D:\\fake\\checkov.cmd"


def test_resolve_exe_never_falls_back_to_a_bare_name(tmp_path: Path) -> None:
    """No PATH fallback: a scanner absent from `resolved.json` raises, never `"checkov"`."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "resolved.json").write_text(json.dumps({}), encoding="utf-8")
    with pytest.raises(invoke.ScannerNotResolvedError):
        invoke._resolve_exe("tfsec", tmp_path)


# --------------------------------------------------------------------------
# R33: the argv table.
# --------------------------------------------------------------------------


def test_scanner_argv_matches_the_proven_vectors() -> None:
    assert invoke.SCANNER_ARGV["checkov"] == (
        "--output",
        "json",
        "--compact",
        "--skip-download",
        "--directory",
    )
    assert invoke.SCANNER_ARGV["trivy"] == (
        "config",
        "--format",
        "json",
        "--quiet",
        "--disable-telemetry",
        "--skip-check-update",
    )
    assert invoke.SCANNER_ARGV["tfsec"] == (
        "--format",
        "json",
        "--no-colour",
        "--no-module-downloads",
    )


def test_checkov_directory_flag_stays_immediately_before_the_target() -> None:
    """`--directory` must be checkov's final flag; the target path follows it."""
    argv = invoke._build_argv("checkov", "checkov.cmd", "D:/corpus")
    assert argv[-2:] == ("--directory", "D:/corpus")


def test_target_is_always_the_last_argv_element() -> None:
    pairs = (("checkov", "checkov.cmd"), ("trivy", "trivy.exe"), ("tfsec", "tfsec.exe"))
    for scanner, exe in pairs:
        argv = invoke._build_argv(scanner, exe, "D:/corpus/root")
        assert argv[0] == exe
        assert argv[-1] == "D:/corpus/root"


def test_rejected_flags_stay_absent() -> None:
    """Each rejection was measured, not reasoned - do not re-add them.

    trivy's table legitimately carries its own `--quiet`; the withheld
    `--quiet` is checkov's, a different flag on a different scanner.
    """
    assert "--quiet" not in invoke.SCANNER_ARGV["checkov"]
    assert "--framework" not in invoke.SCANNER_ARGV["checkov"]
    assert "--soft-fail" not in invoke.SCANNER_ARGV["tfsec"]


def test_unmapped_scanner_raises_keyerror() -> None:
    """A scanner this repo has not pinned has no proven invocation."""
    with pytest.raises(KeyError):
        invoke._build_argv("snyk", "snyk.exe", "D:/corpus")


# --------------------------------------------------------------------------
# build_invocations
# --------------------------------------------------------------------------


def test_build_invocations_emits_nothing_for_a_platform_with_no_files() -> None:
    """No files at all -> no platforms present -> no invocations.

    Deliberately touches no scanner resolution: with an empty `files` tuple,
    `build_invocations` never has a platform to resolve a scanner for, so
    this holds regardless of whether this checkout has a `tools/resolved.json`.
    """
    discovery = DiscoveryResult(files=(), ignored=("README.md",), unparseable=())
    assert invoke.build_invocations(discovery, Path("D:/wherever")) == ()


def _skip_without_resolved() -> None:
    if not (invoke.REPO_ROOT / "tools" / "resolved.json").exists():
        pytest.skip("tools/resolved.json does not exist yet (written by tools/bootstrap.ps1)")


def test_build_invocations_builds_one_per_applicable_scanner(tmp_path: Path) -> None:
    """Wiring check against the real, committed lockfile and this host's resolved binaries.

    Builds argv only - no subprocess is started here, so this stays inside
    the "never invoke a real scanner" rule while still proving
    `build_invocations` resolves and constructs something real rather than
    only ever being exercised against synthetic data.
    """
    _skip_without_resolved()
    tf_file = DiscoveredFile(
        path=tmp_path / "main.tf", relative_path="main.tf", platform="terraform"
    )
    discovery = DiscoveryResult(files=(tf_file,), ignored=(), unparseable=())

    invocations = invoke.build_invocations(discovery, tmp_path)

    expected_scanners = invoke.applicable_scanners("terraform")
    assert tuple(inv.scanner for inv in invocations) == expected_scanners
    for inv in invocations:
        assert inv.platform == "terraform"
        assert inv.argv[0]
        assert inv.argv[-1] == str(tmp_path)


def test_build_invocations_only_covers_platforms_present() -> None:
    """A Terraform-only discovery never resolves tfsec's Kubernetes-absent siblings.

    Uses a scan root under `tmp_path` (not this repo's actual corpus roots),
    so this is checking the platform-derivation logic, not real resolution -
    guarded the same way as the test above where resolution would matter.
    """
    _skip_without_resolved()
    tf_file = DiscoveredFile(path=Path("main.tf"), relative_path="main.tf", platform="terraform")
    discovery = DiscoveryResult(files=(tf_file,), ignored=(), unparseable=())

    invocations = invoke.build_invocations(discovery, Path("D:/wherever"))

    assert {inv.platform for inv in invocations} == {"terraform"}


# --------------------------------------------------------------------------
# R34: run() does not raise on a non-zero exit.
# --------------------------------------------------------------------------


def test_run_returns_parsed_json_on_nonzero_exit() -> None:
    """A real Python subprocess exits 1 and prints JSON - the scanners' own ordinary path.

    Not a mock of `subprocess.run`: the behaviour under test is exit-code
    handling, and mocking the call would assert the mock rather than the
    code that decides whether to raise.
    """
    invocation = invoke.ScanInvocation(
        scanner="faux",
        platform="terraform",
        scan_root="D:/does-not-matter",
        argv=(
            sys.executable,
            "-c",
            "import json, sys; print(json.dumps({'ok': True})); sys.exit(1)",
        ),
    )
    assert invoke.run(invocation) == {"ok": True}


def test_run_raises_on_unparseable_stdout_and_names_the_scanner() -> None:
    invocation = invoke.ScanInvocation(
        scanner="faux",
        platform="terraform",
        scan_root="D:/does-not-matter",
        argv=(sys.executable, "-c", "print('not json')"),
    )
    with pytest.raises(ValueError, match="faux"):
        invoke.run(invocation)


def test_run_raises_scanner_timeout_error_and_names_the_scanner() -> None:
    """A real hung subprocess, killed by a tiny override - never the 900s production value.

    Unlike `tools/harvest/run.py`, which returns partial output plus an error
    string on the same condition, `run()` raises: this asserts the divergence
    the dispatch called for, not just that *some* timeout fires.
    """
    invocation = invoke.ScanInvocation(
        scanner="faux",
        platform="terraform",
        scan_root="D:/does-not-matter",
        argv=(sys.executable, "-c", "import time; time.sleep(60)"),
    )
    with pytest.raises(invoke.ScannerTimeoutError, match="faux") as excinfo:
        invoke.run(invocation, timeout=0.05)
    assert excinfo.value.scanner == "faux"
    assert excinfo.value.timeout == 0.05
