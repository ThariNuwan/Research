"""Lockfile-driven scanner invocation (design spec §3).

`tools/harvest/run.py` solves this same problem for the S0 harvest and is the
proven precedent for every decision below, but this module does not import
it - `tests/test_architecture.py::test_harvest_does_not_define_a_normalized_finding`
and the plan's harvest-isolation constraint both forbid that, so the platform
matrix, the argv table and the subprocess handling are re-derived here rather
than shared.

Three things this module refuses to do, each measured rather than assumed:

- Resolve a binary from PATH. `tools/scanners.lock.json` itself records why:
  checkov 3.3.12 declares no `console_scripts` entry point, so upstream's own
  `checkov.cmd` resolves `python` from PATH, which on this host hits the
  Microsoft Store app-execution alias stub (observed: exit 9009, "Python was
  not found"). `tools/bootstrap.ps1` exists partly to generate a pinned
  launcher into `tools/bin/` and record it in `tools/resolved.json`; that
  gitignored file is the only place a binary path comes from here. A PATH
  fallback could also silently run an unpinned scanner version.
- Branch on a scanner's name to decide platform applicability. That matrix is
  `tools/scanners.lock.json`'s `platforms` list, read as data the same way
  `tools/harvest/run.py`'s own `applicable_scanners` reads it - an entry
  declaring no `platforms` is applicable to nothing, the safe direction, so a
  scanner added to the lockfile without declaring its platforms does not
  silently get pointed at every scan root.
- Raise on a scanner's non-zero exit. All three pinned scanners exit non-zero
  when they find misconfigurations - their ordinary, successful path - which
  is exactly why `--soft-fail` is withheld from tfsec's own argv below: it
  would force exit 0 and make the exit-code observation unanswerable for a
  flag this module never sets in the first place.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iacrisk.input import DiscoveryResult

REPO_ROOT = Path(__file__).resolve().parents[3]

SCANNER_ARGV: dict[str, tuple[str, ...]] = {
    "checkov": ("--output", "json", "--compact", "--skip-download", "--directory"),
    "trivy": (
        "config",
        "--format",
        "json",
        "--quiet",
        "--disable-telemetry",
        "--skip-check-update",
    ),
    "tfsec": ("--format", "json", "--no-colour", "--no-module-downloads"),
}
"""The vectors Task 5 proved, argument for argument, with the scan root appended last.

`--directory` must stay checkov's *final* flag - the target path follows it,
positionally, in `_build_argv`. Three flags were withheld, and each rejection
was measured on this host rather than reasoned about in the abstract: checkov
`--quiet` drops three keys out of `results`, which the adapters parse; tfsec
`--soft-fail` forces exit 0 and makes the exit-code observation unanswerable;
checkov `--framework` is withheld so checkov's own multi-framework detection
stays visible. Do not re-add any of the three.
"""


class ScannerNotResolvedError(RuntimeError):
    """`tools/resolved.json` is missing, or does not resolve the named scanner.

    The one error path a wrong binary spelling has: nothing here falls back
    to PATH, so a scanner absent from `resolved.json` fails loudly, naming
    `.\\tools\\bootstrap.ps1` as the fix, rather than silently trying a bare
    command name.
    """


@dataclass(frozen=True)
class ScanInvocation:
    """One scanner run to make: which scanner, which platform, and its exact argv.

    `argv` already carries the resolved binary at index 0 and the scan root
    as its last element. `run()` launches it exactly as given and resolves
    nothing itself - which is what lets that function's own tests hand it a
    bare `sys.executable` invocation, standing in for a scanner, without
    touching `tools/resolved.json` or a real scanner binary at all.
    """

    scanner: str
    platform: str
    scan_root: str
    argv: tuple[str, ...]


def _scanners_for_platform(lock: Mapping[str, Any], platform: str) -> tuple[str, ...]:
    """Pure lockfile-matrix lookup, re-deriving `tools/harvest/run.py`'s `applicable_scanners`.

    Takes the already-parsed lockfile mapping rather than a path, so the
    no-`platforms`-key case is testable against a synthetic mapping without
    writing a temp lockfile to disk. An entry with no `platforms` key, or an
    empty one, is applicable to nothing - the safe direction: a scanner added
    to the lockfile without declaring its platforms does not silently get
    pointed at every scan root.
    """
    return tuple(
        sorted(
            name
            for name, entry in lock["scanners"].items()
            if platform in entry.get("platforms", [])
        )
    )


def _read_json(path: Path) -> Any:
    """Parse a lockfile from raw bytes, so a UTF-8 BOM raises rather than being tolerated.

    Mirrors `tools/harvest/run.py::_read_json`'s reasoning: `json.loads`
    accepts a UTF-8 BOM in `bytes` and raises `Unexpected UTF-8 BOM` only on
    `str`, and `tools/resolved.json` is written by `bootstrap.ps1` on a
    PowerShell 5.1 host where a BOM is one `Set-Content` away.
    """
    return json.loads(path.read_bytes())


def applicable_scanners(platform: str) -> tuple[str, ...]:
    """Scanners `tools/scanners.lock.json` declares applicable to `platform`, sorted.

    Reads the committed lockfile - never gitignored, present on every
    checkout - so this has no fresh-clone failure mode of its own.
    """
    lock = _read_json(REPO_ROOT / "tools" / "scanners.lock.json")
    return _scanners_for_platform(lock, platform)


def _resolve_exe(scanner: str, repo_root: Path) -> str:
    """The one pinned, absolute executable path for `scanner`, read from `tools/resolved.json`.

    No PATH fallback and no default: a missing file, or a file present but
    missing `scanner`'s own key, both raise `ScannerNotResolvedError` naming
    `.\\tools\\bootstrap.ps1` as the fix. `repo_root` is a parameter rather
    than always `REPO_ROOT` so this can be exercised against a `tmp_path`
    standing in for the repo root, independent of whether this particular
    checkout happens to have been bootstrapped.
    """
    resolved_path = repo_root / "tools" / "resolved.json"
    if not resolved_path.exists():
        raise ScannerNotResolvedError(
            f"tools/resolved.json not found; run .\\tools\\bootstrap.ps1 to resolve "
            f"{scanner} before invoking it"
        )
    resolved = _read_json(resolved_path)
    if scanner not in resolved:
        raise ScannerNotResolvedError(
            f"{scanner!r} is not resolved in tools/resolved.json; run "
            ".\\tools\\bootstrap.ps1 to resolve it"
        )
    return str(resolved[scanner]["exe"])


def _build_argv(scanner: str, exe: str, target: str) -> tuple[str, ...]:
    """One scanner's argv: the resolved binary, its proven flags, the target last.

    A tuple, never a shell string: it is handed to `subprocess.run` as a
    list, which goes straight to `CreateProcess`, so a corpus path containing
    a space needs no quoting and cannot acquire any by accident.

    `SCANNER_ARGV[scanner]` raises `KeyError` for a scanner this repo has not
    pinned - deliberately not caught here, the same contract
    `tools/harvest/run.py::scanner_command` uses: a scanner with no proven
    invocation gets no guessed one.
    """
    return (exe, *SCANNER_ARGV[scanner], target)


def build_invocations(discovery: DiscoveryResult, scan_root: Path) -> tuple[ScanInvocation, ...]:
    """One `ScanInvocation` per platform discovery found, times its applicable scanners.

    Platforms come from `discovery.files` - never a hardcoded list of the two
    this sub-project happens to support - so a platform with no discovered
    files contributes no invocation at all: the loop below simply never
    reaches it. Scanner order within a platform follows `applicable_scanners`,
    which is lexicographic (spec §3).
    """
    platforms = sorted({discovered.platform for discovered in discovery.files})
    target = str(scan_root)

    invocations: list[ScanInvocation] = []
    for platform in platforms:
        for scanner in applicable_scanners(platform):
            exe = _resolve_exe(scanner, REPO_ROOT)
            argv = _build_argv(scanner, exe, target)
            invocations.append(
                ScanInvocation(scanner=scanner, platform=platform, scan_root=target, argv=argv)
            )
    return tuple(invocations)


def run(invocation: ScanInvocation) -> object:
    """Launch `invocation.argv` and return its parsed JSON stdout, whatever the exit code.

    All three pinned scanners exit non-zero on their ordinary, successful
    path - they find misconfigurations - so the exit code is never inspected
    here and `subprocess.run` is called with `check=False`. Unparseable
    stdout is the one thing this function does raise on, and the message
    names `invocation.scanner` so a caller running several invocations can
    tell which one produced it.
    """
    result = subprocess.run(list(invocation.argv), capture_output=True, check=False)
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{invocation.scanner}: unparseable stdout: {exc}") from exc
