"""Provenance block: makes every emitted artifact self-describing.

A reviewer holding only the output JSON can tell which scanner binaries, which
interpreter and host, which repository commit and which spec files produced it.

Two shapes here are wider than they look, for the same reason. This block exists so
a reader can reconstruct which bytes produced which numbers, which makes *"I could
not determine this"* and *"there is nothing to determine"* exactly the two facts it
may not report with one value:

- **`repo_commit` is a mapping, not a bare SHA-or-None.** Six outcomes reach it -
  a commit; not a checkout; git not installed; git ran and failed; git hung; and a
  successful run that printed nothing - and five of the six are falsy. `commit`
  carries the SHA or `None`, `state` carries which of the six it was.
- **`spec_hashes` is reported with the roots it searched.** `{}` on its own cannot
  be told apart from "specs exist and were not hashed", which is what an empty
  result meant for as long as the only search root was a directory this repository
  does not have. `spec_search_roots` names each root, whether it existed, and how
  many files it contributed.

`tools/resolved.json` is read as **bytes**. `json.loads` accepts a UTF-8 BOM in
`bytes` and raises `Unexpected UTF-8 BOM` on a `str`, and that file is written by
`tools/bootstrap.ps1` on a Windows PowerShell 5.1 host, whose default writers emit
one. The committed copy is BOM-free today; that is a fact about today, not a
property of the writer.

Read-only in the other direction too: nothing here recomputes a pinned digest, a
version or a vendored commit SHA from disk. The recorded value is the value, and
`version_output` keeps its captured name so this block cannot desynchronize from
the read-only file it was copied from.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GIT_TIMEOUT_SECONDS = 30

_NONZERO_EXIT = "nonzero-exit"
"""Internal marker: git ran and exited non-zero. What that means is the caller's."""

SPEC_SEARCH_ROOTS: tuple[str, ...] = ("docs/superpowers/specs", "specs")
"""Where spec files are looked for, in search order.

`docs/superpowers/specs/` holds the one spec this repository has today. A top-level
`specs/` does not exist here - checked with `ls`, which reports no such directory -
but it is a path `.gitattributes` pins `eol=lf` for by name (`specs/**`), so it is
searched rather than assumed away. Both roots are reported either way: a root that
was searched and found absent is a different fact from a root never looked at.
"""

VERSION_DISPLAY_RULE = "last-non-empty-line"
"""How `version_display` is derived from a captured `version_output`.

Measured this session over the committed `tools/resolved.json`: checkov's
`version_output` is 6 characters on 1 line, trivy's is 15 on 1 line, and tfsec's is
382 over 11 lines, 9 of them non-empty - a deprecation banner wrapped around the
number. Last non-empty line, whitespace-stripped, yields `3.3.12`,
`Version: 0.74.0` and `v1.28.14` respectively, with no per-scanner branch. First
non-empty line would yield tfsec's row of `=` characters, which is worse than the
banner it replaces.
"""


def hash_file(path: Path) -> str:
    """SHA256 of a file's bytes, hex-encoded.

    Bytes, not text: `.gitattributes` normalizes every tracked text blob to LF
    (`* text=auto eol=lf`, restated by name for `specs/**` and `artifacts/**`
    precisely because those digests are what a provenance block is read for), and
    that is what keeps a digest stable across checkouts. Verified this session with
    `git check-attr text eol` on the one spec this repository has: `text: auto`,
    `eol: lf`.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_stdout(repo_root: Path, *args: str) -> tuple[str | None, str | None]:
    """Run `git -C repo_root *args`. Returns `(stdout, None)` or `(None, failure)`.

    The failure is `git-unavailable`, `git-timeout` or `_NONZERO_EXIT` - and the
    last of those is deliberately not one of the reported state names, because what
    a non-zero exit *means* depends on which probe made it.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "git-unavailable"
    except subprocess.TimeoutExpired:
        return None, "git-timeout"
    except subprocess.CalledProcessError:
        return None, _NONZERO_EXIT
    return result.stdout, None


def _git_commit(repo_root: Path) -> dict[str, str | None]:
    """HEAD, as `{"commit": sha-or-None, "state": one-of-six}`.

    The six states are `ok`, `not-a-checkout`, `git-unavailable`, `git-failed`,
    `git-timeout` and `empty-output`. A single `None` for all of them would make a
    provenance record claim *"there is no commit"* in four cases where the truth is
    *"I could not ask"*, and in a fifth where git answered with nothing at all.

    Two probes rather than one: `rev-parse HEAD` exits non-zero both outside a
    repository and inside a fresh one whose HEAD is unborn, so on its own it cannot
    tell those apart. `rev-parse --git-dir` answers the first question by itself.
    """
    _, failure = _git_stdout(repo_root, "rev-parse", "--git-dir")
    if failure is not None:
        return {"commit": None, "state": "not-a-checkout" if failure == _NONZERO_EXIT else failure}

    stdout, failure = _git_stdout(repo_root, "rev-parse", "HEAD")
    if failure is not None:
        return {"commit": None, "state": "git-failed" if failure == _NONZERO_EXIT else failure}

    commit = (stdout or "").strip()
    if not commit:
        return {"commit": None, "state": "empty-output"}
    return {"commit": commit, "state": "ok"}


def _version_display(version_output: str) -> str | None:
    """The last non-empty line of a captured `--version`, whitespace-stripped.

    `None` when nothing non-empty was printed: a scanner that printed nothing gets
    no tidy value invented on its behalf. See VERSION_DISPLAY_RULE for why the last
    line and not the first.
    """
    lines = [line.strip() for line in version_output.splitlines() if line.strip()]
    return lines[-1] if lines else None


def _scanner_entry(entry: Any) -> dict[str, Any]:
    """One scanner's provenance, built from its `tools/resolved.json` record.

    `version_output` is copied under its captured name, at full fidelity: renaming
    or trimming it would desynchronize this block from a read-only file whose
    verbatim-ness is the point. The tidy one-line form sits beside it as
    `version_display`, with the rule that produced it as a sibling key, so a reader
    can tell the captured value from the derived one *and* see how the derived one
    was derived.

    A record with no `version_output` gets neither key - not an empty display
    string, which would assert a tidy value for a capture that does not exist.
    """
    scanner: dict[str, Any] = {"exe": entry.get("exe"), "version": entry.get("version")}
    version_output = entry.get("version_output")
    if version_output is None:
        return scanner
    scanner["version_output"] = version_output
    display = _version_display(str(version_output))
    if display is not None:
        scanner["version_display"] = display
        scanner["version_display_rule"] = VERSION_DISPLAY_RULE
    return scanner


def _spec_hashes(repo_root: Path) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Digest every file under each search root, and report the roots as well.

    Keys are repository-root-relative POSIX paths, so two roots cannot collide and
    the mapping does not carry this machine's drive letter into an artifact. Both
    the mapping and the report are built in search order, for stable diffs.
    """
    hashes: dict[str, str] = {}
    searched: list[dict[str, Any]] = []
    for relative_root in SPEC_SEARCH_ROOTS:
        root = repo_root / relative_root
        exists = root.is_dir()
        hashed = 0
        if exists:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    hashes[path.relative_to(repo_root).as_posix()] = hash_file(path)
                    hashed += 1
        searched.append({"root": relative_root, "exists": exists, "files_hashed": hashed})
    return hashes, searched


def build_provenance(repo_root: Path) -> dict[str, Any]:
    """Assemble the provenance block for one harvest run.

    Raises FileNotFoundError when `tools/resolved.json` is absent: emitting an
    artifact with no scanner provenance at all would be worse than failing here,
    and that file is gitignored, so a fresh clone hits this path before bootstrap.
    """
    resolved_path = repo_root / "tools" / "resolved.json"
    if not resolved_path.exists():
        raise FileNotFoundError(
            f"resolved.json not found at {resolved_path}; run tools/bootstrap.ps1 first"
        )
    # Bytes, not text: json.loads tolerates a UTF-8 BOM in bytes and rejects one in
    # str, and a PowerShell 5.1 host writes this file. See the module docstring.
    resolved = json.loads(resolved_path.read_bytes())

    spec_hashes, spec_search_roots = _spec_hashes(repo_root)
    return {
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "host": {"system": platform.system(), "release": platform.release()},
        "repo_commit": _git_commit(repo_root),
        "scanners": {name: _scanner_entry(entry) for name, entry in sorted(resolved.items())},
        "spec_hashes": spec_hashes,
        "spec_search_roots": spec_search_roots,
    }
