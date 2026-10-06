"""Every output carries enough provenance to be reproduced (spec section 4.4).

A provenance block exists so a reader holding only the output JSON can reconstruct
which bytes produced which numbers. That is what makes two pairs of facts, which a
bare `None` or a bare `{}` would render identically, the ones this module tests
hardest:

- *there is no commit to determine* against *I could not determine the commit*, in
  `repo_commit`'s six states;
- *no spec files exist* against *specs exist and were not hashed*, in
  `spec_hashes` plus the roots it reports having searched.

The tests that read this repository rather than a `tmp_path` skip when
`tools/resolved.json` is absent: it is written by `tools/bootstrap.ps1` and
git-ignored, so it exists on a bootstrapped host and not in a fresh clone. `-rs` in
`addopts` makes such a skip visible rather than silent.

Where a payload this repository's writer cannot produce is used deliberately,
`Unobserved:` marks it in the test's own docstring - the convention
`tests/harvest/test_walkers.py` established and `test_tally.py` restates.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

# `_git_commit` is private and imported anyway: its six states are reached through a
# repository's shape and through git's own refusals, and `build_provenance` offers no
# way to supply either - one fixture per state would have to be a whole repository.
# `GIT_TIMEOUT_SECONDS` is public and imported so the stand-in below raises the timeout
# the code under test actually passed, rather than a number restated here.
from tools.harvest.provenance import (
    GIT_TIMEOUT_SECONDS,
    _git_commit,
    build_provenance,
    hash_file,
    worktree_clean,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESOLVED = REPO_ROOT / "tools" / "resolved.json"
UTF8_BOM = b"\xef\xbb\xbf"
HEX = set("0123456789abcdef")

# The pinned versions, and the one-line display value each scanner's captured
# `--version` output reduces to. Hardcoded rather than read from
# `tools/resolved.json` for the reason `tests/test_scanners_lock.py` gives about the
# pins: a test whose expectation comes from the file under test cannot detect that
# file changing. tfsec's is the case that motivates `version_display` at all - its
# raw capture is a 382-character, 11-line deprecation banner wrapped around
# `v1.28.14`, measured this session over the bootstrapped `tools/resolved.json` on
# this host.
EXPECTED_DISPLAY = {"checkov": "3.3.12", "trivy": "Version: 0.74.0", "tfsec": "v1.28.14"}


def _skip_without_resolved() -> None:
    if not RESOLVED.exists():
        pytest.skip("tools/resolved.json does not exist yet (written by tools/bootstrap.ps1)")


def _skip_without_git() -> None:
    """Skip when git cannot be run: every state assertion below would read the same.

    Without this, a host with no git turns the `not-a-checkout` and `git-failed`
    tests into `git-unavailable` failures that say nothing about the code.
    """
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        pytest.skip(f"git is not usable here: {exc}")


def _skip_inside_a_checkout(tmp_path: Path) -> None:
    """Skip when a `.git` sits above `tmp_path`: the refusals below cannot be produced.

    `rev-parse --git-dir` succeeds from any child of a repository, so with a checkout
    as an ancestor every directory built under `tmp_path` answers `ok` and the states
    this file distinguishes collapse into one.
    """
    if any((parent / ".git").exists() for parent in (tmp_path, *tmp_path.parents)):
        pytest.skip(f"{tmp_path} sits inside a git checkout, so the states collapse")


def _raising_run(error: BaseException) -> Callable[..., subprocess.CompletedProcess[str]]:
    """A `subprocess.run` stand-in that always raises `error`.

    Patched onto the `subprocess` module itself rather than onto an attribute of
    `provenance`: that module does `import subprocess` and resolves `.run` at call
    time, so its global is this same module object and one `monkeypatch.setattr`
    reaches both. `monkeypatch` undoes it when the test ends.
    """

    def fake(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise error

    return fake


def test_hash_file_is_stable_and_hex(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    digest = hash_file(target)
    assert digest == hash_file(target)
    assert len(digest) == 64
    assert digest == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_provenance_records_scanner_versions_and_python(tmp_path: Path) -> None:
    """The shape Task 8's runner stamps onto the inventory.

    Neither of these two records carries a `version_output`, which is the state
    decision 2 rules on: a scanner that printed nothing gets no `version_display`
    key at all rather than an empty display string, since `""` would assert a tidy
    value for a capture that does not exist.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_text(
        json.dumps(
            {
                "trivy": {"exe": "C:\\bin\\trivy.exe", "version": "0.74.0"},
                "checkov": {"exe": "C:\\bin\\checkov.exe", "version": "3.3.12"},
            }
        ),
        encoding="utf-8",
    )

    prov = build_provenance(tmp_path)

    assert prov["scanners"]["trivy"]["version"] == "0.74.0"
    assert prov["scanners"]["trivy"]["exe"] == "C:\\bin\\trivy.exe"
    assert sorted(prov["scanners"]) == ["checkov", "trivy"]
    assert "version_output" not in prov["scanners"]["trivy"]
    assert "version_display" not in prov["scanners"]["trivy"]
    assert "version_display_rule" not in prov["scanners"]["trivy"]
    assert prov["python"].startswith("3.12")
    assert prov["generated_utc"].endswith("Z")
    assert set(prov["repo_commit"]) == {"commit", "state"}
    assert prov["spec_hashes"] == {}, "neither docs/superpowers/specs nor specs exists here"
    searched = prov["spec_search_roots"]
    assert [root["root"] for root in searched] == ["docs/superpowers/specs", "specs"]
    assert all(root["exists"] is False for root in searched)
    assert all(root["files_hashed"] == 0 for root in searched)


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
    report = {root["root"]: root for root in prov["spec_search_roots"]}
    assert report["specs"] == {"root": "specs", "exists": True, "files_hashed": 2}
    assert report["docs/superpowers/specs"]["exists"] is False


def test_both_spec_roots_are_searched_and_each_one_is_reported(tmp_path: Path) -> None:
    """`{}` with no statement of where it looked cannot be told from "not hashed".

    Two roots because this repository's one spec lives under `docs/superpowers/`
    while `.gitattributes` pins LF for a top-level `specs/` by name. Searching one
    and reporting neither is what made the empty result unreadable.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_text("{}", encoding="utf-8")
    nested = tmp_path / "docs" / "superpowers" / "specs"
    nested.mkdir(parents=True)
    (nested / "design.md").write_text("# design\n", encoding="utf-8")
    top = tmp_path / "specs"
    top.mkdir()
    (top / "rubric.yaml").write_text("factors: []\n", encoding="utf-8")

    prov = build_provenance(tmp_path)

    assert set(prov["spec_hashes"]) == {"docs/superpowers/specs/design.md", "specs/rubric.yaml"}
    assert [root["files_hashed"] for root in prov["spec_search_roots"]] == [1, 1]


def test_missing_resolved_json_is_an_explicit_error(tmp_path: Path) -> None:
    """Silently emitting a result with no scanner provenance is worse than failing."""
    with pytest.raises(FileNotFoundError, match=r"resolved\.json"):
        build_provenance(tmp_path)


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"[]", "object of scanner records"),
        (b'{"trivy": "0.74.0"}', "records trivy as a str"),
        (b"{not json at all", "not valid JSON"),
    ],
    ids=["top-level-list", "record-is-a-string", "unparseable-bytes"],
)
def test_a_malformed_resolved_json_names_the_file_it_could_not_read(
    payload: bytes, expected: str, tmp_path: Path
) -> None:
    """A file that exists but is the wrong shape fails the way an absent one does.

    Unvalidated, a top-level list reaches `.items()` and a string record reaches
    `.get`, and the `AttributeError` that follows names neither the file nor what was
    wrong with it. For a file that is gitignored, written only by
    `tools/bootstrap.ps1`, and read five tasks later, naming the path *is* the
    diagnosis - which is why the absent case already does it.

    Unobserved: all three payloads are shapes this repository's writer cannot produce.
    `tools/bootstrap.ps1` writes one object per resolved scanner or dies first, so
    these are the hand-edit and half-written-file cases, not observed output.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_bytes(payload)

    with pytest.raises(ValueError, match=expected) as raised:
        build_provenance(tmp_path)
    assert str(tmp_path / "tools" / "resolved.json") in str(raised.value)


def test_a_utf8_bom_on_resolved_json_is_read_not_rejected(tmp_path: Path) -> None:
    """`json.loads` accepts a BOM in `bytes` and rejects one in `str`.

    `tools/resolved.json` is written by `tools/bootstrap.ps1` on a Windows
    PowerShell 5.1 host, where `Out-File -Encoding utf8` and `Set-Content` both emit
    a UTF-8 BOM and `ConvertFrom-Json` tolerates one. Reading it as text would fail
    on a file every default writer there produces, five tasks after the file was
    written. The bootstrapped copy on this host is BOM-free today, which is a fact
    about today rather than a property of the writer, so this test supplies the BOM
    itself.
    """
    (tmp_path / "tools").mkdir()
    payload = json.dumps({"tfsec": {"exe": "C:\\bin\\tfsec.exe", "version": "1.28.14"}})
    (tmp_path / "tools" / "resolved.json").write_bytes(UTF8_BOM + payload.encode("utf-8"))

    prov = build_provenance(tmp_path)

    assert prov["scanners"]["tfsec"]["version"] == "1.28.14"


@pytest.mark.parametrize(
    ("version_output", "output_is_retained"),
    [("  \n\n ", True), (None, False)],
    ids=["blank-capture", "json-null"],
)
def test_a_scanner_that_printed_nothing_gets_no_display_value(
    version_output: str | None, output_is_retained: bool, tmp_path: Path
) -> None:
    """The raw capture is kept; no tidy value is invented from a blank one.

    The other half of decision 2: a `version_output` that is present but holds no
    non-empty line is not an absent key, so the raw is still copied - but there is
    no one-line version to display, and `""` would assert that there is.

    The `null` case is the one that folds. `entry.get` returns `None` both for a key
    that is absent and for a key whose value is JSON `null`, so `null` is emitted the
    way a missing key is - no `version_output` at all - while a blank string is
    retained. Three input states, two behaviours, and this parametrization is where
    the second one is asserted rather than inferred from the code.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "resolved.json").write_text(
        json.dumps({"tfsec": {"exe": "x", "version": "1.28.14", "version_output": version_output}}),
        encoding="utf-8",
    )

    prov = build_provenance(tmp_path)

    entry = prov["scanners"]["tfsec"]
    assert ("version_output" in entry) is output_is_retained
    if output_is_retained:
        assert entry["version_output"] == version_output
    assert entry["version"] == "1.28.14", "the record's other keys are unaffected"
    assert "version_display" not in entry
    assert "version_display_rule" not in entry


def test_a_multi_line_banner_reduces_to_its_last_non_empty_line(tmp_path: Path) -> None:
    """The normalization rule, on a hermetic capture with the shape tfsec's has.

    Last non-empty line, whitespace-stripped - not first: tfsec prints its ASCII
    rule first, and a display value of `======...` is worse than the banner it
    replaces. CRLF is in the fixture deliberately, because that is what the real
    capture holds: the bootstrapped `tools/resolved.json` on this host stores
    tfsec's banner with `\\r\\n` separators.
    """
    (tmp_path / "tools").mkdir()
    banner = "======\r\nsomething is joining something\r\n\r\n======\r\n  v9.9.9  \r\n"
    (tmp_path / "tools" / "resolved.json").write_text(
        json.dumps({"tfsec": {"exe": "x", "version": "9.9.9", "version_output": banner}}),
        encoding="utf-8",
    )

    prov = build_provenance(tmp_path)

    entry = prov["scanners"]["tfsec"]
    assert entry["version_display"] == "v9.9.9"
    assert entry["version_display_rule"] == "last-non-empty-line"
    assert entry["version_output"] == banner, "the raw capture is retained beside the tidy one"


def test_repo_commit_is_ok_with_a_forty_hex_sha_in_this_checkout() -> None:
    """The `ok` state, measured against the checkout the tests are running in."""
    _skip_without_git()
    result = _git_commit(REPO_ROOT)
    assert result["state"] == "ok"
    commit = result["commit"]
    assert commit is not None
    assert len(commit) == 40
    assert set(commit) <= HEX, f"not a hex sha: {commit!r}"


def test_not_a_checkout_is_a_different_state_from_a_git_that_failed(tmp_path: Path) -> None:
    """The distinction one `None` for every failure destroys.

    Both directories make `git rev-parse HEAD` exit non-zero, and they mean opposite
    things: one is not a repository at all, the other is a repository whose HEAD is
    unborn. Telling them apart needs the second probe - `rev-parse --git-dir` - which
    is why `_git_commit` runs two.
    """
    _skip_without_git()
    _skip_inside_a_checkout(tmp_path)

    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    unborn = tmp_path / "fresh-repo"
    unborn.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", str(unborn)], capture_output=True, check=True, timeout=30
    )

    assert _git_commit(outside) == {"commit": None, "state": "not-a-checkout"}
    assert _git_commit(unborn) == {"commit": None, "state": "git-failed"}


def _missing_directory(tmp_path: Path) -> Path:
    """A path that was never created, so git cannot change into it."""
    return tmp_path / "never-created"


def _corrupt_git_pointer(tmp_path: Path) -> Path:
    """A directory whose `.git` *file* points at a gitdir that does not exist."""
    target = tmp_path / "corrupt-pointer"
    target.mkdir()
    (target / ".git").write_text(f"gitdir: {tmp_path / 'nowhere-at-all'}\n", encoding="utf-8")
    return target


@pytest.mark.parametrize(
    "make_target",
    [_missing_directory, _corrupt_git_pointer],
    ids=["missing-directory", "corrupt-git-pointer"],
)
def test_an_exit_128_without_the_non_repository_signature_is_git_failed(
    make_target: Callable[[Path], Path], tmp_path: Path
) -> None:
    """Exit 128 is not a verdict: three different refusals share it.

    Measured this session with git 2.55.0.windows.5, running
    `git -C <path> rev-parse --git-dir` on three directories that all exit **128**:

        no repository       fatal: not a git repository (or any of the parent directories): .git
        missing directory   fatal: cannot change to '<abs path>': No such file or directory
        .git -> nowhere     fatal: not a git repository: (NULL)

    Only the first is *"there is nothing to determine"*; the other two - the two cases
    here - are *"I could not ask"*. Calling either of them `not-a-checkout` would put
    the one positive claim this state carries into a provenance block on the strength
    of an exit code that four other refusals also produce.

    Each case asserts a plain sibling directory alongside itself, because a
    discrimination that had collapsed the other way - `git-failed` for everything,
    including a genuine non-repository - would pass the first assertion on its own.

    git's message is read for that discrimination and then dropped: the
    missing-directory line above quotes the host's absolute path, and this block gets
    written into a committed artifact.
    """
    _skip_without_git()
    _skip_inside_a_checkout(tmp_path)

    target = make_target(tmp_path)
    assert _git_commit(target) == {"commit": None, "state": "git-failed"}

    plain = tmp_path / "plain-dir"
    plain.mkdir()
    assert _git_commit(plain) == {"commit": None, "state": "not-a-checkout"}


@pytest.mark.parametrize(
    ("error", "expected_state"),
    [
        (FileNotFoundError("git"), "git-unavailable"),
        (subprocess.TimeoutExpired(cmd=["git"], timeout=GIT_TIMEOUT_SECONDS), "git-timeout"),
    ],
    ids=["git-unavailable", "git-timeout"],
)
def test_git_that_could_not_run_names_which_way_it_could_not(
    error: BaseException, expected_state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git absent and git hung are two facts, and neither is "there is no commit"."""
    monkeypatch.setattr(subprocess, "run", _raising_run(error))
    assert _git_commit(REPO_ROOT) == {"commit": None, "state": expected_state}


def test_a_successful_git_with_empty_output_is_its_own_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fifth failure that looks like success from outside: exit 0, nothing said."""

    def fake(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["git"], returncode=0, stdout="", stderr="")

    # Same patch target as `_raising_run`, for the reason given there.
    monkeypatch.setattr(subprocess, "run", fake)
    assert _git_commit(REPO_ROOT) == {"commit": None, "state": "empty-output"}


def test_a_hang_on_the_second_probe_is_a_timeout_and_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The realistic hang: `--git-dir` answers at once and `rev-parse HEAD` does not.

    `_raising_run` raises on every call, so every test above it can only ever exercise
    probe 1. Probe 2 has its own `except` arms and its own mapping from failure to
    state - it is the one that turns a non-zero exit into `git-failed` rather than
    consulting stderr - and nothing reaches them until a stand-in survives the first
    call. The call log is asserted for the same reason: `git-timeout` would also be the
    answer if probe 2 had never run, and a returned state cannot tell those apart.

    The timeout raised is `GIT_TIMEOUT_SECONDS`, imported from the module under test
    rather than restated here, so this stand-in hangs for as long as the code allows.
    """
    calls: list[tuple[str, ...]] = []

    def fake(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(cmd))
        if len(calls) == 1:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=".git\n", stderr="")
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=GIT_TIMEOUT_SECONDS)

    monkeypatch.setattr(subprocess, "run", fake)  # same target as `_raising_run`

    assert _git_commit(REPO_ROOT) == {"commit": None, "state": "git-timeout"}
    assert len(calls) == 2, "probe 2 has to have run for this to be probe 2's timeout"
    assert calls[0][-1] == "--git-dir"
    assert calls[1][-1] == "HEAD"


def test_this_repository_hashes_its_real_spec_and_tidies_the_tfsec_banner() -> None:
    """The two halves that only the real repository can show, on a bootstrapped host.

    `spec_hashes` was `{}` at every real run while the glob pointed at a top-level
    `specs/` this repository does not have, and the tmp_path tests could not see it:
    their fixtures had no spec root either, so `== {}` was true for the wrong reason.

    And tfsec's raw `version_output` really is a banner - measured this session over
    the bootstrapped `tools/resolved.json` on this host: 382 characters across 11
    lines, against checkov's 6 and trivy's 15 on one line each. The tidy value sits beside the raw,
    never instead of it, since `tools/resolved.json` is read-only and its fidelity is
    deliberate.
    """
    _skip_without_resolved()
    _skip_without_git()

    prov = build_provenance(REPO_ROOT)

    spec = "docs/superpowers/specs/2026-08-24-implementation-phase0-design.md"
    assert spec in prov["spec_hashes"], f"the one spec this repo has went unhashed: {spec}"
    assert len(prov["spec_hashes"][spec]) == 64
    assert prov["repo_commit"]["state"] == "ok"

    raw: dict[str, Any] = json.loads(RESOLVED.read_bytes())
    for name, display in EXPECTED_DISPLAY.items():
        entry = prov["scanners"][name]
        assert entry["version_display"] == display
        assert entry["version_display_rule"] == "last-non-empty-line"
        assert entry["version_output"] == raw[name]["version_output"], "raw capture altered"
    assert "\n" in prov["scanners"]["tfsec"]["version_output"], "tfsec's banner is multi-line"
    assert "\n" not in prov["scanners"]["tfsec"]["version_display"]


def test_worktree_clean_tracks_whether_the_tree_matches_head(tmp_path: Path) -> None:
    """A fresh repository with one committed file is clean; an edit makes it dirty."""
    _skip_without_git()
    _skip_inside_a_checkout(tmp_path)

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *args],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )

    git("init", "-q")
    tracked = tmp_path / "a.txt"
    tracked.write_text("one\n", encoding="utf-8")
    git("add", "a.txt")
    git("commit", "-q", "-m", "one")
    assert worktree_clean(tmp_path) is True

    tracked.write_text("two\n", encoding="utf-8")
    assert worktree_clean(tmp_path) is False


def test_worktree_clean_can_ignore_a_directory_of_outputs(tmp_path: Path) -> None:
    """A regenerated output does not make the code that produced it dirty; an edit
    anywhere else still does."""
    _skip_without_git()
    _skip_inside_a_checkout(tmp_path)

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", *args],
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )

    git("init", "-q")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "result.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "code.py").write_text("x = 1\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "one")

    (tmp_path / "out" / "result.json").write_text('{"a": 1}\n', encoding="utf-8")
    assert worktree_clean(tmp_path) is False
    assert worktree_clean(tmp_path, ignoring=("out",)) is True

    (tmp_path / "code.py").write_text("x = 2\n", encoding="utf-8")
    assert worktree_clean(tmp_path, ignoring=("out",)) is False


def test_worktree_clean_is_none_where_git_cannot_say(tmp_path: Path) -> None:
    """Not False: outside a repository there is no tree to be dirty."""
    _skip_without_git()
    _skip_inside_a_checkout(tmp_path)
    assert worktree_clean(tmp_path) is None
