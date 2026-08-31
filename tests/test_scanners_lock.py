"""The lockfile is the single source of truth for pins and platform applicability."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "tools" / "scanners.lock.json"
RESOLVED = REPO_ROOT / "tools" / "resolved.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTF8_BOM = b"\xef\xbb\xbf"
EXPECTED = {"checkov": "3.3.12", "trivy": "0.74.0", "tfsec": "1.28.14"}

# The scanners acquired as release archives. Named as a literal rather than
# derived from the lockfile so that flipping an entry's channel cannot silently
# empty the loops that iterate it.
RELEASE_SCANNERS = {"trivy", "tfsec"}

# Verbatim from the plan's Global Constraints. Hardcoded deliberately: this
# test's job is to detect the pin *changing*, so it must not read the pin from
# the file it is checking. Shape alone is not enough - a fat-fingered but
# well-formed digest passes `SHA256_RE` and then surfaces at bootstrap as
# "checksum mismatch" pointing at the archive rather than at the lockfile typo,
# which invites the worst possible repair: pasting the observed hash over the
# pin.
EXPECTED_ARCHIVE_SHA256 = {
    "trivy": "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842",
    "tfsec": "a53c4d7c6c85029378c8895ffbf9b23ea04a887d20136dc1d24d1307cf1a0491",
}

# The executables extracted from the two archives above. These inherit upstream's
# attestation via those digests rather than being self-attested from whatever
# happens to sit in tools/bin/. Pinned by value for the same reason as the
# archive digests, and it matters more here: if a mismatch reported by
# bootstrap.ps1 can be "fixed" by pasting the observed hash into the lockfile,
# the executable check is undone and nothing notices.
EXPECTED_EXE_SHA256 = {
    "trivy": "4c532e1f28f53282dc364671e87381cd77760fa9cafab143f576449c2207cdd5",
    "tfsec": "c177de9da7f75965fdd7b7785ad7d668dfec36b28e6f6b5d62c84a4dfa6374b5",
}


def _lock() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(LOCK.read_text(encoding="utf-8"))
    return data


def test_all_three_scanners_pinned_to_exact_versions() -> None:
    scanners = _lock()["scanners"]
    assert set(scanners) == set(EXPECTED)
    for name, version in EXPECTED.items():
        assert scanners[name]["version"] == version


def test_downloaded_binaries_carry_a_sha256() -> None:
    """A pin without a checksum is not a pin (spec §4.2)."""
    checked: set[str] = set()
    for name, entry in _lock()["scanners"].items():
        if entry["channel"] != "github-release":
            continue
        assert SHA256_RE.match(entry["sha256"]), f"{name} sha256 malformed"
        assert entry["sha256"] == EXPECTED_ARCHIVE_SHA256[name], (
            f"{name} archive sha256 does not match the digest pinned by the plan's "
            "Global Constraints; if bootstrap reported a mismatch, do not paste the "
            "observed hash over the pin"
        )
        assert entry["url"].startswith("https://github.com/"), f"{name} url not https github"
        assert entry["version"] in entry["url"], f"{name} url does not contain its pinned version"
        checked.add(name)

    # Not vacuous: `continue` alone means that flipping both entries to another
    # channel would leave this loop examining nothing and the test passing green,
    # silently discarding the only guard on the sentence in the docstring.
    assert checked == RELEASE_SCANNERS, f"expected {RELEASE_SCANNERS}, checked {checked}"


def test_release_entries_pin_the_executable_not_only_the_archive() -> None:
    """`tools/bin/<exe>` is what the framework runs; the archive is a bystander.

    `tools/cache/` is gitignored and disposable, so an archive digest is the one
    integrity record that can legitimately be absent from a working checkout. The
    executable digest cannot: `bootstrap.ps1` compares it on every run and in
    every mode, and dies when the field is missing rather than skipping the
    comparison. Guard the field's presence, its shape, and its value.

    Unconditional - it reads the committed lockfile, so unlike the
    `resolved.json` guards it also runs on a fresh clone and in CI.
    """
    checked: set[str] = set()
    for name, entry in _lock()["scanners"].items():
        if entry["channel"] != "github-release":
            continue
        assert "exe_sha256" in entry, (
            f"{name} is a github-release entry with no exe_sha256; bootstrap.ps1 "
            "would have nothing to compare tools/bin/ against"
        )
        assert SHA256_RE.match(entry["exe_sha256"]), f"{name} exe_sha256 malformed"
        assert entry["exe_sha256"] == EXPECTED_EXE_SHA256[name], (
            f"{name} exe_sha256 does not match the pinned digest; if bootstrap "
            "reported a mismatch, do not paste the observed hash over the pin"
        )
        checked.add(name)

    assert checked == RELEASE_SCANNERS, f"expected {RELEASE_SCANNERS}, checked {checked}"


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


def test_resolved_json_is_bom_free_utf8_with_absolute_paths() -> None:
    """The contract Task 7's provenance builder and Task 8's runner consume.

    `resolved.json` is written by `tools/bootstrap.ps1` and is gitignored, so
    nothing else in the plan re-checks its bytes. Windows PowerShell 5.1's
    `Out-File -Encoding utf8` emits a UTF-8 BOM, and `ConvertFrom-Json`
    tolerates one - so a BOM here would pass every PowerShell-side check and
    only surface five tasks later as `json.loads` raising "Unexpected UTF-8
    BOM", pointing at a file this task wrote. Assert the Python-side contract
    where it is produced: BOM-free UTF-8, an absolute `exe`, a real `version`.
    """
    if not RESOLVED.exists():
        pytest.skip("tools/resolved.json does not exist yet (written by tools/bootstrap.ps1)")

    assert not RESOLVED.read_bytes().startswith(UTF8_BOM), (
        "tools/resolved.json starts with a UTF-8 BOM; write it with "
        "[System.IO.File]::WriteAllText(..., New-Object System.Text.UTF8Encoding $false)"
    )

    resolved: dict[str, Any] = json.loads(RESOLVED.read_text(encoding="utf-8"))

    # Not vacuous: the bootstrap loops over the lockfile, whose scanner set
    # test_all_three_scanners_pinned_to_exact_versions already pins to EXPECTED.
    assert set(resolved) == set(EXPECTED), f"resolved.json scanners {sorted(resolved)}"
    for name, entry in resolved.items():
        assert Path(entry["exe"]).is_absolute(), f"{name} exe is not an absolute path"
        assert entry["version"], f"{name} version is empty"
