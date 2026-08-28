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
