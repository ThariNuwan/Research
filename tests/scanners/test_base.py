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
    assert (
        rebase_to_scan_root(
            "d:\\research\\CORPUS\\vendor\\terragoat\\terraform\\aws\\ec2.tf", SCAN_ROOT
        )
        == "ec2.tf"
    )


@pytest.mark.parametrize(
    "raw",
    [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:",
        "\\\\server\\share\\file.tf",
    ],
    ids=["drive-elsewhere", "bare-drive", "unc-root"],
)
def test_an_absolute_path_outside_the_scan_root_raises(raw: str) -> None:
    """Silently passing it through would produce a path that joins with nothing.

    Three absolute shapes, none emitted by any scanner in corpus v0 (spec §1):
    a normal drive-letter path elsewhere on disk, a bare drive with no path
    component, and a UNC root. A drive-only pattern like ``^[A-Za-z]:/`` misses
    the last two - ``C:`` has no trailing separator and ``//server/share/...``
    has no drive letter at all - and each would otherwise fall through to
    ``lstrip("/")`` and be silently treated as scan-root-relative.
    """
    with pytest.raises(ValueError, match="outside the scan root"):
        rebase_to_scan_root(raw, SCAN_ROOT)


def test_rebasing_is_idempotent() -> None:
    absolute = "D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\ec2.tf"
    once = rebase_to_scan_root(absolute, SCAN_ROOT)

    assert rebase_to_scan_root(once, SCAN_ROOT) == once
