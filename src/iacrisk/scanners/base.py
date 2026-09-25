"""Shared adapter surface, and the one path spelling all three scanners reduce to.

Each adapter (Tasks 5-7) turns one scanner's raw JSON into `NormalizedFinding`
values; this module holds only what all three share before any of them exist:
the result shape they return in, the protocol they implement, and the path
rebasing every one of them needs before a finding can be joined to a resource
in the index built by Task 3. checkov and trivy already report paths
scan-root-relative; tfsec reports 119 of 119 findings as an absolute Windows
path (measured, design spec §1; the rebasing rule itself is §5.1).
`ResourceIndex.by_line` matches on `relative_path` by equality, so a path
spelled three ways is silently three files to that lookup - not an error,
just a `None` where a match should have been.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from iacrisk.finding import NormalizedFinding
from iacrisk.resources import ResourceIndex

_ABSOLUTE_PREFIX = re.compile(r"^[A-Za-z]:|^//")
"""A drive prefix (`C:`, with or without a trailing separator) or a UNC root
(`//server/share`), once backslashes are forward slashes.

tfsec's own paths only ever exercise the drive-with-separator shape
(`D:/Research/...`), but `_is_absolute` has to recognize the other two shapes
as absolute as well, or each becomes a second silent mis-join hiding behind
the first: `//server/share/file.tf` starts with `/`, not a letter, so a
drive-only pattern never matches it and it falls through to `lstrip("/")` as
though it were scan-root-relative; a bare `C:` has no trailing `/` to match a
pattern that requires one, so it falls through the same way. Neither shape is
emitted by any scanner in corpus v0 (spec §1's measured-facts table) or by
this function's own output - named here as a closed door, not a measured one.
checkov's `/ec2.tf` must still read as *not* absolute - a single leading `/`
with no drive letter and no second `/` is a scan-root-relative path, not a
filesystem root - or it would raise instead of rebasing.
"""


@dataclass(frozen=True)
class AdapterResult:
    """What one adapter run produced, plus what it explicitly could not use.

    `dropped` is `(rule_id, reason)` pairs for raw findings that did not become
    a `NormalizedFinding` at all - never a place to route a finding that merely
    carries an unresolved field, which stays IN `findings` per the explicit-
    state discipline (spec §0.1) rather than being pulled out of the count.
    """

    findings: tuple[NormalizedFinding, ...]
    dropped: tuple[tuple[str, str], ...]


def rebase_to_scan_root(raw_path: str, scan_root: Path) -> str:
    """Reduce any scanner's path spelling to one scan-root-relative, forward-slash form.

    Backslashes are replaced explicitly rather than via a path library, per the
    Windows-native constraint (spec §0.1): path handling here is character
    work, not a `pathlib` assumption, because `PurePosixPath` does not treat a
    backslash as a separator even on Windows, which is exactly the checkov
    spelling (`\\db-app.tf`) this function has to normalize.

    Scan-root-relative is the target, not repository-relative: stripping only
    the repository root would leave `corpus/vendor/terragoat/terraform/aws/
    ec2.tf`, which joins with neither checkov's nor trivy's spelling of the same
    file (spec §5.1). The scan root is the frame the scanners were invoked in,
    so it is the only frame all three can be brought to without rewriting two
    of them.

    An absolute path outside the scan root raises rather than passing through:
    there is no meaningful rebasing for it, and a passed-through absolute path
    would silently join with nothing rather than failing loudly. Prefix
    matching is case-insensitive because the scan root as configured and the
    path as tfsec reports it need not agree on drive-letter or path case.
    """
    normalized = raw_path.replace("\\", "/")
    root = str(scan_root).replace("\\", "/").rstrip("/")

    if _is_absolute(normalized):
        if normalized.lower().startswith(root.lower() + "/"):
            normalized = normalized[len(root) + 1 :]
        elif normalized.lower() == root.lower():
            normalized = ""
        else:
            raise ValueError(f"absolute path is outside the scan root: {raw_path!r}")

    return normalized.lstrip("/")


def _is_absolute(posix_style: str) -> bool:
    """Whether `posix_style` is a Windows drive or UNC path rather than being relative."""
    return bool(_ABSOLUTE_PREFIX.match(posix_style))


class ScannerAdapter(Protocol):
    """The shape every scanner adapter presents to whatever runs the pipeline.

    `index` is `None` for terraform, where identity comes from the scanner's
    own field (spec §5.1); a Kubernetes adapter needs it to resolve identity by
    line or by kind/namespace/name. The protocol takes the union rather than
    two separate methods so one call site can drive any adapter without
    knowing which platform it belongs to.
    """

    name: str

    def parse(self, raw: object, scan_root: Path, index: ResourceIndex | None) -> AdapterResult: ...
