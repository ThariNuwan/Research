"""The retention-coverage report (design spec section 8).

This is PLAN Q7's *normalization / retention coverage* metric, not a detection-
accuracy metric: detection is delegated to the three scanners, and this module
only accounts for what happened to what they already found on the way through
layers 1-2 and Q8 dedupe. Its whole purpose is to make "nothing was silently
lost" a checkable claim rather than an assertion - every scanner run's `in`
count must equal `out + dropped`, and every state the record can carry
(`unmapped:`, `unknown`, an unresolved identity, an unresolved fingerprint) is
counted explicitly rather than folded into a rate that would hide it.

**Spec section 8's cause list is corrected here, in two ways, both measured
against the committed fixtures rather than argued.** First, "non-resource
kind" is not an unresolved-identity cause at all - Task 5 gives non-resource
findings real, resolved identities (`identity_kind` values `secret`, `file`,
`provider`) - so it is reported here as its own context-eligibility breakdown
(`identity_kind_counts`, `context_eligible`, `context_ineligible`) rather than
folded into the unresolved-cause counters. Second, the remaining three causes
- unparseable file, no line supplied, and a supplied line matching no
indexed span - are all kept as separate, named counters, including the third
one. Fix round 2 corrected an earlier version of this module that dropped the
third counter on the reasoning that it has zero population in corpus v0;
that conflated "zero here" with "cannot happen" - `resources.py`'s
`ResourceIndex.by_line` and `trivy.py`'s `_resolve_kubernetes` both document
the unmatched-line case as a real return path, just one corpus v0 never
exercises. Reporting it as an explicit zero, rather than omitting the counter,
is what lets a future corpus that does exercise it be seen rather than
silently folded into "no line supplied".

One finding in corpus v0 hits two of the three causes at once: its file is
unparseable **and** its raw record carries no line number at all. Unparseable-
file takes precedence over both line-based causes - the file never entered the
resource index, so whatever the line field says is moot - and each unresolved
finding is assigned to exactly one cause, never more than one, so the three
counters sum to the unresolved total without double counting.

Per scanner-and-platform coverage is keyed `(scanner, platform)`, not `scanner`
alone: checkov is the one scanner in corpus v0 that runs against both scan
roots, and a `str`-keyed mapping could hold only one of its two runs. No
rollup across platforms is computed - the per-run breakdown is what spec
section 8 asks for, and a summed figure is not.

Tier 1 and Tier 2 are reported as the separate figures Q8 already keeps
distinct (`DedupeResult.collapsed_count`, `.candidates`,
`.cross_scanner_candidates`, `.same_scanner_candidates`) and are never summed
here either - an alert-reduction figure that mixed an exact collapse count
with a surfaced-but-unmerged candidate count would overstate what the
pipeline actually removed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iacrisk.dedupe import DedupeResult
from iacrisk.finding import NormalizedFinding
from iacrisk.scanners.base import AdapterResult

UNPARSEABLE_FILE = "unparseable_file"
"""One of three unresolved-identity causes this module distinguishes (module docstring).

Checked first in `_unresolved_cause`: it wins over either line-based cause
whenever more than one condition holds on the same finding.
"""

NO_LINE_SUPPLIED = "no_line_supplied"
"""The scanner's raw record carried no line number at all (`line_range is None`).

Checked second, after `UNPARSEABLE_FILE`.
"""

LINE_UNMATCHED = "line_unmatched"
"""A line number was supplied, on a parseable file, but matched no indexed span.

Zero population in corpus v0 (module docstring) but a real, documented return
path in `resources.py`'s `ResourceIndex.by_line` and `trivy.py`'s
`_resolve_kubernetes` - reported as an explicit zero rather than omitted, so a
future corpus that does exercise it is counted rather than silently folded
into `NO_LINE_SUPPLIED`.
"""


@dataclass(frozen=True)
class ScannerCoverage:
    """Retention accounting for one `(scanner, platform)` adapter run.

    `findings_in` is derived as `findings_out + len(dropped)` rather than read
    from a fourth, independent count - `AdapterResult` carries no other number
    to derive it from, so this is the whole of what "in == out + dropped"
    means for a report built from one `AdapterResult`.

    The four resolution/rate pairs below are stored counts plus properties
    computed from them, never a second stored rate that could drift from the
    count it describes. Every rate's denominator is `findings_out`; where that
    is zero the rate is `None`, not `0.0` - a rate over no findings is
    undefined, and `0.0` would read as "nothing unresolved" (module docstring;
    zero-findings rule).
    """

    scanner: str
    platform: str
    findings_in: int
    findings_out: int
    dropped: tuple[tuple[str, str], ...]
    identity_resolved: int
    identity_unresolved: int
    unresolved_unparseable_file: int
    unresolved_no_line_supplied: int
    unresolved_line_unmatched: int
    fingerprint_resolved: int
    unmapped: int
    unknown_severity: int
    identity_kind_counts: Mapping[str, int]
    context_eligible: int
    context_ineligible: int

    @property
    def identity_resolution_rate(self) -> float | None:
        """`identity_resolved / findings_out`, or `None` if there were no findings."""
        if self.findings_out == 0:
            return None
        return self.identity_resolved / self.findings_out

    @property
    def fingerprint_resolution_rate(self) -> float | None:
        """`fingerprint_resolved / findings_out`, or `None` if there were no findings.

        Trivy's fingerprint is `None` by design on every finding (spec section
        6), so this rate is `0.0` for every trivy run - a real, expected zero,
        not a defect (task 9 brief).
        """
        if self.findings_out == 0:
            return None
        return self.fingerprint_resolved / self.findings_out

    @property
    def unmapped_rate(self) -> float | None:
        """`unmapped / findings_out`, or `None` if there were no findings."""
        if self.findings_out == 0:
            return None
        return self.unmapped / self.findings_out

    @property
    def unknown_severity_rate(self) -> float | None:
        """`unknown_severity / findings_out`, or `None` if there were no findings."""
        if self.findings_out == 0:
            return None
        return self.unknown_severity / self.findings_out

    def to_json(self) -> dict[str, object]:
        """This run's coverage as JSON-safe primitives, one dict per `(scanner, platform)` key."""
        return {
            "scanner": self.scanner,
            "platform": self.platform,
            "findings_in": self.findings_in,
            "findings_out": self.findings_out,
            "dropped": [{"rule_id": rule_id, "reason": reason} for rule_id, reason in self.dropped],
            "identity_resolved": self.identity_resolved,
            "identity_unresolved": self.identity_unresolved,
            "identity_resolution_rate": self.identity_resolution_rate,
            "unresolved_unparseable_file": self.unresolved_unparseable_file,
            "unresolved_no_line_supplied": self.unresolved_no_line_supplied,
            "unresolved_line_unmatched": self.unresolved_line_unmatched,
            "fingerprint_resolved": self.fingerprint_resolved,
            "fingerprint_resolution_rate": self.fingerprint_resolution_rate,
            "unmapped": self.unmapped,
            "unmapped_rate": self.unmapped_rate,
            "unknown_severity": self.unknown_severity,
            "unknown_severity_rate": self.unknown_severity_rate,
            "identity_kind_counts": dict(self.identity_kind_counts),
            "context_eligible": self.context_eligible,
            "context_ineligible": self.context_ineligible,
        }


@dataclass(frozen=True)
class RetentionReport:
    """Every `ScannerCoverage` this run produced, plus the two dedupe tiers, never summed.

    `scanners` is keyed `(scanner, platform)` (R27): a `str`-keyed mapping
    cannot hold checkov's two runs at once, so the tuple key is what keeps
    `checkov/terraform` and `checkov/kubernetes` from silently overwriting one
    another at the call site. `tier1_collapsed` is `DedupeResult.
    collapsed_count`; `tier2_candidates`, `tier2_cross_scanner` and
    `tier2_same_scanner` are the three Tier-2 figures `DedupeResult` already
    keeps apart (R28) - `tier2_cross_scanner + tier2_same_scanner ==
    tier2_candidates` by construction, since both are read from
    `DedupeResult`'s own partition of `candidates` rather than recomputed.
    """

    scanners: Mapping[tuple[str, str], ScannerCoverage]
    tier1_collapsed: int
    tier2_candidates: int
    tier2_cross_scanner: int
    tier2_same_scanner: int

    def to_json(self) -> dict[str, object]:
        """The full report as JSON-safe primitives.

        `scanners` keys serialize as `"<scanner>/<platform>"` strings (JSON
        object keys must be strings; R27) rather than a two-element array or a
        nested mapping, so the same key spelling this report and a reader both
        use is unambiguous. Sorted for a deterministic top-level ordering, not
        because ordering carries meaning.
        """
        return {
            "scanners": {
                f"{scanner}/{platform}": coverage.to_json()
                for (scanner, platform), coverage in sorted(self.scanners.items())
            },
            "tier1_collapsed": self.tier1_collapsed,
            "tier2_candidates": self.tier2_candidates,
            "tier2_cross_scanner": self.tier2_cross_scanner,
            "tier2_same_scanner": self.tier2_same_scanner,
        }


def _unresolved_cause(finding: NormalizedFinding, unparseable: frozenset[str]) -> str:
    """Which of the three causes one unresolved-identity finding is assigned to.

    Unparseable-file is checked first and wins whenever more than one
    condition holds on the same finding - the file never entered the resource
    index, so whatever `line_range` says is moot once that is true (module
    docstring; the one corpus v0 finding, a `KSV-0117` on a
    `metadata-db/templates` Helm template, that is both unparseable and
    lineless). Between the two line-based causes, an absent `line_range` is
    checked before an unmatched one - a finding with no line at all was never
    going to reach `ResourceIndex.by_line`, so `LINE_UNMATCHED` is reserved for
    a line that was actually looked up and failed to match, not merely absent.
    Assigning to exactly one cause is what keeps `unresolved_unparseable_file +
    unresolved_no_line_supplied + unresolved_line_unmatched` equal to the
    unresolved total instead of double counting.
    """
    if finding.file_path in unparseable:
        return UNPARSEABLE_FILE
    if finding.line_range is None:
        return NO_LINE_SUPPLIED
    return LINE_UNMATCHED


def _coverage_for(
    scanner: str,
    platform: str,
    result: AdapterResult,
    unparseable: frozenset[str],
) -> ScannerCoverage:
    """One `ScannerCoverage` from one adapter run's `AdapterResult`."""
    findings = result.findings
    findings_out = len(findings)
    findings_in = findings_out + len(result.dropped)

    unresolved_findings = [f for f in findings if f.identity_kind == "unresolved"]
    identity_unresolved = len(unresolved_findings)
    identity_resolved = findings_out - identity_unresolved

    causes = Counter(_unresolved_cause(f, unparseable) for f in unresolved_findings)

    fingerprint_resolved = sum(1 for f in findings if f.has_resolved_fingerprint)
    unmapped = sum(1 for f in findings if f.is_unmapped)
    unknown_severity = sum(1 for f in findings if f.severity_level == "unknown")
    context_eligible = sum(1 for f in findings if f.context_eligible)

    return ScannerCoverage(
        scanner=scanner,
        platform=platform,
        findings_in=findings_in,
        findings_out=findings_out,
        dropped=result.dropped,
        identity_resolved=identity_resolved,
        identity_unresolved=identity_unresolved,
        unresolved_unparseable_file=causes[UNPARSEABLE_FILE],
        unresolved_no_line_supplied=causes[NO_LINE_SUPPLIED],
        unresolved_line_unmatched=causes[LINE_UNMATCHED],
        fingerprint_resolved=fingerprint_resolved,
        unmapped=unmapped,
        unknown_severity=unknown_severity,
        identity_kind_counts=MappingProxyType(dict(Counter(f.identity_kind for f in findings))),
        context_eligible=context_eligible,
        context_ineligible=findings_out - context_eligible,
    )


def build_report(
    results: Mapping[tuple[str, str], AdapterResult],
    dedupe: DedupeResult,
    unparseable: frozenset[str],
) -> RetentionReport:
    """Build the retention-coverage report from every adapter run plus the dedupe result.

    `results` is keyed `(scanner, platform)` (R27), not `scanner` alone, so
    checkov's two runs both survive to the output. `unparseable` is the
    scan-root-relative POSIX path set a caller already has from
    `DiscoveryResult.unparseable` or `ResourceIndex.unparseable` - taken as a
    plain `frozenset[str]` rather than the `resources.py`/`input.py` types
    that produce it, so this module's own dependencies stay to `dedupe.py`,
    `finding.py` and `scanners/base.py` alone.

    `unparseable` has no default. An empty default would silently move every
    unparseable-file finding into one of the two line-based causes for a
    caller that forgot to pass it - exactly the silent default this project's
    explicit-state discipline forbids - so a caller with no unparseable files
    must pass `frozenset()` explicitly.
    """
    scanners = {
        key: _coverage_for(key[0], key[1], result, unparseable) for key, result in results.items()
    }
    return RetentionReport(
        scanners=MappingProxyType(scanners),
        tier1_collapsed=dedupe.collapsed_count,
        tier2_candidates=len(dedupe.candidates),
        tier2_cross_scanner=len(dedupe.cross_scanner_candidates),
        tier2_same_scanner=len(dedupe.same_scanner_candidates),
    )
