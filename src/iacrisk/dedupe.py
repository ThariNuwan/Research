"""Two-tier deduplication (design spec section 7).

Q8's key is `(canonical resource identity, normalized issue-class, violation
fingerprint)`. Tier 1 collapses two findings into one group only when
identity, class AND a resolved, equal fingerprint all agree - the fingerprint
is what keeps two materially different violations on one resource (two
separate open ingress rules on one security group, two different container
fields) from being conflated into one row, which is exactly what PLAN Q8 #6
added it to prevent. Tier 2 surfaces the rest of the overlap - findings that
share identity and class but where the fingerprint cannot settle whether they
are the same violation or not - as candidates: counted, never merged, and
never contributing to the reported deduplication number. Only Tier 1 produces
that number; alert reduction is reported as two separate figures elsewhere
(deduplication vs. priority-band reduction) and this module is only the
first.

A finding whose `resource_identity` is `identity.UNRESOLVED` is excluded
before grouping starts. Two such findings "matching" is coincidence, not
overlap - they may point at entirely different, unrelated resources that both
happened to fail identity resolution - so `<unresolved>` findings never enter
a `DedupeGroup` or a `CandidateOverlap`; they stand alone in the caller's
accounting like every other finding this module does not group.

**Candidate scope, read literally from spec section 7's own words.**
"Findings sharing identity and issue-class where either fingerprint is
unresolved" is the condition for Tier 2 - not "findings sharing identity and
class that failed to collapse." Two findings on one resource with two
different *resolved* fingerprints (the two-ingress-rules case Q8 #6 names)
carry no ambiguity at all: their fingerprints already prove they are
different violations, so there is nothing for a human to adjudicate and no
candidate group is produced for them. They simply stand alone. Only a group
containing at least one *unresolved* fingerprint is genuinely ambiguous - it
cannot be ruled out that the unresolved finding is the same violation as one
of its resolved-but-unmatched neighbours - and that ambiguity is what Tier 2
exists to surface.

**Candidates split into cross-scanner and same-scanner, because they are two
different research claims, not two shades of one number.** Measured on
corpus v0's fixtures: of 207 candidate groups, 116 involve more than one
scanner and 91 involve exactly one. Collapsing them into a single "candidate
overlap" figure would misreport the 91 - a real example from the corpus is
`checkov` alone reporting `CKV2_AWS_61` and `CKV2_AWS_62` on one S3 bucket,
two genuinely different checks with no scanner overlap involved at all. The
two counts mean different things and PLAN Q7 requires exactly this discipline
for alert-reduction numbers - reported separately, never combined:

- `DedupeResult.cross_scanner_candidates` - evidence for PLAN's
  scanner-selection note #19, the rule-family overlap discussion between
  tfsec and trivy (and, per the one measured Tier-1 example, checkov too).
- `DedupeResult.same_scanner_candidates` - not scanner overlap at all. It is
  a precision limit of the fingerprint itself: cases where our own
  extraction could not tell two findings on one resource and class apart,
  which belongs in the dissertation's limitations discussion rather than the
  cross-scanner one.

Both are derived properties over `candidates` (via `CandidateOverlap.
is_cross_scanner`, itself read off the already-deduplicated `scanners` tuple)
rather than stored fields or a recomputation from raw findings, so they
cannot drift from `candidates` and a caller never needs the original finding
list again to ask which bucket a candidate belongs to.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from iacrisk import identity
from iacrisk.finding import NormalizedFinding


@dataclass(frozen=True)
class DedupeGroup:
    """One Tier-1 exact collapse: same identity, same class, same resolved fingerprint.

    `key` is exactly `identity.dedupe_key`'s output, so a caller comparing two
    groups for the same underlying violation can compare `key` rather than
    reaching into `findings`. `scanners` is the sorted, de-duplicated set of
    scanner names among `findings` - sorted so it is deterministic rather than
    source-order-dependent, since a collapsed group's member order carries no
    meaning once the rows are treated as one violation.
    """

    key: tuple[str, str, str]
    findings: tuple[NormalizedFinding, ...]
    scanners: tuple[str, ...]


@dataclass(frozen=True)
class CandidateOverlap:
    """Unresolved-fingerprint overlap on one resource and class: surfaced, never merged.

    One `CandidateOverlap` per `(resource_identity, issue_class)` pair that
    has more than one finding left after Tier-1 collapsing, with at least one
    unresolved fingerprint among what's left - not one per fingerprint value,
    because an unresolved fingerprint cannot be split further; it is exactly
    the value that is missing. `findings` can therefore include a
    resolved-but-unmatched finding alongside the unresolved one(s): its
    relationship to the unresolved finding is exactly the ambiguity this tier
    exists to record.
    """

    resource_identity: str
    issue_class: str
    findings: tuple[NormalizedFinding, ...]
    scanners: tuple[str, ...]

    @property
    def is_cross_scanner(self) -> bool:
        """Whether more than one scanner contributed to this candidate group.

        Read off `scanners` - already the deduplicated set of scanner names
        among `findings` - rather than recomputed from `findings` itself, so
        this can never disagree with what `scanners` already states. This is
        the fact `DedupeResult.cross_scanner_candidates` and
        `.same_scanner_candidates` partition on: a cross-scanner group is
        evidence of rule-family overlap between scanners (PLAN #19); a
        same-scanner group is one scanner reporting two findings the
        fingerprint could not distinguish - a precision limit of the
        fingerprint, not overlap between scanners at all.
        """
        return len(self.scanners) > 1


@dataclass(frozen=True)
class DedupeResult:
    """Everything `deduplicate` produced, plus the one number the dissertation reports.

    `collapsed_count` is a finding count, not a group count - the reported
    reduction is "how many findings a reader no longer has to read twice," and
    a group of 3 findings removes 2 of them, not 3 and not 1 (task 8 brief).
    It is derived by summing `len(group.findings) - 1` over `groups` as they
    are built, so it cannot drift from what `groups` actually contains.
    """

    groups: tuple[DedupeGroup, ...]
    candidates: tuple[CandidateOverlap, ...]
    collapsed_count: int

    @property
    def cross_scanner_candidates(self) -> tuple[CandidateOverlap, ...]:
        """The subset of `candidates` more than one scanner contributed to.

        Evidence for PLAN's scanner-selection note #19 (rule-family overlap
        between scanners) - report this count, never `len(candidates)`
        undifferentiated, when that is the claim being made (module
        docstring's "candidates split" section).
        """
        return tuple(c for c in self.candidates if c.is_cross_scanner)

    @property
    def same_scanner_candidates(self) -> tuple[CandidateOverlap, ...]:
        """The subset of `candidates` exactly one scanner contributed to.

        Not scanner overlap - one scanner reported findings on one resource
        and class that the fingerprint could not tell apart. Belongs in the
        dissertation's limitations discussion (a precision limit of the
        fingerprint), never folded into the cross-scanner count (module
        docstring's "candidates split" section; PLAN Q7's discipline of
        reporting alert-reduction facts separately, never combined).
        """
        return tuple(c for c in self.candidates if not c.is_cross_scanner)


def deduplicate(findings: Iterable[NormalizedFinding]) -> DedupeResult:
    """Partition `findings` into Tier-1 exact collapses, Tier-2 candidates, and standalones.

    Grouping runs in two stages per `(resource_identity, issue_class)` pair,
    mirroring the two tiers spec section 7 names:

    1. Findings whose `has_resolved_fingerprint` is true are further split by
       fingerprint value. A fingerprint value shared by more than one finding
       is an exact Tier-1 collapse. A fingerprint value held by exactly one
       finding proves nothing about ambiguity by itself, so that finding
       falls through to step 2 alongside every unresolved-fingerprint
       finding.
    2. What is left for one `(resource_identity, issue_class)` pair becomes a
       Tier-2 `CandidateOverlap` only if at least one of those leftover
       findings has an unresolved fingerprint - the case where ambiguity
       genuinely exists - and more than one finding is left to be ambiguous
       about. Otherwise every leftover finding stands alone: each differs
       from its neighbours by a fingerprint value that DID resolve, so there
       is nothing left to ask a human to adjudicate.

    A finding whose `resource_identity` is `identity.UNRESOLVED` is excluded
    before either stage runs, so it can appear in neither a group nor a
    candidate - grouping two such findings together would only ever be
    coincidence, never evidence of overlap on a real resource.

    Reads `finding.has_resolved_fingerprint` rather than testing
    `finding.fingerprint is not None` directly, so this module's notion of
    "resolved" cannot drift from the record's own.
    """
    by_pair: dict[tuple[str, str], list[NormalizedFinding]] = defaultdict(list)
    for finding in findings:
        if finding.resource_identity == identity.UNRESOLVED:
            continue
        by_pair[(finding.resource_identity, finding.issue_class)].append(finding)

    groups: list[DedupeGroup] = []
    candidates: list[CandidateOverlap] = []
    collapsed_count = 0

    for (resource_identity, issue_class), members in by_pair.items():
        by_fingerprint: dict[str, list[NormalizedFinding]] = defaultdict(list)
        unresolved_members: list[NormalizedFinding] = []
        for finding in members:
            if finding.has_resolved_fingerprint:
                fingerprint = finding.fingerprint
                # `has_resolved_fingerprint` is exactly `fingerprint is not
                # None` (finding.py), so this narrows for mypy rather than
                # asserting anything this module decides for itself.
                assert fingerprint is not None
                by_fingerprint[fingerprint].append(finding)
            else:
                unresolved_members.append(finding)

        remaining: list[NormalizedFinding] = list(unresolved_members)
        for fingerprint, same_fingerprint in by_fingerprint.items():
            if len(same_fingerprint) > 1:
                key = identity.dedupe_key(resource_identity, issue_class, fingerprint)
                scanners = tuple(sorted({f.scanner for f in same_fingerprint}))
                groups.append(
                    DedupeGroup(key=key, findings=tuple(same_fingerprint), scanners=scanners)
                )
                collapsed_count += len(same_fingerprint) - 1
            else:
                remaining.extend(same_fingerprint)

        if len(remaining) > 1 and unresolved_members:
            scanners = tuple(sorted({f.scanner for f in remaining}))
            candidates.append(
                CandidateOverlap(
                    resource_identity=resource_identity,
                    issue_class=issue_class,
                    findings=tuple(remaining),
                    scanners=scanners,
                )
            )

    return DedupeResult(
        groups=tuple(groups), candidates=tuple(candidates), collapsed_count=collapsed_count
    )
