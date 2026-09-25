"""Tests for two-tier deduplication (design spec section 7, task 8 brief).

Synthetic cases below are hand-built because they need to isolate one rule at
a time - a real fixture finding always drags several other fields along with
it, which would make it unclear which field a failing assertion is actually
about. The headline numbers instead come from running the three real adapters
over the committed golden fixtures (`tests/harvest/fixtures/`), because a
deduplication figure built only from constructed examples would be an
assertion about the test author's imagination, not a measurement of the
corpus - and PLAN Q7's alert-reduction metric has to be the latter.

Every count asserted against real adapter output is derived from the fixtures
in the test itself (an independent tally, not a call into `dedupe.py`'s own
internals), never restated as a literal - a re-capture that changes the
corpus must fail these tests instead of leaving a stale number standing.

The five real adapter runs the headline numbers below are measured over come
from `tests/_corpus.py`, shared with `test_report.py` and `test_s3a_gates.py`
so the three modules cannot silently drift onto three different corpora
(whole-branch review Finding 4; `tests/test_corpus_wiring.py` pins the run
set that module produces).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from _corpus import all_real_findings as _all_real_findings
from iacrisk import identity
from iacrisk.dedupe import CandidateOverlap, DedupeGroup, DedupeResult, deduplicate
from iacrisk.finding import NormalizedFinding

# --- synthetic finding factory -------------------------------------------------------


def _finding(**overrides: Any) -> NormalizedFinding:
    """A minimally valid `NormalizedFinding`, with every field a test cares about overridable.

    Defaults describe an arbitrary but internally consistent terraform finding
    - `dedupe.py` never reads `scanner`, `rule_id`, `title` etc. for its own
    logic, so their default values are inert filler except where a test
    overrides them to make a point (e.g. `scanner` to prove provenance is
    retained).
    """
    defaults: dict[str, Any] = {
        "scanner": "checkov",
        "rule_id": "CKV_AWS_1",
        "canonical_rule_id": "CKV_AWS_1",
        "issue_class": "networking.open_ingress",
        "title": "an insecure thing",
        "remediation": None,
        "native_severity": None,
        "severity_level": "unknown",
        "platform": "terraform",
        "resource_identity": "aws_security_group.web",
        "identity_kind": "terraform",
        "file_path": "sg.tf",
        "line_range": None,
        "fingerprint": None,
        "context_eligible": True,
    }
    defaults.update(overrides)
    return NormalizedFinding(**defaults)


# --- Tier 1: exact collapse -----------------------------------------------------------


def test_two_findings_with_equal_resolved_fingerprint_collapse_into_one_group() -> None:
    """The base case spec section 7 names: same identity, same class, same resolved
    fingerprint - collapsed regardless of which two scanners reported it, with
    both scanners retained on the group as provenance.
    """
    a = _finding(scanner="checkov", fingerprint="ingress[0].cidr_blocks")
    b = _finding(scanner="tfsec", fingerprint="ingress[0].cidr_blocks")

    result = deduplicate([a, b])

    assert len(result.groups) == 1
    (group,) = result.groups
    assert group.key == identity.dedupe_key(
        "aws_security_group.web", "networking.open_ingress", "ingress[0].cidr_blocks"
    )
    assert set(group.findings) == {a, b}
    assert set(group.scanners) == {"checkov", "tfsec"}
    assert result.candidates == ()
    assert result.collapsed_count == 1


def test_two_findings_with_different_resolved_fingerprints_do_not_collapse() -> None:
    """PLAN Q8 #6's concrete case: two separate open-ingress rules on one security
    group. Both fingerprints are known and known to differ, so there is no
    ambiguity for Tier 2 to surface either - they simply stand alone, neither
    merged nor reported as a candidate (spec section 7's condition is "either
    fingerprint is unresolved", which is false for both of these).
    """
    rule_0 = _finding(fingerprint="ingress[0].cidr_blocks")
    rule_1 = _finding(fingerprint="ingress[1].cidr_blocks")

    result = deduplicate([rule_0, rule_1])

    assert result.groups == ()
    assert result.candidates == ()
    assert result.collapsed_count == 0


def test_an_unresolved_fingerprint_never_collapses_even_against_an_identical_match() -> None:
    """A finding with `fingerprint is None` must never collapse - not even when two
    OTHER findings sharing its identity and class do collapse with each other,
    which is the strongest version of "never" this module can demonstrate: the
    unresolved finding is left standing alone while its neighbours collapse
    around it, rather than being swept in because it happens to share identity
    and class with a group that did form.
    """
    resolved_a = _finding(scanner="checkov", fingerprint="storage_encrypted")
    resolved_b = _finding(scanner="tfsec", fingerprint="storage_encrypted")
    unresolved = _finding(scanner="trivy", fingerprint=None)

    result = deduplicate([resolved_a, resolved_b, unresolved])

    assert len(result.groups) == 1
    (group,) = result.groups
    assert set(group.findings) == {resolved_a, resolved_b}
    assert unresolved not in group.findings
    assert result.collapsed_count == 1
    # `unresolved` had nothing left to be ambiguous about once its two
    # neighbours collapsed into an exact group, so it stands alone rather than
    # becoming a (size-1) candidate.
    assert result.candidates == ()


def test_collapsed_count_counts_findings_removed_not_groups() -> None:
    """A group of 3 removes 2 findings from the reported total, not 3 and not 1
    (task 8 brief) - `collapsed_count` is a finding count, never a group count.
    """
    trio = [
        _finding(scanner="checkov", fingerprint="publicly_accessible"),
        _finding(scanner="tfsec", fingerprint="publicly_accessible"),
        _finding(scanner="trivy", fingerprint="publicly_accessible"),
    ]

    result = deduplicate(trio)

    assert len(result.groups) == 1
    assert len(result.groups[0].findings) == 3
    assert result.collapsed_count == 2


# --- Tier 2: candidate overlap ---------------------------------------------------------


def test_two_findings_sharing_identity_class_with_one_unresolved_fp_are_candidates() -> None:
    """The ambiguous case: one finding's fingerprint resolved, the other's did not,
    so it cannot be ruled out that they are the same violation. Surfaced as a
    candidate, never merged, and excluded from `collapsed_count`.
    """
    resolved = _finding(scanner="checkov", fingerprint="storage_encrypted")
    unresolved = _finding(scanner="trivy", fingerprint=None)

    result = deduplicate([resolved, unresolved])

    assert result.groups == ()
    assert result.collapsed_count == 0
    assert len(result.candidates) == 1
    (candidate,) = result.candidates
    assert candidate.resource_identity == "aws_security_group.web"
    assert candidate.issue_class == "networking.open_ingress"
    assert set(candidate.findings) == {resolved, unresolved}
    assert set(candidate.scanners) == {"checkov", "trivy"}


def test_two_findings_with_both_fingerprints_unresolved_are_candidates() -> None:
    """Neither side resolved, so there is nothing to compare - which is exactly
    the "either... is unresolved" condition spec section 7 states; it does not
    require exactly one side to be missing.
    """
    a = _finding(scanner="trivy", fingerprint=None)
    b = _finding(scanner="checkov", fingerprint=None)

    result = deduplicate([a, b])

    assert result.groups == ()
    assert len(result.candidates) == 1
    assert set(result.candidates[0].findings) == {a, b}


def test_a_lone_unresolved_fingerprint_finding_with_no_sibling_stands_alone() -> None:
    """One finding, alone at its `(identity, class)` pair, has nothing to be a
    candidate WITH - a candidate group of size 1 would misreport "overlap"
    where none exists.
    """
    lone = _finding(fingerprint=None)

    result = deduplicate([lone])

    assert result.groups == ()
    assert result.candidates == ()
    assert result.collapsed_count == 0


# --- candidate split: cross-scanner (rule-family overlap) vs same-scanner (a -----------
# --- precision limit of the fingerprint) - two different claims, never combined --------


def test_cross_scanner_and_same_scanner_candidates_are_correctly_classified_and_partition() -> None:
    """Fix round, coordinator-directed: `candidates` alone conflates two different
    research claims. A cross-scanner candidate (two different scanners on one
    resource and class) is evidence for PLAN #19's rule-family overlap
    discussion; a same-scanner candidate (one scanner, two genuinely different
    checks, neither fingerprinted) is a precision limit of the fingerprint
    itself and has nothing to do with scanner overlap - the real corpus v0
    example is `checkov` alone reporting `CKV2_AWS_61` and `CKV2_AWS_62` on
    one S3 bucket. This builds one of each, on two different resources so
    they cannot be confused with each other, and checks both the per-candidate
    flag and the `DedupeResult`-level split.
    """
    cross_a = _finding(scanner="checkov", resource_identity="aws_s3_bucket.logs", fingerprint=None)
    cross_b = _finding(scanner="trivy", resource_identity="aws_s3_bucket.logs", fingerprint=None)
    same_a = _finding(
        scanner="checkov",
        rule_id="CKV2_AWS_61",
        resource_identity="aws_s3_bucket.data",
        fingerprint=None,
    )
    same_b = _finding(
        scanner="checkov",
        rule_id="CKV2_AWS_62",
        resource_identity="aws_s3_bucket.data",
        fingerprint=None,
    )

    result = deduplicate([cross_a, cross_b, same_a, same_b])

    assert len(result.candidates) == 2
    cross_candidate = next(
        c for c in result.candidates if c.resource_identity == "aws_s3_bucket.logs"
    )
    same_candidate = next(
        c for c in result.candidates if c.resource_identity == "aws_s3_bucket.data"
    )

    assert cross_candidate.is_cross_scanner
    assert not same_candidate.is_cross_scanner

    assert result.cross_scanner_candidates == (cross_candidate,)
    assert result.same_scanner_candidates == (same_candidate,)


def test_cross_and_same_scanner_candidates_partition_the_total_exactly() -> None:
    """The coordinator's required invariant: `cross + same == len(candidates)`,
    derived from `DedupeResult` itself rather than restated as a literal count
    - and every candidate lands in exactly one of the two, never both and
    never neither.
    """
    cross = _finding(scanner="checkov", resource_identity="aws_s3_bucket.logs", fingerprint=None)
    cross_partner = _finding(
        scanner="trivy", resource_identity="aws_s3_bucket.logs", fingerprint=None
    )
    same_a = _finding(
        scanner="checkov",
        rule_id="CKV2_AWS_61",
        resource_identity="aws_s3_bucket.data",
        fingerprint=None,
    )
    same_b = _finding(
        scanner="checkov",
        rule_id="CKV2_AWS_62",
        resource_identity="aws_s3_bucket.data",
        fingerprint=None,
    )

    result = deduplicate([cross, cross_partner, same_a, same_b])

    assert len(result.cross_scanner_candidates) + len(result.same_scanner_candidates) == len(
        result.candidates
    )
    cross_ids = {id(c) for c in result.cross_scanner_candidates}
    same_ids = {id(c) for c in result.same_scanner_candidates}
    assert cross_ids.isdisjoint(same_ids)
    assert cross_ids | same_ids == {id(c) for c in result.candidates}


# --- unresolved identity: opts out of both tiers entirely -----------------------------


def test_an_unresolved_identity_never_collapses_and_never_joins_a_candidate_group() -> None:
    """`resource_identity == identity.UNRESOLVED` findings share no real resource -
    two of them "matching" is coincidence, not overlap, in either tier. Paired
    here with same class and fingerprint so the only thing preventing a match
    is the identity check, isolating exactly the rule under test.
    """
    a = _finding(resource_identity=identity.UNRESOLVED, identity_kind="unresolved", fingerprint="x")
    b = _finding(resource_identity=identity.UNRESOLVED, identity_kind="unresolved", fingerprint="x")
    c = _finding(
        resource_identity=identity.UNRESOLVED, identity_kind="unresolved", fingerprint=None
    )

    result = deduplicate([a, b, c])

    assert result.groups == ()
    assert result.candidates == ()
    assert result.collapsed_count == 0


# --- total accounting: nothing vanishes, nothing is counted twice ---------------------


def _partition_membership(
    findings: list[NormalizedFinding], result: DedupeResult
) -> dict[int, list[str]]:
    """Which of `result`'s structures each input finding (by `id()`) appears in.

    Tracked by `id()` rather than by dataclass equality: `NormalizedFinding` is
    a frozen dataclass with full value equality (its own docstring says so),
    so two synthetic findings built with identical field values would compare
    equal even though they are meant to represent two distinct rows - using
    `in`/`set()` membership here could silently miscount which physical
    finding landed where.
    """
    membership: dict[int, list[str]] = {id(f): [] for f in findings}
    for group in result.groups:
        for f in group.findings:
            membership[id(f)].append("group")
    for candidate in result.candidates:
        for f in candidate.findings:
            membership[id(f)].append("candidate")
    return membership


def test_every_input_finding_appears_in_exactly_one_group_or_candidate_or_stands_alone() -> None:
    """The accounting invariant task 8 states directly: every input finding ends
    up in exactly one `DedupeGroup`, exactly one `CandidateOverlap`, or neither
    (standing alone) - never zero-with-a-loss and never counted in two places.
    This exercises every rule at once: a Tier-1 pair, a Tier-2 pair, an
    unresolved-identity finding, and a lone standalone finding, all in one
    input list, which is exactly the shape that would expose a finding being
    silently dropped or double-counted by an implementation that, say, mutated
    a shared list across iterations of the `(identity, class)` loop.
    """
    tier1_a = _finding(
        scanner="checkov",
        resource_identity="aws_db_instance.default",
        fingerprint="storage_encrypted",
    )
    tier1_b = _finding(
        scanner="tfsec",
        resource_identity="aws_db_instance.default",
        fingerprint="storage_encrypted",
    )
    tier2_resolved = _finding(
        scanner="checkov", resource_identity="aws_s3_bucket.data", fingerprint="acl"
    )
    tier2_unresolved = _finding(
        scanner="trivy", resource_identity="aws_s3_bucket.data", fingerprint=None
    )
    unresolved_identity = _finding(
        resource_identity=identity.UNRESOLVED, identity_kind="unresolved", fingerprint=None
    )
    standalone = _finding(resource_identity="aws_iam_role.admin", fingerprint="assume_role_policy")

    findings = [
        tier1_a,
        tier1_b,
        tier2_resolved,
        tier2_unresolved,
        unresolved_identity,
        standalone,
    ]
    result = deduplicate(findings)

    membership = _partition_membership(findings, result)
    for f in findings:
        placements = membership[id(f)]
        assert len(placements) <= 1, f"finding counted more than once: {placements}"

    assert set(membership[id(tier1_a)]) == {"group"}
    assert set(membership[id(tier1_b)]) == {"group"}
    assert set(membership[id(tier2_resolved)]) == {"candidate"}
    assert set(membership[id(tier2_unresolved)]) == {"candidate"}
    assert membership[id(unresolved_identity)] == []
    assert membership[id(standalone)] == []

    # Every finding is accounted for by exactly one of: a group, a candidate,
    # or "neither" (standalone).
    grouped = sum(len(g.findings) for g in result.groups)
    candidated = sum(len(c.findings) for c in result.candidates)
    standalone_count = sum(1 for f in findings if not membership[id(f)])
    assert grouped + candidated + standalone_count == len(findings)


# --- real adapter output: the headline measurement --------------------------------
#
# `_all_real_findings` is `tests/_corpus.py::all_real_findings`, imported at
# the top of this module under its old local name so every call site below is
# unchanged (whole-branch review Finding 4).


def test_real_corpus_tier1_group_count_matches_an_independent_tally() -> None:
    """The Tier-1 group count and `collapsed_count`, cross-checked against a tally
    built directly from the finding list by this test - not by calling into
    `dedupe.py`'s own grouping code - so a bug in `deduplicate`'s subgrouping
    (an off-by-one, a wrong equality) cannot mark its own homework. Mirrors
    `test_checkov.py`'s `_raw_failed_checks` precedent: the oracle walks the
    same data independently rather than asking the adapter what it saw.
    """
    findings = _all_real_findings()
    result = deduplicate(findings)

    eligible = [
        f
        for f in findings
        if f.resource_identity != identity.UNRESOLVED and f.has_resolved_fingerprint
    ]
    tally = Counter((f.resource_identity, f.issue_class, f.fingerprint) for f in eligible)
    expected_group_count = sum(1 for count in tally.values() if count > 1)
    expected_collapsed_count = sum(count - 1 for count in tally.values() if count > 1)

    # Corpus v0 has at least one such key (design brief measured 35) - asserted
    # as non-zero so this test cannot vacuously pass if the fixtures ever
    # stopped exercising Tier 1 at all.
    assert expected_group_count > 0
    assert len(result.groups) == expected_group_count
    assert result.collapsed_count == expected_collapsed_count


def test_real_corpus_tier2_candidate_count_matches_an_independent_tally() -> None:
    """Self-review finding: the structural invariant tests and the total-accounting
    test above cannot, on their own, catch a finding that `deduplicate` silently
    fails to place in a `CandidateOverlap` it should belong to - a missing
    finding just reads as "standalone" from outside, which is a valid state,
    not a visible failure. This test closes that gap the same way the Tier-1
    test above does: an oracle built independently, from `Counter` and list
    comprehensions rather than by mirroring `dedupe.py`'s own defaultdict/loop
    structure, applying the identical rule stated in spec section 7 (remove
    exact-fingerprint duplicate sets first, since those are fully absorbed by
    Tier 1; a `(resource_identity, issue_class)` pair's remainder is a
    candidate only if more than one finding is left AND at least one of them
    has an unresolved fingerprint) to the same finding list.
    """
    findings = _all_real_findings()
    result = deduplicate(findings)

    by_pair: dict[tuple[str, str], list[NormalizedFinding]] = {}
    for f in findings:
        if f.resource_identity == identity.UNRESOLVED:
            continue
        by_pair.setdefault((f.resource_identity, f.issue_class), []).append(f)

    expected_candidate_groups = 0
    expected_candidated_findings = 0
    for members in by_pair.values():
        fingerprint_counts = Counter(f.fingerprint for f in members if f.has_resolved_fingerprint)
        remaining = [
            f
            for f in members
            if not f.has_resolved_fingerprint or fingerprint_counts[f.fingerprint] == 1
        ]
        if len(remaining) > 1 and any(not f.has_resolved_fingerprint for f in remaining):
            expected_candidate_groups += 1
            expected_candidated_findings += len(remaining)

    assert expected_candidate_groups > 0
    assert len(result.candidates) == expected_candidate_groups
    assert sum(len(c.findings) for c in result.candidates) == expected_candidated_findings


def test_real_corpus_cross_and_same_scanner_candidates_partition_exactly() -> None:
    """The coordinator's fix-round requirement, over the full real corpus rather
    than only the synthetic cases: `cross_scanner_candidates` and
    `same_scanner_candidates` partition `candidates` exactly - every real
    candidate lands in one and only one - and neither count is restated as a
    literal; both are read off `DedupeResult` itself.
    """
    result = deduplicate(_all_real_findings())
    assert result.candidates  # non-vacuous

    cross = result.cross_scanner_candidates
    same = result.same_scanner_candidates
    assert len(cross) + len(same) == len(result.candidates)
    cross_ids = {id(c) for c in cross}
    same_ids = {id(c) for c in same}
    assert cross_ids.isdisjoint(same_ids)
    assert cross_ids | same_ids == {id(c) for c in result.candidates}
    assert all(c.is_cross_scanner for c in cross)
    assert all(not c.is_cross_scanner for c in same)
    # Both categories are genuinely exercised in corpus v0 (measured: 116
    # cross-scanner, 91 same-scanner) - asserted as non-empty rather than
    # restating either literal, so this test cannot vacuously pass if a
    # future recapture stopped exercising one side.
    assert cross
    assert same


def test_real_corpus_cross_scanner_candidate_count_matches_an_independent_tally() -> None:
    """The split's cross-scanner count, cross-checked against an oracle built
    independently from the finding list - the same discipline the Tier-1 and
    Tier-2 independent tallies above apply, extended to the new split so a bug
    in `is_cross_scanner` or in how `cross_scanner_candidates` filters cannot
    mark its own homework.
    """
    findings = _all_real_findings()
    result = deduplicate(findings)

    by_pair: dict[tuple[str, str], list[NormalizedFinding]] = {}
    for f in findings:
        if f.resource_identity == identity.UNRESOLVED:
            continue
        by_pair.setdefault((f.resource_identity, f.issue_class), []).append(f)

    expected_cross = 0
    expected_same = 0
    for members in by_pair.values():
        fingerprint_counts = Counter(f.fingerprint for f in members if f.has_resolved_fingerprint)
        remaining = [
            f
            for f in members
            if not f.has_resolved_fingerprint or fingerprint_counts[f.fingerprint] == 1
        ]
        if len(remaining) > 1 and any(not f.has_resolved_fingerprint for f in remaining):
            if len({f.scanner for f in remaining}) > 1:
                expected_cross += 1
            else:
                expected_same += 1

    assert len(result.cross_scanner_candidates) == expected_cross
    assert len(result.same_scanner_candidates) == expected_same


def test_real_corpus_has_at_least_one_genuinely_cross_scanner_tier1_group() -> None:
    """Q8 #6 exists to guard the cross-scanner case specifically. If Tier 1 only
    ever collapsed duplicate rows from one scanner's own JSON, the
    cross-scanner collapse spec section 7 describes would be an untested claim
    against real data - the design brief measured exactly one such group in
    corpus v0 (`checkov` + `tfsec` on `aws_db_instance.default` /
    `storage-public-accessibility`), and this checks that the property holds
    without restating which resource or how many.
    """
    result = deduplicate(_all_real_findings())
    assert any(len(group.scanners) > 1 for group in result.groups)


def test_real_corpus_tier1_groups_never_mix_fingerprints_or_include_unresolved() -> None:
    """Acceptance gate 5 (spec section 10): Tier 1 never collapses two findings
    with different resolved fingerprints, and never collapses an
    unresolved-fingerprint finding with anything. Checked as an invariant over
    every group real adapter output actually produces, not only the synthetic
    cases above.
    """
    result = deduplicate(_all_real_findings())
    assert result.groups  # non-vacuous: corpus v0 does produce Tier-1 groups
    for group in result.groups:
        fingerprints = {f.fingerprint for f in group.findings}
        assert fingerprints == {group.key[2]}
        assert None not in fingerprints


def test_real_corpus_candidates_share_identity_class_and_include_an_unresolved_fp() -> None:
    """Structural invariants over every real `CandidateOverlap`: every member
    shares the group's `(resource_identity, issue_class)`, the group would not
    exist without at least one unresolved fingerprint among its members (the
    ambiguity condition spec section 7 states), and no candidate is a group of
    one - "overlap" implies more than one finding.
    """
    result = deduplicate(_all_real_findings())
    assert result.candidates  # non-vacuous: corpus v0 does produce Tier-2 candidates
    for candidate in result.candidates:
        assert len(candidate.findings) > 1
        assert all(f.resource_identity == candidate.resource_identity for f in candidate.findings)
        assert all(f.issue_class == candidate.issue_class for f in candidate.findings)
        assert any(not f.has_resolved_fingerprint for f in candidate.findings)
        assert set(candidate.scanners) == {f.scanner for f in candidate.findings}


def test_real_corpus_unresolved_identity_findings_are_excluded_from_both_tiers() -> None:
    """Corpus v0 measurably produces `<unresolved>`-identity findings (the four
    unparseable Helm templates, spec section 4); this confirms none of them
    reach a group or a candidate, over real data rather than only the
    synthetic case above.
    """
    findings = _all_real_findings()
    unresolved_identity_findings = [
        f for f in findings if f.resource_identity == identity.UNRESOLVED
    ]
    assert unresolved_identity_findings  # non-vacuous: corpus v0 exercises this branch

    result = deduplicate(findings)
    grouped_or_candidated_ids = {id(f) for group in result.groups for f in group.findings} | {
        id(f) for candidate in result.candidates for f in candidate.findings
    }
    for f in unresolved_identity_findings:
        assert id(f) not in grouped_or_candidated_ids


def test_real_corpus_total_accounting_holds() -> None:
    """The same accounting invariant as the synthetic test above, over the full
    real corpus: every finding lands in exactly one group, exactly one
    candidate, or neither.
    """
    findings = _all_real_findings()
    result = deduplicate(findings)

    membership = _partition_membership(findings, result)
    for f in findings:
        assert len(membership[id(f)]) <= 1

    grouped = sum(len(g.findings) for g in result.groups)
    candidated = sum(len(c.findings) for c in result.candidates)
    standalone_count = sum(1 for f in findings if not membership[id(f)])
    assert grouped + candidated + standalone_count == len(findings)


def test_module_level_conformance_guard_exists() -> None:
    """Not a runtime behaviour claim - `DedupeGroup`, `CandidateOverlap` and
    `DedupeResult` are importable and constructible with the field names task
    8's interface section names, matching the module-conformance style
    `checkov.py`/`trivy.py`/`tfsec.py` already use for their own protocol guard.
    """
    group = DedupeGroup(key=("a", "b", "c"), findings=(), scanners=())
    candidate = CandidateOverlap(resource_identity="a", issue_class="b", findings=(), scanners=())
    result = DedupeResult(groups=(group,), candidates=(candidate,), collapsed_count=0)
    assert result.groups == (group,)
    assert result.candidates == (candidate,)
