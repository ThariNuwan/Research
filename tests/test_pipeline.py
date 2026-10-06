"""`iacrisk.pipeline`: the Tier-1 collapse applied before scoring, and what it stands for.

The corpus-wide properties are measured over the real adapter output (`_corpus`), not over
hand-built findings: the S3b lesson is that a test building its own fixture cannot discover
that the real shape differs. The representative rule is the exception, tested on constructed
members, because corpus v0 holds exactly one group that exercises it.
"""

from __future__ import annotations

from dataclasses import replace

from _corpus import all_real_findings
from iacrisk.dedupe import deduplicate
from iacrisk.finding import NormalizedFinding
from iacrisk.pipeline import _representative, prioritize, tier1_survivors
from iacrisk.scoring.engine import severity_factor


def _member(scanner: str, rule_id: str, severity_level: int | str) -> NormalizedFinding:
    template = next(f for f in all_real_findings() if f.has_resolved_fingerprint)
    return replace(template, scanner=scanner, rule_id=rule_id, severity_level=severity_level)


def test_every_raw_finding_is_stood_for_by_exactly_one_survivor() -> None:
    """The accounting the collapse has to keep: nothing dropped, nothing counted twice."""
    findings = all_real_findings()
    dedupe = deduplicate(findings)
    survivors = tier1_survivors(findings, dedupe)

    stood_for = [id(member) for survivor in survivors for member in survivor.members]
    assert sorted(stood_for) == sorted(id(f) for f in findings)
    assert len(survivors) == len(findings) - dedupe.collapsed_count
    assert all(survivor.finding in survivor.members for survivor in survivors)


def test_only_tier1_groups_collapse_and_each_collapses_to_one() -> None:
    findings = all_real_findings()
    dedupe = deduplicate(findings)
    collapsed = [s for s in tier1_survivors(findings, dedupe) if len(s.members) > 1]

    assert dedupe.groups, "corpus v0 has Tier-1 groups; an empty set would make this vacuous"
    assert {s.members for s in collapsed} == {group.findings for group in dedupe.groups}
    assert len(collapsed) == len(dedupe.groups)


def test_tier2_candidates_are_never_merged() -> None:
    """Spec S3a section 7: candidates are surfaced, not collapsed, so every finding in one
    survives as its own row."""
    findings = all_real_findings()
    dedupe = deduplicate(findings)
    alone = {id(s.finding) for s in tier1_survivors(findings, dedupe) if len(s.members) == 1}

    candidates = [f for candidate in dedupe.candidates for f in candidate.findings]
    assert candidates
    assert all(id(f) in alone for f in candidates)


def test_the_representative_prefers_a_supplied_severity_then_the_highest_level() -> None:
    unknown = _member("checkov", "CKV_X", "unknown")
    low = _member("trivy", "AVD-1", 2)
    high = _member("tfsec", "AVD-2", 4)

    assert _representative((unknown, low, high)) is high
    assert _representative((unknown, low)) is low, "a supplied 2 outranks an absent severity"


def test_the_representative_is_deterministic_when_severity_cannot_separate_members() -> None:
    first = _member("checkov", "CKV_A", "unknown")
    second = _member("checkov", "CKV_B", "unknown")
    third = _member("trivy", "AVD-1", "unknown")

    assert _representative((third, second, first)) is first
    assert _representative((first, second, third)) is first


def test_the_representative_rule_changes_no_score_in_corpus_v0() -> None:
    """The module docstring's measured claim: whichever member of a real Tier-1 group were
    scored, the severity contribution would be the same. Derived, so a re-capture that makes
    the rule matter fails here instead of leaving the docstring quietly false.
    """
    groups = deduplicate(all_real_findings()).groups
    mixed = [g for g in groups if len({f.severity_level for f in g.findings}) > 1]

    assert len(mixed) == 1, "corpus v0 has exactly one group whose members differ in severity"
    for group in groups:
        assert len({severity_factor(f).scored_level for f in group.findings}) == 1


def test_collapsing_removes_exactly_the_tier1_count_from_the_ranked_population() -> None:
    findings = all_real_findings()
    collapsed = prioritize(findings, {}, {})
    uncollapsed = prioritize(findings, {}, {}, collapse=False)

    removed = deduplicate(findings).collapsed_count
    assert uncollapsed["population"] == {
        "findings_in": len(findings),
        "tier1_collapsed": 0,
        "ranked": len(findings),
    }
    assert collapsed["population"]["tier1_collapsed"] == removed
    assert collapsed["population"]["ranked"] == len(findings) - removed
    assert collapsed["report"]["total"] == len(collapsed["findings"]) == len(findings) - removed


def test_every_ranked_finding_names_every_raw_finding_it_stands_for() -> None:
    findings = all_real_findings()
    ranked = prioritize(findings, {}, {})["findings"]

    assert all(entry["flagged_by"] for entry in ranked)
    assert sum(len(entry["flagged_by"]) for entry in ranked) == len(findings)
    for entry in ranked:
        assert {"scanner": entry["scanner"], "rule_id": entry["rule_id"]} in entry["flagged_by"]
