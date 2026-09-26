"""The six S2 acceptance gates (design spec section 6; task 7 brief), as tests
rather than as a claim in a report.

Corpus v1 (`eval/ground_truth/corpus-v1.json`) is already-authored data, so
none of these six gates can start red against it - a green assertion alone
proves the data passes its gate, never that the gate could have failed.
Every gate below is therefore paired with at least one "can fail" test that
runs the same check against a locally mutated copy (or, for gate 5's two
halves, a small synthetic document) and expects it to raise. No mutation
touches the committed file; `_mutated` deep-copies before editing.

Each gate covers something `eval/ground_truth.py::_check_semantics` does
not. That validator already enforces unique ids, that pair sides and
scenario tiers resolve to real cases, `case_high != case_low`, and
`oracle.author != oracle.reviewer` - none of that is re-implemented here.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from _corpus import all_real_findings
from eval.ground_truth import GroundTruthError, load_and_validate, validate
from iacrisk.finding import NormalizedFinding
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"
AUTHORED_FIXTURES = REPO_ROOT / "tests" / "harvest" / "fixtures" / "authored"
AUTHORED_SCAN_ROOT = REPO_ROOT / "corpus" / "authored"

PAIRABLE_FACTORS = ("exposure", "privilege", "sensitivity", "criticality", "encryption")
DOMAINS = ("storage", "networking", "iam", "compute", "containers")


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    return load_and_validate(CORPUS_PATH)


def _mutated(document: dict[str, Any]) -> dict[str, Any]:
    """A deep copy safe to mutate without touching the cached original."""
    copy: dict[str, Any] = json.loads(json.dumps(document))
    return copy


# ---------------------------------------------------------------------------
# Gate 1: the committed document loads through load_and_validate without
# error.
# ---------------------------------------------------------------------------


def test_gate_1_corpus_v1_loads_and_validates() -> None:
    """Gate 1: "eval/ground_truth/corpus-v1.json loads through the committed
    load_and_validate without error."
    """
    document = _document()
    assert document["cases"]
    assert document["contrastive_pairs"]
    assert document["scenarios"]


def test_gate_1_can_fail_on_a_malformed_case() -> None:
    """Proof gate 1 is not vacuously green: deleting one case's `expected`
    block - the exact defect `load_and_validate` exists to hard-reject rather
    than skip - makes validation fail against corpus v1's own data, not just
    the schema exemplar `tests/test_s1_gates.py::test_gate_4_...` already
    covers.
    """
    broken = _mutated(_document())
    del broken["cases"][0]["expected"]
    with pytest.raises(GroundTruthError):
        validate(broken)


# ---------------------------------------------------------------------------
# Gate 2: each of the five pairable factors is factor_under_test of >=2
# pairs; severity is factor_under_test of exactly 0.
# ---------------------------------------------------------------------------


def _check_gate_2(document: dict[str, Any]) -> None:
    counts: dict[str, int] = defaultdict(int)
    for pair in document["contrastive_pairs"]:
        counts[pair["factor_under_test"]] += 1
    for factor in PAIRABLE_FACTORS:
        assert counts[factor] >= 2, (
            f"{factor} is factor_under_test of only {counts[factor]} pair(s), need >=2"
        )
    assert counts["severity"] == 0, (
        f"severity is factor_under_test of {counts['severity']} pair(s); it is not "
        "pair-testable by any construction (design spec section 1) and must stay at "
        "exactly 0, asserted rather than merely absent"
    )


def test_gate_2_five_pairable_factors_covered_twice_and_severity_covered_zero() -> None:
    """Gate 2: each of the five pairable factor_key values - exposure,
    privilege, sensitivity, criticality, encryption - is the
    factor_under_test of at least 2 pairs, and severity is the
    factor_under_test of exactly 0 pairs.
    """
    _check_gate_2(_document())


def test_gate_2_can_fail_when_severity_gains_a_pair() -> None:
    """Proof: relabeling one exposure pair's factor_under_test as severity
    breaks both halves of the gate in one move - exposure drops below 2 and
    severity rises above 0 - which is exactly the "a later reader fixes the
    gap with a pair that isolates nothing" failure the gate exists to catch
    (design spec section 1).
    """
    broken = _mutated(_document())
    broken["contrastive_pairs"][0]["factor_under_test"] = "severity"
    with pytest.raises(AssertionError):
        _check_gate_2(broken)


# ---------------------------------------------------------------------------
# Gate 3: every domain has >=1 scenario; every scenario orders >=3 cases
# across >=2 tiers.
# ---------------------------------------------------------------------------


def _check_gate_3(document: dict[str, Any]) -> None:
    covered = {scenario["domain"] for scenario in document["scenarios"]}
    missing = set(DOMAINS) - covered
    assert not missing, f"domains with no scenario: {sorted(missing)}"
    for scenario in document["scenarios"]:
        tiers = scenario["expected_ordering"]
        total_cases = sum(len(tier) for tier in tiers)
        assert len(tiers) >= 2, f"{scenario['scenario_id']} orders only {len(tiers)} tier(s)"
        assert total_cases >= 3, f"{scenario['scenario_id']} orders only {total_cases} case(s)"


def test_gate_3_every_domain_has_a_scenario_of_at_least_three_cases_over_two_tiers() -> None:
    """Gate 3: every one of the five domain values has at least 1 scenario,
    and every scenario orders at least 3 cases across at least 2 tiers.
    """
    _check_gate_3(_document())


def test_gate_3_can_fail_on_a_single_tier_scenario() -> None:
    """Proof: collapsing one scenario to a single tier fails the >=2-tiers
    half directly - 2 cases in 1 tier is a tie, not an ordering (design spec
    section 6).
    """
    broken = _mutated(_document())
    broken["scenarios"][0]["expected_ordering"] = [["only-one-tier"]]
    with pytest.raises(AssertionError):
        _check_gate_3(broken)


def test_gate_3_can_fail_when_a_domain_loses_its_only_scenario() -> None:
    """Proof of the other half: deleting every scenario for one domain must
    fail even though the remaining four still satisfy the tier/case shape.
    """
    broken = _mutated(_document())
    domain_to_drop = broken["scenarios"][0]["domain"]
    broken["scenarios"] = [s for s in broken["scenarios"] if s["domain"] != domain_to_drop]
    with pytest.raises(AssertionError):
        _check_gate_3(broken)


# ---------------------------------------------------------------------------
# Gate 4: no orphan cases - every case_id is referenced by >=1 pair or
# scenario.
# ---------------------------------------------------------------------------


def _check_gate_4(document: dict[str, Any]) -> None:
    all_case_ids = {case["case_id"] for case in document["cases"]}
    referenced: set[str] = set()
    for pair in document["contrastive_pairs"]:
        referenced.add(pair["case_high"])
        referenced.add(pair["case_low"])
    for scenario in document["scenarios"]:
        for tier in scenario["expected_ordering"]:
            referenced.update(tier)
    orphans = all_case_ids - referenced
    assert not orphans, f"cases referenced by no pair and no scenario: {sorted(orphans)}"


def test_gate_4_no_orphan_cases() -> None:
    """Gate 4: every case_id is referenced by at least one contrastive pair
    or scenario. The S1 validator checks that a pair's or scenario's
    references resolve to a real case; it does not check the converse, which
    is what this gate adds.
    """
    _check_gate_4(_document())


def test_gate_4_can_fail_on_an_added_orphan() -> None:
    """Proof: appending a case that no pair and no scenario mentions - the
    shape an author leaves behind while iterating and forgets to wire up -
    must fail.
    """
    broken = _mutated(_document())
    orphan = json.loads(json.dumps(broken["cases"][0]))
    orphan["case_id"] = "gate-4-mutation-orphan-case"
    broken["cases"].append(orphan)
    with pytest.raises(AssertionError):
        _check_gate_4(broken)


# ---------------------------------------------------------------------------
# Gate 5: cross-pair consistency - the recorded class difference for every
# pair still matches real adapter output, the class-difference-to-factor
# relation is a function, and source shapes are honest.
# ---------------------------------------------------------------------------


def _case_by_id(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {case["case_id"]: case for case in document["cases"]}


def _resource_identity(case: dict[str, Any]) -> str:
    (identity,) = case["declared_context"].keys()
    resolved: str = identity
    return resolved


def _recorded_classes(case: dict[str, Any], identity: str) -> frozenset[str]:
    return frozenset(
        finding["issue_class"]
        for finding in case["expected"]["findings"]
        if finding["resource_identity"] == identity
    )


def _authored_findings() -> list[NormalizedFinding]:
    """The three authored-root adapter runs, over
    `tests/harvest/fixtures/authored/` - the one bounded relaxation of the
    don't-run-the-scanners rule the design spec section 4 describes. Never
    touches corpus v0's fixtures under `tests/harvest/fixtures/`.
    """

    def _load(name: str) -> Any:
        return json.loads((AUTHORED_FIXTURES / name).read_text(encoding="utf-8"))

    results = (
        CheckovAdapter().parse(_load("checkov-terraform.json"), AUTHORED_SCAN_ROOT, None),
        TfsecAdapter().parse(_load("tfsec-terraform.json"), AUTHORED_SCAN_ROOT, None),
        TrivyAdapter().parse(_load("trivy-terraform.json"), AUTHORED_SCAN_ROOT, None),
    )
    findings: list[NormalizedFinding] = []
    for result in results:
        findings.extend(result.findings)
    return findings


def _issue_classes_by_identity() -> dict[str, frozenset[str]]:
    """Every case referenced by a pair in corpus v1 is Terraform, drawn
    either from corpus v0's vendored root (`_corpus.all_real_findings`) or
    the authored root above, so pooling both real adapter runs is enough to
    re-derive every pair's two identities' issue-class sets. No
    class-to-factor mapping is invented anywhere in this module - design
    spec section 1 states that mapping does not exist, and this gate does
    not create one; it only re-derives class *sets*, never a factor.
    """
    grouped: dict[str, set[str]] = defaultdict(set)
    for finding in (*all_real_findings(), *_authored_findings()):
        grouped[finding.resource_identity].add(finding.issue_class)
    return {identity: frozenset(classes) for identity, classes in grouped.items()}


def _check_gate_5(document: dict[str, Any], classes_by_identity: dict[str, frozenset[str]]) -> None:
    cases = _case_by_id(document)
    diff_to_factor: dict[frozenset[str], str] = {}

    for pair in document["contrastive_pairs"]:
        case_high = cases[pair["case_high"]]
        case_low = cases[pair["case_low"]]
        identity_high = _resource_identity(case_high)
        identity_low = _resource_identity(case_low)

        recorded_high = _recorded_classes(case_high, identity_high)
        recorded_low = _recorded_classes(case_low, identity_low)
        recorded_diff = (recorded_high - recorded_low, recorded_low - recorded_high)

        actual_high = classes_by_identity.get(identity_high, frozenset())
        actual_low = classes_by_identity.get(identity_low, frozenset())
        actual_diff = (actual_high - actual_low, actual_low - actual_high)

        assert actual_diff == recorded_diff, (
            f"pair {pair['pair_id']!r}: recorded class difference {recorded_diff} no "
            "longer matches what real adapter output over the committed fixtures "
            f"produces, {actual_diff}"
        )

        full_diff = frozenset(actual_diff[0] | actual_diff[1])
        if not full_diff:
            # A declared-context-only pair (sensitivity/criticality) cites no class
            # evidence at all - design spec section 1 states these explicitly as
            # "not a class-difference argument" - so there is nothing here for the
            # class-difference-to-factor relation to be a function over.
            continue
        factor = pair["factor_under_test"]
        seen_factor = diff_to_factor.setdefault(full_diff, factor)
        assert seen_factor == factor, (
            f"class difference {sorted(full_diff)} is cited as evidence for both "
            f"{seen_factor!r} and {factor!r} (pair {pair['pair_id']!r}) - the "
            "class-difference-to-factor relation is not a function"
        )

    for case in document["cases"]:
        source = case["source"]
        if source == "hand-crafted":
            continue
        assert isinstance(source, dict) and {"repo", "commit", "path"} <= source.keys(), (
            f"case {case['case_id']!r} source is neither 'hand-crafted' nor a "
            f"repo/commit/path triple: {source!r}"
        )


def test_gate_5_cross_pair_consistency_and_source_shape() -> None:
    """Gate 5: for every pair, the recorded class difference between its two
    cases is re-derived from real adapter output over the committed
    fixtures (corpus v0's five and the authored root's three) and still
    holds; the relation the pairs induce from class-difference to
    factor_under_test is a function - no single non-empty class difference
    is cited as evidence for two different factors; and every hand-crafted
    case carries source: "hand-crafted" while every vendored one carries a
    {repo, commit, path} triple.
    """
    _check_gate_5(_document(), _issue_classes_by_identity())


def test_gate_5_can_fail_when_two_factors_share_one_class_difference() -> None:
    """Proof of the function-relation half, isolated from the real corpus so
    the mutation exercises exactly one property: two synthetic pairs share
    the identical {storage-public-accessibility} class difference but claim
    different factors. The supplied classes_by_identity matches the
    document's own recorded findings exactly, so the recorded-vs-actual
    check passes and only the function check can be what trips.
    """
    document: dict[str, Any] = {
        "cases": [
            {
                "case_id": "c1",
                "source": "hand-crafted",
                "declared_context": {"r1": {"sensitivity": 3, "criticality": 3}},
                "expected": {
                    "findings": [
                        {"resource_identity": "r1", "issue_class": "storage-public-accessibility"}
                    ]
                },
            },
            {
                "case_id": "c2",
                "source": "hand-crafted",
                "declared_context": {"r2": {"sensitivity": 3, "criticality": 3}},
                "expected": {"findings": []},
            },
            {
                "case_id": "c3",
                "source": "hand-crafted",
                "declared_context": {"r3": {"sensitivity": 3, "criticality": 3}},
                "expected": {
                    "findings": [
                        {"resource_identity": "r3", "issue_class": "storage-public-accessibility"}
                    ]
                },
            },
            {
                "case_id": "c4",
                "source": "hand-crafted",
                "declared_context": {"r4": {"sensitivity": 3, "criticality": 3}},
                "expected": {"findings": []},
            },
        ],
        "contrastive_pairs": [
            {"pair_id": "p1", "factor_under_test": "exposure", "case_high": "c1", "case_low": "c2"},
            {
                "pair_id": "p2",
                "factor_under_test": "encryption",
                "case_high": "c3",
                "case_low": "c4",
            },
        ],
    }
    classes_by_identity: dict[str, frozenset[str]] = {
        "r1": frozenset({"storage-public-accessibility"}),
        "r2": frozenset(),
        "r3": frozenset({"storage-public-accessibility"}),
        "r4": frozenset(),
    }
    with pytest.raises(AssertionError):
        _check_gate_5(document, classes_by_identity)


def test_gate_5_can_fail_when_actual_adapter_output_disagrees_with_recorded() -> None:
    """Proof of the re-derivation half, isolated from the real corpus: the
    document records a class difference that the supplied
    classes_by_identity - standing in for "what the adapters produce now" -
    no longer reproduces.
    """
    document: dict[str, Any] = {
        "cases": [
            {
                "case_id": "c1",
                "source": "hand-crafted",
                "declared_context": {"r1": {"sensitivity": 3, "criticality": 3}},
                "expected": {
                    "findings": [
                        {"resource_identity": "r1", "issue_class": "storage-public-accessibility"}
                    ]
                },
            },
            {
                "case_id": "c2",
                "source": "hand-crafted",
                "declared_context": {"r2": {"sensitivity": 3, "criticality": 3}},
                "expected": {"findings": []},
            },
        ],
        "contrastive_pairs": [
            {"pair_id": "p1", "factor_under_test": "exposure", "case_high": "c1", "case_low": "c2"}
        ],
    }
    # r1 draws no findings under this stand-in for real adapter output, so the
    # recorded difference no longer holds.
    classes_by_identity: dict[str, frozenset[str]] = {"r1": frozenset(), "r2": frozenset()}
    with pytest.raises(AssertionError):
        _check_gate_5(document, classes_by_identity)


def test_gate_5_can_fail_on_a_dishonest_source_shape() -> None:
    """Proof of the source-shape half: a vendored case missing its commit
    must fail even when every pair in the document is otherwise consistent.
    """
    broken = _mutated(_document())
    for case in broken["cases"]:
        if isinstance(case["source"], dict):
            del case["source"]["commit"]
            break
    with pytest.raises(AssertionError):
        _check_gate_5(broken, _issue_classes_by_identity())


# ---------------------------------------------------------------------------
# Gate 6: defaulted_factors and unresolved_factors each non-empty on >=1
# expected finding; every scenario oracle is complete.
# ---------------------------------------------------------------------------


def _check_gate_6(document: dict[str, Any], *, now: datetime) -> None:
    defaulted_present = any(
        finding.get("defaulted_factors")
        for case in document["cases"]
        for finding in case["expected"]["findings"]
    )
    unresolved_present = any(
        finding.get("unresolved_factors")
        for case in document["cases"]
        for finding in case["expected"]["findings"]
    )
    assert defaulted_present, "no expected finding carries a non-empty defaulted_factors (PLAN Q4)"
    assert unresolved_present, (
        "no expected finding carries a non-empty unresolved_factors (PLAN Q9)"
    )

    verdicts = {"agree", "disagree", "partial"}
    for scenario in document["scenarios"]:
        oracle = scenario["oracle"]
        assert oracle["reviewer_verdict"] in verdicts, (
            f"{scenario['scenario_id']}'s reviewer_verdict {oracle['reviewer_verdict']!r} "
            f"is not one of {sorted(verdicts)}"
        )
        assert oracle["reviewer"] != oracle["author"], (
            f"{scenario['scenario_id']}'s oracle reviewer and author are the same"
        )
        registered = datetime.fromisoformat(oracle["registered_at"])
        if registered.tzinfo is not None:
            registered = registered.astimezone().replace(tzinfo=None)
        assert registered < now, (
            f"{scenario['scenario_id']}'s registered_at {oracle['registered_at']!r} does "
            "not parse as a date before now"
        )


def test_gate_6_defaulted_and_unresolved_present_and_every_oracle_is_complete() -> None:
    """Gate 6: both defaulted_factors and unresolved_factors are non-empty on
    at least one expected finding each - checked separately because PLAN
    Q4's missing-declared-value rate and PLAN Q9's extractor-failure rate
    must stay reportable apart (design spec section 0.1); merging the two
    fields into one check would make that report impossible after the
    fact. Every scenario oracle is also complete: reviewer_verdict is in the
    enum, reviewer is distinct from author, and registered_at parses as a
    date before now.

    This gate does NOT assert that registered_at predates a scoring
    artifact: no such module exists anywhere in this repository, so that
    comparison would pass without checking anything - the defect the task
    dispatch names as already having shipped three times on the previous
    branch. The claim that this ground truth was authored before any score
    existed rests on git history instead: the commit that adds
    corpus-v1.json is checkable directly against the commit log, and that is
    stronger evidence than a self-reported timestamp, because it is not
    written by the party making the claim. A test in this file cannot read
    that history at collection time in any way that would not itself be
    circular, so it is cited from the log rather than asserted here.
    """
    _check_gate_6(_document(), now=datetime.now())


def test_gate_6_can_fail_on_a_future_registered_at() -> None:
    """Proof: setting one oracle's registered_at a century out must fail."""
    broken = _mutated(_document())
    broken["scenarios"][0]["oracle"]["registered_at"] = "2199-01-01"
    with pytest.raises(AssertionError):
        _check_gate_6(broken, now=datetime.now())


def test_gate_6_can_fail_when_defaulted_factors_is_stripped_everywhere() -> None:
    """Proof of the other half: removing every defaulted_factors occurrence
    must fail even though unresolved_factors survives untouched - a gate
    that only checked "either field is non-empty somewhere" could not tell
    a missing-declared-value case apart from an extractor-failure case,
    which is exactly the distinction PLAN Q4 and Q9 require staying separate.
    """
    broken = _mutated(_document())
    for case in broken["cases"]:
        for finding in case["expected"]["findings"]:
            finding.pop("defaulted_factors", None)
    with pytest.raises(AssertionError):
        _check_gate_6(broken, now=datetime.now())


def test_gate_6_can_fail_on_a_reviewer_equal_to_the_author() -> None:
    """Proof of the oracle-completeness half most likely to be re-broken by
    a future edit: setting one scenario's reviewer to its own author must
    fail. `_check_gate_6` is called directly here rather than through
    `validate`, which already enforces this same property at load time
    (`_check_semantics`) - so this test shows `_check_gate_6` does not
    silently rely on that validator having run first.
    """
    broken = _mutated(_document())
    broken["scenarios"][0]["oracle"]["reviewer"] = broken["scenarios"][0]["oracle"]["author"]
    with pytest.raises(AssertionError):
        _check_gate_6(broken, now=datetime.now())
