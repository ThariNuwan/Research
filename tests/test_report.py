"""Tests for the retention-coverage report (design spec section 8, task 9 brief).

Synthetic cases isolate one arithmetic rule at a time, the same reasoning
`test_dedupe.py`'s module docstring gives for its own synthetic cases: a real
fixture finding drags several fields along with it, which would obscure which
field a failing assertion is actually about. The headline figures instead come
from running the three real adapters over the committed golden fixtures
(`tests/harvest/fixtures/`) and the real `deduplicate()` over their combined
output, so a re-capture that changes the corpus fails these tests instead of
leaving a stale number standing - counts are never restated as literals.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from iacrisk import identity
from iacrisk.dedupe import DedupeResult, deduplicate
from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.report import RetentionReport, ScannerCoverage, build_report
from iacrisk.resources import ResourceIndex, build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"

_EMPTY_DEDUPE = DedupeResult(groups=(), candidates=(), collapsed_count=0)


# --- synthetic finding factory -----------------------------------------------------


def _finding(**overrides: Any) -> NormalizedFinding:
    """A minimally valid `NormalizedFinding`, matching `test_dedupe.py`'s own factory
    shape - every field a test cares about is overridable, the rest is inert filler.
    """
    defaults: dict[str, Any] = {
        "scanner": "trivy",
        "rule_id": "KSV-0001",
        "canonical_rule_id": "KSV-0001",
        "issue_class": "workload.some_class",
        "title": "an insecure thing",
        "remediation": None,
        "native_severity": None,
        "severity_level": "unknown",
        "platform": "kubernetes",
        "resource_identity": "apps/v1/Deployment/default/web",
        "identity_kind": "kubernetes",
        "file_path": "web.yaml",
        "line_range": None,
        "fingerprint": None,
        "context_eligible": True,
    }
    defaults.update(overrides)
    return NormalizedFinding(**defaults)


# --- Step 1: rates are computed, not stored -----------------------------------------


def test_coverage_rates_are_computed_from_known_synthetic_counts() -> None:
    """Five findings, one drop, with every rate's numerator and denominator hand
    picked so the expected arithmetic can be stated directly rather than trusted.
    """
    resolved_fp_known_severity = _finding(
        identity_kind="kubernetes",
        fingerprint="containers[].securityContext.runAsNonRoot",
        severity_level=3,
        issue_class="workload.privileged",
        context_eligible=True,
    )
    unresolved_on_unparseable_file = _finding(
        identity_kind="unresolved",
        resource_identity=identity.UNRESOLVED,
        file_path="metadata-db/templates/a.yaml",
        issue_class="unmapped:trivy:KSV-9999",
        context_eligible=False,
    )
    unresolved_lineless = _finding(
        identity_kind="unresolved",
        resource_identity=identity.UNRESOLVED,
        file_path="parseable/b.yaml",
        context_eligible=False,
    )
    secret_kind = _finding(
        identity_kind="secret",
        resource_identity="a1b2c3",
        severity_level=2,
        context_eligible=False,
    )
    resolved_no_fp = _finding(identity_kind="kubernetes", context_eligible=True)

    findings = (
        resolved_fp_known_severity,
        unresolved_on_unparseable_file,
        unresolved_lineless,
        secret_kind,
        resolved_no_fp,
    )
    result = AdapterResult(findings=findings, dropped=(("KSV-0002", "no ID"),))
    unparseable = frozenset({"metadata-db/templates/a.yaml"})

    report = build_report({("trivy", "kubernetes"): result}, _EMPTY_DEDUPE, unparseable)
    coverage = report.scanners[("trivy", "kubernetes")]

    assert coverage.findings_in == 6
    assert coverage.findings_out == 5
    assert coverage.dropped == (("KSV-0002", "no ID"),)

    assert coverage.identity_unresolved == 2
    assert coverage.identity_resolved == 3
    assert coverage.unresolved_unparseable_file == 1
    assert coverage.unresolved_no_line_supplied == 1
    assert coverage.unresolved_line_unmatched == 0
    assert coverage.identity_resolution_rate == 3 / 5

    assert coverage.fingerprint_resolved == 1
    assert coverage.fingerprint_resolution_rate == 1 / 5

    assert coverage.unmapped == 1
    assert coverage.unmapped_rate == 1 / 5

    assert coverage.unknown_severity == 3  # both unresolved + resolved_no_fp default to "unknown"
    assert coverage.unknown_severity_rate == 3 / 5

    assert coverage.context_eligible == 2
    assert coverage.context_ineligible == 3
    assert dict(coverage.identity_kind_counts) == {"kubernetes": 2, "unresolved": 2, "secret": 1}


def test_zero_findings_reports_rates_as_none_not_zero() -> None:
    """A rate over no findings is undefined - `0.0` would read as "nothing
    unresolved", a false reassurance the zero-findings rule exists to prevent.
    """
    empty = AdapterResult(findings=(), dropped=())
    report = build_report({("checkov", "terraform"): empty}, _EMPTY_DEDUPE, frozenset())
    coverage = report.scanners[("checkov", "terraform")]

    assert coverage.findings_out == 0
    assert coverage.identity_resolution_rate is None
    assert coverage.fingerprint_resolution_rate is None
    assert coverage.unmapped_rate is None
    assert coverage.unknown_severity_rate is None

    json_coverage = coverage.to_json()
    assert json_coverage["identity_resolution_rate"] is None
    assert json_coverage["fingerprint_resolution_rate"] is None
    assert json_coverage["unmapped_rate"] is None
    assert json_coverage["unknown_severity_rate"] is None
    # None must survive to actual JSON `null`, not be coerced away by a caller
    # serializing the dict - proves the value really is `None`, not a falsy 0.0.
    assert "null" in json.dumps(json_coverage)


def test_zero_findings_with_a_drop_still_reports_in_correctly() -> None:
    """`in == out + dropped` must hold even at the empty-findings edge: a run
    that found nothing normalizable but did drop something is not "zero
    coverage", it is "one dropped record and nothing retained".
    """
    empty_but_dropped = AdapterResult(findings=(), dropped=(("X", "not an object"),))
    report = build_report({("tfsec", "terraform"): empty_but_dropped}, _EMPTY_DEDUPE, frozenset())
    coverage = report.scanners[("tfsec", "terraform")]

    assert coverage.findings_out == 0
    assert coverage.findings_in == 1
    assert coverage.identity_resolution_rate is None


def test_a_line_matching_no_span_is_the_line_unmatched_cause_not_no_line_supplied() -> None:
    """Fix round 2: `LINE_UNMATCHED` is a real, documented return path
    (`resources.py`'s `ResourceIndex.by_line` and `trivy.py`'s
    `_resolve_kubernetes` both return `<unresolved>` when a supplied line
    matches no indexed span), even though corpus v0 never exercises it. A
    version of `_unresolved_cause` that only checks `file_path in unparseable`
    and falls through everything else to `NO_LINE_SUPPLIED` would silently
    mislabel this finding - constructed directly since corpus v0 has no real
    example to drive it from.
    """
    unresolved_with_a_line = _finding(
        identity_kind="unresolved",
        resource_identity=identity.UNRESOLVED,
        file_path="parseable/c.yaml",
        line_range=(10, 12),
    )
    result = AdapterResult(findings=(unresolved_with_a_line,), dropped=())

    report = build_report({("trivy", "kubernetes"): result}, _EMPTY_DEDUPE, frozenset())
    coverage = report.scanners[("trivy", "kubernetes")]

    assert coverage.unresolved_line_unmatched == 1
    assert coverage.unresolved_no_line_supplied == 0
    assert coverage.unresolved_unparseable_file == 0


# --- R27: tuple-keyed mapping, checkov surviving both platforms --------------------


def test_checkov_survives_at_both_platform_keys_distinctly() -> None:
    """The defect a `str`-keyed mapping would produce: checkov is the one
    scanner that runs against both scan roots, and only a `(scanner, platform)`
    key can hold both runs without one silently overwriting the other.
    """
    terraform_result = AdapterResult(
        findings=(_finding(scanner="checkov", platform="terraform"),), dropped=()
    )
    kubernetes_result = AdapterResult(
        findings=(
            _finding(scanner="checkov", platform="kubernetes"),
            _finding(scanner="checkov", platform="kubernetes"),
        ),
        dropped=(),
    )

    report = build_report(
        {
            ("checkov", "terraform"): terraform_result,
            ("checkov", "kubernetes"): kubernetes_result,
        },
        _EMPTY_DEDUPE,
        frozenset(),
    )

    assert len(report.scanners) == 2
    assert report.scanners[("checkov", "terraform")].findings_out == 1
    assert report.scanners[("checkov", "kubernetes")].findings_out == 2

    serialized = report.to_json()["scanners"]
    assert isinstance(serialized, dict)
    assert set(serialized) == {"checkov/terraform", "checkov/kubernetes"}
    assert serialized["checkov/terraform"]["findings_out"] == 1
    assert serialized["checkov/kubernetes"]["findings_out"] == 2


# --- R28: Tier 2's three-number split, never summed with Tier 1 --------------------


def test_to_json_top_level_keys_are_exactly_the_expected_set_no_summed_key() -> None:
    """The definitive form of "no key sums Tier 1 and Tier 2": if any such key
    existed it would appear in this set and fail the equality, regardless of
    what value it happened to hold.
    """
    # An empty `scanners` mapping is sufficient here - this test only inspects
    # `to_json()`'s top-level keys, and no `ScannerCoverage` needs building for that.
    report = RetentionReport(
        scanners={},
        tier1_collapsed=39,
        tier2_candidates=207,
        tier2_cross_scanner=116,
        tier2_same_scanner=91,
    )
    serialized = report.to_json()
    assert set(serialized) == {
        "scanners",
        "tier1_collapsed",
        "tier2_candidates",
        "tier2_cross_scanner",
        "tier2_same_scanner",
    }


def test_tier2_cross_and_same_partition_tier2_candidates_exactly() -> None:
    """`DedupeResult`'s own invariant, carried through unchanged: cross + same
    == candidates. Built from a small real dedupe run rather than restated.
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
    dedupe_result = deduplicate([cross_a, cross_b, same_a, same_b])

    report = build_report({}, dedupe_result, frozenset())

    assert report.tier2_cross_scanner + report.tier2_same_scanner == report.tier2_candidates
    assert report.tier2_candidates == len(dedupe_result.candidates)
    assert report.tier1_collapsed == dedupe_result.collapsed_count


# --- real fixtures: the headline retention measurement ------------------------------


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _kubernetes_index() -> ResourceIndex:
    return build_index(discover(KUBERNETES_SCAN_ROOT))


def _real_results() -> dict[tuple[str, str], AdapterResult]:
    """Every `(scanner, platform)` adapter run over the golden fixtures, the same
    five runs `test_dedupe.py::_all_real_findings` combines into one pool - kept
    separate by key here, which is exactly what this report exists to do.
    """
    kubernetes_index = _kubernetes_index()
    return {
        ("checkov", "terraform"): CheckovAdapter().parse(
            _load_fixture("checkov-terraform.json"), TERRAFORM_SCAN_ROOT, None
        ),
        ("checkov", "kubernetes"): CheckovAdapter().parse(
            _load_fixture("checkov-kubernetes.json"), KUBERNETES_SCAN_ROOT, kubernetes_index
        ),
        ("trivy", "terraform"): TrivyAdapter().parse(
            _load_fixture("trivy-terraform.json"), TERRAFORM_SCAN_ROOT, None
        ),
        ("trivy", "kubernetes"): TrivyAdapter().parse(
            _load_fixture("trivy-kubernetes.json"), KUBERNETES_SCAN_ROOT, kubernetes_index
        ),
        ("tfsec", "terraform"): TfsecAdapter().parse(
            _load_fixture("tfsec-terraform.json"), TERRAFORM_SCAN_ROOT, None
        ),
    }


def _real_unparseable() -> frozenset[str]:
    """The scan-root-relative unparseable path set a real caller already has from
    `ResourceIndex.unparseable` (and `DiscoveryResult.unparseable` for the
    terraform root, empty in corpus v0 but unioned in for generality).
    """
    kubernetes_unparseable = _kubernetes_index().unparseable
    terraform_unparseable = discover(TERRAFORM_SCAN_ROOT).unparseable
    return frozenset(kubernetes_unparseable) | frozenset(terraform_unparseable)


def _real_dedupe() -> DedupeResult:
    findings: list[NormalizedFinding] = []
    for result in _real_results().values():
        findings.extend(result.findings)
    return deduplicate(findings)


def _real_report() -> RetentionReport:
    return build_report(_real_results(), _real_dedupe(), _real_unparseable())


def test_real_corpus_findings_in_is_internally_consistent_with_out_and_dropped() -> None:
    """Fix round 2: renamed from a name that claimed the retention property.
    `ScannerCoverage.findings_in` is *derived* as `findings_out + len(dropped)`
    (report.py's own docstring says so), so this assertion is `a == a` and
    cannot fail for any input - it checks that the derivation was not broken
    on the way to `to_json()`, nothing more. The actual retention claim - that
    `findings_out + len(dropped)` equals an independently counted raw total -
    is `test_real_corpus_findings_out_plus_dropped_equals_an_independent_raw_count`
    below, which does not import or call `_coverage_for` for its expectation.
    """
    report = _real_report()
    assert report.scanners  # non-vacuous
    for coverage in report.scanners.values():
        assert coverage.findings_in == coverage.findings_out + len(coverage.dropped)


def _raw_checkov_record_count(name: str) -> int:
    """Every `failed_checks` entry across every framework block of one fixture,
    read directly from the JSON rather than through `CheckovAdapter`. Checkov's
    own fixtures are a top-level list of per-framework result objects (`--
    framework` is deliberately withheld so multi-framework detection stays
    visible in the raw capture) - handled as a list, with a single-object
    fallback so this does not assume a shape it has not checked.
    """
    document = _load_fixture(name)
    frameworks = document if isinstance(document, list) else [document]
    return sum(len((fw.get("results") or {}).get("failed_checks") or []) for fw in frameworks)


def _raw_trivy_record_count(name: str) -> int:
    """Every `Misconfigurations` entry across every `Results` block, read
    directly from the JSON rather than through `TrivyAdapter`.
    """
    document = _load_fixture(name)
    return sum(len(block.get("Misconfigurations") or []) for block in document.get("Results") or [])


def _raw_tfsec_record_count(name: str) -> int:
    """tfsec's flat `results` array, read directly from the JSON rather than
    through `TfsecAdapter`.
    """
    document = _load_fixture(name)
    return len(document.get("results") or [])


def test_real_corpus_findings_out_plus_dropped_equals_an_independent_raw_count() -> None:
    """The retention claim this report exists to make checkable: `findings_out
    + len(dropped)` must equal a record count taken from a DIFFERENT path than
    the thing under test - the raw fixture JSON, walked by this test's own
    code, never by calling an adapter (which would just rebuild the tautology
    `test_real_corpus_findings_in_is_internally_consistent_with_out_and_dropped`
    above already names honestly). Each scanner's raw shape is read as it
    actually is, not assumed: checkov's fixtures are a list of per-framework
    objects, trivy nests under `Results[].Misconfigurations`, tfsec is a flat
    `results` array. Expected totals are computed from the fixtures here, not
    hardcoded, though they are known to match S0's independently harvested
    inventory (`artifacts/rule-inventory.json`): 221 + 268 + 115 + 332 + 119 =
    1055, with 0 dropped in corpus v0.
    """
    report = _real_report()
    expected = {
        ("checkov", "terraform"): _raw_checkov_record_count("checkov-terraform.json"),
        ("checkov", "kubernetes"): _raw_checkov_record_count("checkov-kubernetes.json"),
        ("trivy", "terraform"): _raw_trivy_record_count("trivy-terraform.json"),
        ("trivy", "kubernetes"): _raw_trivy_record_count("trivy-kubernetes.json"),
        ("tfsec", "terraform"): _raw_tfsec_record_count("tfsec-terraform.json"),
    }
    assert set(report.scanners) == set(expected)  # every run accounted for, none missing
    for key, expected_count in expected.items():
        assert expected_count > 0  # non-vacuous
        coverage = report.scanners[key]
        assert coverage.findings_out + len(coverage.dropped) == expected_count


def test_real_corpus_nothing_is_dropped() -> None:
    """Corpus v0's measured total: 1055 findings, 0 dropped, across all five runs -
    checked as a structural fact (every `dropped` tuple is empty) rather than by
    restating the literal 1055.
    """
    report = _real_report()
    for coverage in report.scanners.values():
        assert coverage.dropped == ()
        assert coverage.findings_in == coverage.findings_out


def test_real_corpus_only_trivy_kubernetes_has_unresolved_identities() -> None:
    """Every other run's Kubernetes/Terraform identity fully resolves in corpus
    v0; only trivy's Kubernetes run exercises the unresolved branch at all
    (measured fact, checked structurally rather than by count).
    """
    report = _real_report()
    for key, coverage in report.scanners.items():
        if key == ("trivy", "kubernetes"):
            assert coverage.identity_unresolved > 0
        else:
            assert coverage.identity_unresolved == 0


def test_real_corpus_unresolved_causes_sum_to_the_unresolved_total() -> None:
    """Single-assignment, not precedence: each unresolved finding is assigned to
    exactly one of the three cause buckets, so they sum to the total with no
    double count and no residual. This holds under ANY precedence ordering
    among the three (`_unresolved_cause` always returns exactly one string),
    so it cannot by itself prove which cause a specific finding lands in -
    that is what `test_real_corpus_unparseable_file_precedence_over_missing_line`
    below checks, as a separate and independent claim.
    """
    report = _real_report()
    coverage = report.scanners[("trivy", "kubernetes")]
    assert coverage.identity_unresolved > 0  # non-vacuous
    assert (
        coverage.unresolved_unparseable_file
        + coverage.unresolved_no_line_supplied
        + coverage.unresolved_line_unmatched
        == coverage.identity_unresolved
    )


def test_real_corpus_line_unmatched_cause_is_an_explicit_zero() -> None:
    """Fix round 2: `LINE_UNMATCHED` has zero population in corpus v0, and
    reporting that zero explicitly - rather than omitting the counter, the
    earlier version of this module's mistake - is the whole point (module
    docstring). Paired with `identity_unresolved > 0` so this cannot pass
    vacuously because there were no unresolved findings to classify at all.
    """
    report = _real_report()
    coverage = report.scanners[("trivy", "kubernetes")]
    assert coverage.identity_unresolved > 0  # non-vacuous
    assert coverage.unresolved_line_unmatched == 0


def test_real_corpus_unparseable_file_precedence_over_missing_line() -> None:
    """R30's overlap case, pinned by equality rather than by a loose inequality.

    Fix round 1: an earlier version of this test asserted
    `unresolved_unparseable_file >= len(overlap)` and relied on the sum test
    above as a second check. Both are too weak to catch inverted precedence -
    proven by mutation: swapping `_unresolved_cause` to check `line_range is
    None` before the unparseable-file set moves the one real overlapping
    finding (`metadata-db/templates/deployment.yaml`'s `KSV-0117`, both
    unparseable and lineless) into the no-line bucket, but `_unresolved_cause`
    still returns exactly one string per finding, so the sum stays 19 either
    way and `>=` is satisfied by both 16 and 15. Neither test noticed.

    The fix is an equality against a count computed independently of
    `_unresolved_cause` itself: every unresolved finding whose file is in the
    unparseable set - overlapping ones included - must be counted under
    `unresolved_unparseable_file`, full stop. That pins the precedence exactly
    rather than merely bounding it from below.
    """
    results = _real_results()
    unparseable = _real_unparseable()
    trivy_kubernetes_findings = results[("trivy", "kubernetes")].findings

    overlap = [
        f
        for f in trivy_kubernetes_findings
        if f.identity_kind == "unresolved" and f.file_path in unparseable and f.line_range is None
    ]
    assert overlap  # non-vacuous: R30 names exactly this case as present in corpus v0

    expected_unparseable = sum(
        1
        for f in trivy_kubernetes_findings
        if f.identity_kind == "unresolved" and f.file_path in unparseable
    )
    expected_no_line = sum(
        1
        for f in trivy_kubernetes_findings
        if f.identity_kind == "unresolved"
        and f.file_path not in unparseable
        and f.line_range is None
    )
    expected_line_unmatched = sum(
        1
        for f in trivy_kubernetes_findings
        if f.identity_kind == "unresolved"
        and f.file_path not in unparseable
        and f.line_range is not None
    )

    report = build_report(results, deduplicate(list(trivy_kubernetes_findings)), unparseable)
    coverage = report.scanners[("trivy", "kubernetes")]

    assert coverage.unresolved_unparseable_file == expected_unparseable
    assert coverage.unresolved_no_line_supplied == expected_no_line
    assert coverage.unresolved_line_unmatched == expected_line_unmatched


def test_real_corpus_identity_kind_counts_match_an_independent_tally() -> None:
    """`identity_kind_counts` (the context-eligibility breakdown, R29) checked
    per run against a `Counter` built directly from that run's findings - not
    by asking `_coverage_for` what it saw.
    """
    results = _real_results()
    report = build_report(results, _real_dedupe(), _real_unparseable())

    for key, result in results.items():
        expected = Counter(f.identity_kind for f in result.findings)
        assert dict(report.scanners[key].identity_kind_counts) == dict(expected)


def test_real_corpus_context_eligible_counts_match_an_independent_tally_and_partition() -> None:
    results = _real_results()
    report = build_report(results, _real_dedupe(), _real_unparseable())

    for key, result in results.items():
        coverage = report.scanners[key]
        expected_eligible = sum(1 for f in result.findings if f.context_eligible)
        assert coverage.context_eligible == expected_eligible
        assert coverage.context_eligible + coverage.context_ineligible == coverage.findings_out


def test_real_corpus_trivy_fingerprint_resolution_rate_is_zero_on_every_run() -> None:
    """Trivy's fingerprint is `None` by design on every finding (spec section
    6) - a real, expected zero the report has to carry through rather than
    mask, checked against real adapter output on both trivy runs.
    """
    report = _real_report()
    for key in (("trivy", "terraform"), ("trivy", "kubernetes")):
        coverage = report.scanners[key]
        assert coverage.findings_out > 0  # non-vacuous
        assert coverage.fingerprint_resolved == 0
        assert coverage.fingerprint_resolution_rate == 0.0


def test_real_corpus_unmapped_and_unknown_severity_counts_match_independent_tallies() -> None:
    results = _real_results()
    report = build_report(results, _real_dedupe(), _real_unparseable())

    for key, result in results.items():
        coverage = report.scanners[key]
        expected_unmapped = sum(1 for f in result.findings if f.is_unmapped)
        expected_unknown_severity = sum(1 for f in result.findings if f.severity_level == "unknown")
        assert coverage.unmapped == expected_unmapped
        assert coverage.unknown_severity == expected_unknown_severity


def test_real_corpus_tier1_and_tier2_figures_match_the_dedupe_result_directly() -> None:
    """The report carries `DedupeResult`'s own figures through unmodified - this
    checks it does not recompute or drift from them, using the real corpus's
    dedupe run rather than the synthetic one in the R28 test above.
    """
    dedupe_result = _real_dedupe()
    report = build_report(_real_results(), dedupe_result, _real_unparseable())

    assert report.tier1_collapsed == dedupe_result.collapsed_count
    assert report.tier2_candidates == len(dedupe_result.candidates)
    assert report.tier2_cross_scanner == len(dedupe_result.cross_scanner_candidates)
    assert report.tier2_same_scanner == len(dedupe_result.same_scanner_candidates)
    assert report.tier2_cross_scanner + report.tier2_same_scanner == report.tier2_candidates
    # Both are genuinely exercised in corpus v0 - non-vacuous rather than
    # restating the measured literals (39 / 207 / 116 / 91).
    assert report.tier1_collapsed > 0
    assert report.tier2_candidates > 0


def test_real_report_round_trips_through_json_serialization() -> None:
    """`to_json()` must produce something `json.dumps` actually accepts - the
    practical meaning of "JSON-safe primitives" for the full real report, not
    just the empty/synthetic cases above.
    """
    report = _real_report()
    serialized = report.to_json()
    text = json.dumps(serialized)
    round_tripped = json.loads(text)
    assert set(round_tripped["scanners"]) == {
        "checkov/terraform",
        "checkov/kubernetes",
        "trivy/terraform",
        "trivy/kubernetes",
        "tfsec/terraform",
    }


def test_module_level_conformance_guard_exists() -> None:
    """Not a runtime behaviour claim - `ScannerCoverage` and `RetentionReport`
    are importable and constructible with the field names this module's own
    interface names, matching `test_dedupe.py`'s own conformance-guard style.
    """
    coverage = ScannerCoverage(
        scanner="checkov",
        platform="terraform",
        findings_in=1,
        findings_out=1,
        dropped=(),
        identity_resolved=1,
        identity_unresolved=0,
        unresolved_unparseable_file=0,
        unresolved_no_line_supplied=0,
        unresolved_line_unmatched=0,
        fingerprint_resolved=0,
        unmapped=0,
        unknown_severity=0,
        identity_kind_counts={"terraform": 1},
        context_eligible=1,
        context_ineligible=0,
    )
    report = RetentionReport(
        scanners={("checkov", "terraform"): coverage},
        tier1_collapsed=0,
        tier2_candidates=0,
        tier2_cross_scanner=0,
        tier2_same_scanner=0,
    )
    assert report.scanners[("checkov", "terraform")] is coverage
