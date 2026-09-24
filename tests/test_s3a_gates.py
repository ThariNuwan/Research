"""The six S3a acceptance gates (design spec section 10), as tests rather than
as a claim in a report.

Each gate's docstring quotes spec section 10 verbatim, mirroring
`tests/test_s1_gates.py`'s own precedent. Every expectation is driven from the
committed golden fixtures (`tests/harvest/fixtures/`) rather than restated as a
literal pulled from prose: a test that hardcodes the number it is supposed to
be measuring cannot detect that number changing on a re-capture. Where an
independent oracle is needed, it walks the raw fixture JSON directly - never
through `CheckovAdapter`/`TrivyAdapter`/`TfsecAdapter`/`build_report` for the
*expectation* - so a bug shared between the code under test and its own
oracle cannot mark its own homework (this branch shipped exactly that
tautology once and had to fix it, per the task 11 dispatch).

**Gate 4 is corrected here from the plan's wording.** The plan states
"Kubernetes identity resolves for every finding in a parseable manifest" -
false as measured: 3 `KSV-0117` findings on parseable Kubernetes files carry
no `StartLine` at all, so there is nothing for `ResourceIndex.by_line` to look
up, and they correctly take `<unresolved>` too. The gate below asserts the
narrower, true claim - identity resolves for every finding in a parseable
manifest that also carries a line number - and separately asserts the two
causes that are legitimately `<unresolved>` (the four unparseable Helm
templates, and the three lineless findings) sum to the observed total with no
double count, since one finding (`metadata-db/templates/deployment.yaml`'s
`KSV-0117`) is both unparseable and lineless and precedence assigns it to
exactly one cause.

Never invokes a real scanner. Every fixture is read as committed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from iacrisk import identity
from iacrisk.dedupe import DedupeResult, deduplicate
from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.report import build_report
from iacrisk.resources import ResourceIndex, build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


# --- fixture loading and raw, adapter-independent record counts --------------------
#
# Duplicated rather than imported from `tests/test_report.py`, matching this
# project's existing precedent of each test module owning its own oracle
# (`test_dedupe.py` and `test_report.py` already each carry their own copy of
# this same shape) - a gate file's oracle should not depend on another test
# module's internals surviving unchanged.


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _raw_checkov_record_count(name: str) -> int:
    """Every `failed_checks` entry across every framework block of one checkov
    fixture, read directly from the JSON. Checkov's fixtures are a top-level
    list of per-framework result objects, with a single-object fallback so
    this does not assume a shape it has not checked.
    """
    document = _load_fixture(name)
    frameworks = document if isinstance(document, list) else [document]
    return sum(len((fw.get("results") or {}).get("failed_checks") or []) for fw in frameworks)


def _raw_trivy_record_count(name: str) -> int:
    """Every `Misconfigurations` entry across every `Results` block, read
    directly from the JSON.
    """
    document = _load_fixture(name)
    return sum(len(block.get("Misconfigurations") or []) for block in document.get("Results") or [])


def _raw_tfsec_record_count(name: str) -> int:
    """tfsec's flat `results` array, read directly from the JSON."""
    document = _load_fixture(name)
    return len(document.get("results") or [])


# --- real adapter output over the committed fixtures --------------------------------


def _kubernetes_index() -> ResourceIndex:
    return build_index(discover(KUBERNETES_SCAN_ROOT))


def _real_results() -> dict[tuple[str, str], AdapterResult]:
    """Every `(scanner, platform)` adapter run over the golden fixtures - the
    same five runs `test_dedupe.py`/`test_report.py` combine, kept separate
    by key here as those two modules also do.
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
    kubernetes_unparseable = _kubernetes_index().unparseable
    terraform_unparseable = discover(TERRAFORM_SCAN_ROOT).unparseable
    return frozenset(kubernetes_unparseable) | frozenset(terraform_unparseable)


def _all_real_findings() -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in _real_results().values():
        findings.extend(result.findings)
    return findings


def _real_dedupe() -> DedupeResult:
    return deduplicate(_all_real_findings())


# --- Gate 1 ---------------------------------------------------------------------------


def test_gate_1_every_fixture_finding_yields_one_finding_or_one_counted_drop() -> None:
    """Spec section 10, gate 1, verbatim:

    "Every finding in every golden fixture produces exactly one
    `NormalizedFinding`, or is counted as dropped with a stated reason. No
    silent loss."

    Measured: 1055 out, 0 dropped, across all five scanner/platform runs. The
    raw total per run is counted independently of every adapter - each
    scanner's own raw shape walked directly (checkov: a list of per-framework
    objects; trivy: nested under `Results[].Misconfigurations`; tfsec: a flat
    `results` array) - never by calling an adapter for the expectation, which
    would only prove an adapter agrees with itself.
    """
    results = _real_results()

    expected_by_run = {
        ("checkov", "terraform"): _raw_checkov_record_count("checkov-terraform.json"),
        ("checkov", "kubernetes"): _raw_checkov_record_count("checkov-kubernetes.json"),
        ("trivy", "terraform"): _raw_trivy_record_count("trivy-terraform.json"),
        ("trivy", "kubernetes"): _raw_trivy_record_count("trivy-kubernetes.json"),
        ("tfsec", "terraform"): _raw_tfsec_record_count("tfsec-terraform.json"),
    }
    assert set(results) == set(expected_by_run)  # every run accounted for, none missing

    total_expected = 0
    total_out = 0
    total_dropped = 0
    for key, expected_count in expected_by_run.items():
        assert expected_count > 0  # non-vacuous
        result = results[key]
        assert len(result.findings) + len(result.dropped) == expected_count, key
        total_expected += expected_count
        total_out += len(result.findings)
        total_dropped += len(result.dropped)

    # The whole-corpus figure, derived rather than restated: 1055 out, 0
    # dropped falls out of the per-run equalities above holding with
    # total_dropped == 0, not out of writing either number here.
    assert total_out == total_expected
    assert total_dropped == 0


# --- Gate 2 ---------------------------------------------------------------------------


def test_gate_2_every_finding_carries_a_class_and_a_severity_or_unknown() -> None:
    """Spec section 10, gate 2, verbatim:

    "Every finding carries an issue-class - a real class or an explicit
    `unmapped:` id - and a severity level or the explicit `unknown`."

    Measured: 0 unmapped, 489 findings carrying `severity_level == "unknown"`,
    and every one of the 489 is checkov (CLAUDE.md's independently harvested
    S0 measurement). The 489 is cross-checked here against an independent walk
    of checkov's own raw `severity` field across both its fixtures, not
    against the adapter's own count of its own output.
    """
    findings = _all_real_findings()
    assert findings  # non-vacuous

    for f in findings:
        assert f.issue_class  # never empty: a real class or `unmapped:<scanner>:<rule_id>`
        assert isinstance(f.severity_level, int) or f.severity_level == "unknown"

    unmapped = [f for f in findings if f.is_unmapped]
    assert unmapped == []

    unknown = [f for f in findings if f.severity_level == "unknown"]
    assert unknown  # non-vacuous
    assert all(f.scanner == "checkov" for f in unknown)

    raw_null_severity = 0
    for name in ("checkov-terraform.json", "checkov-kubernetes.json"):
        document = _load_fixture(name)
        frameworks = document if isinstance(document, list) else [document]
        for fw in frameworks:
            for check in (fw.get("results") or {}).get("failed_checks") or []:
                if check.get("severity") is None:
                    raw_null_severity += 1

    assert len(unknown) == raw_null_severity


# --- Gate 3 ---------------------------------------------------------------------------


def test_gate_3_tfsec_paths_join_string_equal_with_checkov_and_trivy() -> None:
    """Spec section 10, gate 3, verbatim:

    "All 119 tfsec findings resolve to scan-root-relative paths that are
    string-equal to the normalized paths checkov and trivy report for the
    same files. Asserted as set equality over the shared files, not merely as
    'tfsec paths look relative'."

    tfsec emits 119/119 absolute Windows paths natively (`scanners/tfsec.py`'s
    module docstring), so this is the gate that actually proves
    `rebase_to_scan_root` works rather than merely existing. Checked as: every
    one of tfsec's own findings (counted independently of the adapter) carries
    a `file_path` that is a member of both checkov's and trivy's terraform-run
    path sets, and no tfsec path retains a backslash, a leading slash, or a
    drive letter.
    """
    results = _real_results()
    tfsec_findings = results[("tfsec", "terraform")].findings

    expected_tfsec_count = _raw_tfsec_record_count("tfsec-terraform.json")
    assert expected_tfsec_count > 0
    assert len(tfsec_findings) == expected_tfsec_count

    checkov_paths = {f.file_path for f in results[("checkov", "terraform")].findings if f.file_path}
    trivy_paths = {f.file_path for f in results[("trivy", "terraform")].findings if f.file_path}
    assert checkov_paths  # non-vacuous
    assert trivy_paths

    tfsec_paths = [f.file_path for f in tfsec_findings]
    assert all(tfsec_paths)  # every one of the 119 carries a non-empty path
    for path in tfsec_paths:
        assert path in checkov_paths, f"{path!r} not in checkov's terraform path set"
        assert path in trivy_paths, f"{path!r} not in trivy's terraform path set"
        assert "\\" not in path
        assert not path.startswith("/")
        assert re.match(r"^[A-Za-z]:", path) is None


# --- Gate 4 (reworded; see module docstring) -------------------------------------------


def test_gate_4_kubernetes_identity_resolves_for_every_parseable_lined_finding() -> None:
    """Spec section 10, gate 4, as corrected by the task 11 dispatch (the
    plan's own wording is false - see module docstring):

    Kubernetes identity resolves for every finding on a parseable manifest
    that also carries a line number; findings on the four unparseable Helm
    templates, and findings supplying no line number at all, take
    `<unresolved>` and are counted - 19 in total, with exactly one finding
    counted under the unparseable-file cause even though it is also lineless
    (unparseable-file precedence, `report.py`'s `_unresolved_cause`).

    Every `identity_kind == "unresolved"` finding anywhere in the corpus is
    trivy/kubernetes (measured); this exercises the claim directly against
    real adapter output and a real `ResourceIndex`, not through
    `report.py`'s own accounting.
    """
    results = _real_results()
    all_findings = [f for result in results.values() for f in result.findings]

    unresolved_anywhere = [f for f in all_findings if f.identity_kind == "unresolved"]
    assert unresolved_anywhere  # non-vacuous
    assert all(f.scanner == "trivy" and f.platform == "kubernetes" for f in unresolved_anywhere)

    trivy_kubernetes_findings = results[("trivy", "kubernetes")].findings
    unparseable = frozenset(_kubernetes_index().unparseable)
    assert unparseable  # non-vacuous: the four Helm templates are unparseable in corpus v0

    # No finding on an unparseable file resolves - the gate's "findings in the
    # four Helm templates take <unresolved>" half.
    on_unparseable_file = [f for f in trivy_kubernetes_findings if f.file_path in unparseable]
    assert on_unparseable_file  # non-vacuous
    assert all(f.identity_kind == "unresolved" for f in on_unparseable_file)

    unresolved_trivy_kubernetes = [
        f for f in trivy_kubernetes_findings if f.identity_kind == "unresolved"
    ]
    assert {id(f) for f in unresolved_trivy_kubernetes} == {id(f) for f in unresolved_anywhere}

    lineless_on_parseable = [
        f
        for f in unresolved_trivy_kubernetes
        if f.file_path not in unparseable and f.line_range is None
    ]
    unparseable_cause = [f for f in unresolved_trivy_kubernetes if f.file_path in unparseable]

    # Single-assignment: unparseable-file wins precedence, so the two named
    # causes must exhaust the unresolved total with no residual.
    assert len(unparseable_cause) + len(lineless_on_parseable) == len(unresolved_trivy_kubernetes)

    # No unresolved finding is left over once both causes are accounted for -
    # the corrected gate's core claim: a finding on a parseable file WITH a
    # line number is never unresolved.
    leftover = [
        f
        for f in unresolved_trivy_kubernetes
        if f.file_path not in unparseable and f.line_range is not None
    ]
    assert leftover == []

    # Precedence, pinned exactly: exactly one finding is both unparseable and
    # lineless, and it is counted once, under the unparseable-file cause.
    overlap = [
        f
        for f in unresolved_trivy_kubernetes
        if f.file_path in unparseable and f.line_range is None
    ]
    assert len(overlap) == 1
    assert overlap[0].rule_id == "KSV-0117"
    assert overlap[0].file_path in unparseable

    # The positive claim, stated directly: every finding on a parseable file
    # that carries a line number resolves - 100%, not merely "most".
    all_parseable_and_lined = [
        f
        for f in trivy_kubernetes_findings
        if f.file_path not in unparseable and f.line_range is not None
    ]
    resolved_parseable_and_lined = [
        f for f in all_parseable_and_lined if f.identity_kind != "unresolved"
    ]
    assert all_parseable_and_lined  # non-vacuous
    assert len(resolved_parseable_and_lined) == len(all_parseable_and_lined)


# --- Gate 5 ---------------------------------------------------------------------------


def test_gate_5_tier1_never_mixes_fingerprints_or_collapses_unresolved() -> None:
    """Spec section 10, gate 5, verbatim:

    "Tier 1 never collapses two findings with different resolved fingerprints,
    and never collapses an unresolved-fingerprint finding with anything."

    Measured: 35 Tier-1 groups, `collapsed_count` 39, exactly 1 group
    cross-scanner. All three figures are cross-checked against an independent
    tally built directly from the finding list - a count keyed on
    `(resource_identity, issue_class, fingerprint)`, restricted to findings
    with both a resolved identity and a resolved fingerprint - never by
    asking `deduplicate()` about its own output, matching `test_dedupe.py`'s
    own independent-tally precedent for this exact figure.
    """
    findings = _all_real_findings()
    result = deduplicate(findings)

    eligible = [
        f
        for f in findings
        if f.resource_identity != identity.UNRESOLVED and f.has_resolved_fingerprint
    ]
    tally: dict[tuple[str, str, str], list[NormalizedFinding]] = {}
    for f in eligible:
        fingerprint = f.fingerprint
        assert fingerprint is not None  # narrows for mypy; has_resolved_fingerprint guarantees it
        tally.setdefault((f.resource_identity, f.issue_class, fingerprint), []).append(f)

    expected_groups = {key: members for key, members in tally.items() if len(members) > 1}
    assert expected_groups  # non-vacuous

    expected_group_count = len(expected_groups)
    expected_collapsed = sum(len(members) - 1 for members in expected_groups.values())
    expected_cross_scanner = sum(
        1 for members in expected_groups.values() if len({f.scanner for f in members}) > 1
    )

    assert len(result.groups) == expected_group_count
    assert result.collapsed_count == expected_collapsed
    assert sum(1 for g in result.groups if len(g.scanners) > 1) == expected_cross_scanner
    assert expected_cross_scanner == 1  # measured: exactly one Tier-1 group is cross-scanner

    # The structural half of the gate, stated directly: no group mixes
    # fingerprint values, and no group's fingerprint set contains the
    # unresolved `None` state.
    assert result.groups  # non-vacuous
    for group in result.groups:
        fingerprints = {f.fingerprint for f in group.findings}
        assert fingerprints == {group.key[2]}
        assert None not in fingerprints


# --- Gate 6 ---------------------------------------------------------------------------


def test_gate_6_the_retention_report_accounts_for_every_input_finding() -> None:
    """Spec section 10, gate 6, verbatim:

    "The retention report accounts for every input finding: in = out +
    dropped, per scanner."

    `ScannerCoverage.findings_in` is *derived* as `findings_out +
    len(dropped)` (`report.py`'s own docstring), so asserting that identity
    alone is `a == a` and cannot fail - `tests/test_report.py` already names
    this honestly
    (`test_real_corpus_findings_in_is_internally_consistent_with_out_and_dropped`)
    and already closes the real gap with an independent raw count
    (`test_real_corpus_findings_out_plus_dropped_equals_an_independent_raw_count`).
    Reproducing either verbatim here would not close a new gap, so this gate
    instead closes at the whole-corpus grain those per-run tests do not state
    directly: the sum of every run's `findings_out + len(dropped)` equals one
    independently-counted raw total across all five scanner/platform runs
    combined - computed by this test's own walk of the raw fixture JSON,
    never by calling `build_report`, an adapter, or `test_report.py`'s own
    helpers for the expectation.
    """
    results = _real_results()
    dedupe_result = _real_dedupe()
    unparseable = _real_unparseable()
    report = build_report(results, dedupe_result, unparseable)

    # The per-scanner identity the gate states directly - a precondition
    # checked here, not the gate's substance (see docstring).
    for coverage in report.scanners.values():
        assert coverage.findings_in == coverage.findings_out + len(coverage.dropped)

    raw_total = (
        _raw_checkov_record_count("checkov-terraform.json")
        + _raw_checkov_record_count("checkov-kubernetes.json")
        + _raw_trivy_record_count("trivy-terraform.json")
        + _raw_trivy_record_count("trivy-kubernetes.json")
        + _raw_tfsec_record_count("tfsec-terraform.json")
    )
    assert raw_total > 0

    total_out_plus_dropped = sum(
        coverage.findings_out + len(coverage.dropped) for coverage in report.scanners.values()
    )
    total_dropped = sum(len(coverage.dropped) for coverage in report.scanners.values())

    assert total_out_plus_dropped == raw_total
    assert total_dropped == 0
