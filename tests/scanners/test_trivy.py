"""Trivy: the scanner whose Kubernetes findings carry no resource field at all (task 6 brief).

Terraform is the easy half - `CauseMetadata.Resource` is present on 113 of 115
findings and is always a clean `<type>.<name>` pair, the same shape checkov's
`classify_resource` has to work harder to recognize among four other shapes.
The 2 without it (both `DS-*` Dockerfile checks) resolve to `identity_kind
="file"` from `Target` instead - not `<unresolved>`, corrected during the fix
round - matching checkov's own `identity_kind` for the same physical file.

Kubernetes is the hard half. Trivy states the resource only in prose
(`Container 'batch-check' of Job 'batch-check-job' should set...`), so every
one of 332 findings has to be resolved through `ResourceIndex.by_line` against
`CauseMetadata.StartLine` - there is no `resource`-shaped field to read at
all. The tests below measure that resolution rate directly against the index,
independently of the adapter, rather than trusting the adapter's own count.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iacrisk import identity, rubric, taxonomy
from iacrisk.input import discover
from iacrisk.resources import ResourceIndex, build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _raw_misconfigurations(name: str) -> list[tuple[str, dict[str, Any]]]:
    """Every `(Target, misconfiguration)` pair across every Result block of one fixture.

    Read independently of `TrivyAdapter`, by walking the same JSON shape the
    adapter walks rather than by asking the adapter what it saw - so the `in`
    side of `in == out + dropped` is not the adapter grading its own homework,
    matching `test_checkov.py::_raw_failed_checks`'s own reasoning for doing
    the same thing.
    """
    pairs: list[tuple[str, dict[str, Any]]] = []
    for block in _load_fixture(name)["Results"]:
        target = str(block.get("Target") or "")
        pairs.extend((target, m) for m in block.get("Misconfigurations") or [])
    return pairs


def _kubernetes_index() -> ResourceIndex:
    return build_index(discover(KUBERNETES_SCAN_ROOT))


def _terraform_result() -> AdapterResult:
    return TrivyAdapter().parse(_load_fixture("trivy-terraform.json"), TERRAFORM_SCAN_ROOT, None)


def _kubernetes_result() -> AdapterResult:
    return TrivyAdapter().parse(
        _load_fixture("trivy-kubernetes.json"), KUBERNETES_SCAN_ROOT, _kubernetes_index()
    )


# --- retention: every input finding becomes exactly one finding or one drop --------


def test_every_terraform_finding_is_retained_or_dropped() -> None:
    raw = _raw_misconfigurations("trivy-terraform.json")
    result = _terraform_result()
    assert len(raw) == len(result.findings) + len(result.dropped)


def test_every_kubernetes_finding_is_retained_or_dropped() -> None:
    raw = _raw_misconfigurations("trivy-kubernetes.json")
    result = _kubernetes_result()
    assert len(raw) == len(result.findings) + len(result.dropped)


def test_nothing_is_dropped_in_corpus_v0() -> None:
    """Every misconfiguration in both fixtures carries an `ID` (measured: 0 of
    115 and 0 of 332 missing), so nothing should land in `dropped` - even the
    2 terraform findings with no `CauseMetadata.Resource` are retained, with a
    `file` identity resolved from `Target`, never dropped.
    """
    assert _terraform_result().dropped == ()
    assert _kubernetes_result().dropped == ()


# --- terraform identity: CauseMetadata.Resource, and the 2 that lack it ------------


def test_a_terraform_resource_resolves_to_the_terraform_identity() -> None:
    """`aws_instance.db_app` on `AWS-0028`, a real corpus v0 row (verified against
    the raw fixture directly rather than assumed)."""
    raw = _raw_misconfigurations("trivy-terraform.json")
    _, m = next(pair for pair in raw if pair[1]["ID"] == "AWS-0028")
    assert m["CauseMetadata"]["Resource"] == "aws_instance.db_app"

    result = _terraform_result()
    finding = next(
        f for f in result.findings if f.rule_id == "AWS-0028" and f.file_path == "db-app.tf"
    )
    assert finding.identity_kind == "terraform"
    assert finding.context_eligible is True
    assert finding.resource_identity == identity.terraform_identity("aws_instance", "db_app")


def test_the_two_findings_without_a_resource_take_the_file_identity_kind() -> None:
    """The 2 terraform findings with no `CauseMetadata.Resource` at all (measured:
    both are `resources/Dockerfile` findings, `DS-0002` and `DS-0026`, `Type:
    "dockerfile"` - Dockerfile checks trivy runs alongside the terraform scan
    root). **Corrected during the fix round**: the task brief originally said
    these take `<unresolved>`; that conflated "no terraform `Resource`" with
    "identity undeterminable". trivy's own `Target` names the file plainly
    (`resources/Dockerfile`), and checkov flags the *same file* with
    `CKV_DOCKER_2`/`CKV_DOCKER_3` under `identity_kind="file"`
    (`test_checkov.py::test_a_dockerfile_resource_is_a_file_and_not_context_eligible`).
    Giving trivy's view of that file a different kind than checkov's would
    split one Dockerfile across two retention-report buckets (Task 9) and
    make the two scanners' findings on it structurally unable to dedupe-
    candidate together (Task 8, since `<unresolved>` never collapses with
    anything) - for no reason but which scanner happened to find it.
    """
    raw = _raw_misconfigurations("trivy-terraform.json")
    missing = [
        (target, m) for target, m in raw if not (m.get("CauseMetadata") or {}).get("Resource")
    ]
    assert len(missing) == 2
    assert {m["ID"] for _, m in missing} == {"DS-0002", "DS-0026"}
    assert {target for target, _ in missing} == {"resources/Dockerfile"}

    result = _terraform_result()
    file_findings = [f for f in result.findings if f.rule_id in ("DS-0002", "DS-0026")]
    assert len(file_findings) == 2
    for finding in file_findings:
        assert finding.identity_kind == "file"
        assert finding.resource_identity == "resources/Dockerfile"
        assert finding.context_eligible is False


def test_no_resource_and_no_target_stays_genuinely_unresolved() -> None:
    """The `file` fallback above only fires when `Target` actually names a file.
    A finding with neither `CauseMetadata.Resource` nor a real `Target` (here,
    `Target == "."`, trivy's directory-level summary spelling) has nothing to
    point at, so it must still fall through to `<unresolved>` - the boundary
    the fix round's file-identity fallback must not erase. Constructed rather
    than found: corpus v0 has no misconfiguration with both fields absent at
    once (the 2 real no-`Resource` findings both carry a real `Target`).
    """
    synthetic = {
        "Results": [
            {
                "Target": ".",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AWS-9998",
                        "Title": "made up for this test",
                        "Resolution": "n/a",
                        "Severity": "LOW",
                        "CauseMetadata": {},
                    }
                ],
            }
        ]
    }
    result = TrivyAdapter().parse(synthetic, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.file_path == ""
    assert finding.resource_identity == identity.UNRESOLVED
    assert finding.identity_kind == "unresolved"
    assert finding.context_eligible is False


# --- kubernetes identity: entirely from the index, by line -------------------------


def test_kubernetes_identity_resolution_rate_matches_the_index_measured_independently() -> None:
    """Walks `CauseMetadata.StartLine` against the same `ResourceIndex` the
    adapter uses, independently of `TrivyAdapter`, so a defect that resolves a
    different count than the index actually supports is caught rather than the
    adapter grading its own homework (mirrors `test_checkov.py`'s reasoning).

    Measured on this fixture: 313 of 332 resolve (94.3%), 217 of those to a
    container. The 19 misses are 15 in the unparseable `metadata-db/templates/`
    Helm template (a `StartLine` present but matching no span) plus 4 `KSV-0117`
    findings with no `StartLine` at all.
    """
    index = _kubernetes_index()
    raw = _raw_misconfigurations("trivy-kubernetes.json")

    expected_resolved = 0
    expected_container = 0
    for target, m in raw:
        start_line = (m.get("CauseMetadata") or {}).get("StartLine")
        if not isinstance(start_line, int):
            continue
        entry = index.by_line(target, start_line)
        if entry is not None:
            expected_resolved += 1
            if entry.container is not None:
                expected_container += 1

    # Non-triviality guards, not the numbers under test: a defect that made the
    # loop above match nothing at all would otherwise let the comparison below
    # pass vacuously (0 == 0). The 313/217 the docstring quotes are asserted
    # only via that comparison against the adapter's own output, never
    # hardcoded here - so a re-capture that moves the true rate moves what
    # this test expects, rather than failing against a stale literal.
    assert expected_resolved
    assert expected_container

    result = _kubernetes_result()
    resolved = [f for f in result.findings if f.identity_kind == "kubernetes"]
    assert len(resolved) == expected_resolved
    assert len([f for f in resolved if "[container=" in f.resource_identity]) == expected_container


def test_a_known_kubernetes_finding_resolves_to_its_container() -> None:
    """`KSV-0001` on `batch-check/job.yaml`, `StartLine` 11 - the exact example
    the task brief quotes in prose (`Container 'batch-check' of Job
    'batch-check-job' should set 'securityContext.allowPrivilegeEscalation' to
    false`). Verified against the real manifest via the index directly, then
    against the adapter's own output for the same rule and file.
    """
    index = _kubernetes_index()
    entry = index.by_line("batch-check/job.yaml", 11)
    assert entry is not None
    assert entry.kind == "Job"
    assert entry.name == "batch-check-job"
    assert entry.container == "batch-check"

    result = _kubernetes_result()
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "KSV-0001" and f.file_path == "batch-check/job.yaml"
    )
    assert finding.identity_kind == "kubernetes"
    assert finding.resource_identity == entry.to_identity()
    assert "[container=batch-check]" in finding.resource_identity


def test_a_line_matching_no_span_is_unresolved_and_counted() -> None:
    """One of the 15 unparseable-Helm-template misses: `KSV-0001` on
    `metadata-db/templates/deployment.yaml` carries a real `StartLine`, but the
    file is one of the 4 Helm templates `build_index` could not parse (§4), so
    no span in the index contains that line. Grounded in the real fixture
    row, not constructed, since corpus v0 genuinely exercises this case.
    """
    index = _kubernetes_index()
    assert "metadata-db/templates/deployment.yaml" in index.unparseable

    raw = _raw_misconfigurations("trivy-kubernetes.json")
    target, m = next(
        (t, m)
        for t, m in raw
        if t == "metadata-db/templates/deployment.yaml" and m["ID"] == "KSV-0001"
    )
    start_line = m["CauseMetadata"]["StartLine"]
    assert index.by_line(target, start_line) is None

    result = _kubernetes_result()
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "KSV-0001" and f.file_path == "metadata-db/templates/deployment.yaml"
    )
    assert finding.resource_identity == identity.UNRESOLVED
    assert finding.identity_kind == "unresolved"
    assert finding.context_eligible is False


def test_a_missing_start_line_is_unresolved_and_counted() -> None:
    """`KSV-0117` carries no `StartLine`/`EndLine` at all on any of its 4 corpus
    v0 occurrences (measured) - a distinct cause from the by-line miss above,
    since there is no line to even attempt a lookup with.
    """
    raw = _raw_misconfigurations("trivy-kubernetes.json")
    no_line = [(t, m) for t, m in raw if m["ID"] == "KSV-0117"]
    assert len(no_line) == 4
    assert all((m.get("CauseMetadata") or {}).get("StartLine") is None for _, m in no_line)

    result = _kubernetes_result()
    unresolved = [f for f in result.findings if f.rule_id == "KSV-0117"]
    assert len(unresolved) == 4
    for finding in unresolved:
        assert finding.resource_identity == identity.UNRESOLVED
        assert finding.identity_kind == "unresolved"
        assert finding.context_eligible is False


def test_kubernetes_identity_needs_an_index() -> None:
    """`index=None` on a kubernetes run has no lookup to attempt at all - every
    finding must come back unresolved rather than the adapter crashing on a
    `None.by_line(...)` call. Corpus v0 always supplies an index for kubernetes
    runs, so this is a defensive guard, not a measured corpus state.
    """
    raw_kubernetes = _load_fixture("trivy-kubernetes.json")
    result = TrivyAdapter().parse(raw_kubernetes, KUBERNETES_SCAN_ROOT, None)

    # Derived, not restated: losing the index must cost identity, never findings.
    # A hardcoded count here could not distinguish "nothing dropped" from "the
    # fixture changed", which is the whole reason the brief forbids the literal.
    assert len(result.findings) == len(_raw_misconfigurations(raw_kubernetes))
    assert all(f.identity_kind == "unresolved" for f in result.findings)
    assert all(f.context_eligible is False for f in result.findings)


# --- Target == "." : the directory-level summary block, not a file -----------------


def test_a_target_of_dot_yields_an_empty_file_path_and_does_not_crash() -> None:
    """One real block in `trivy-terraform.json` has `Target: "."` - trivy's own
    directory-level summary for the whole scan root (`MisconfSummary.Successes:
    66, Failures: 0`, no `Misconfigurations` key at all), so no real
    misconfiguration is ever attached to it in corpus v0 (verified above: the
    finding counts add up to exactly 115 without it contributing any). This
    constructs a misconfiguration under that `Target` directly, so the "`.`
    names no file" rule (spec §5.1) is checked rather than merely true by the
    absence of a counter-example.
    """
    raw = _load_fixture("trivy-terraform.json")
    dot_blocks = [b for b in raw["Results"] if b.get("Target") == "."]
    assert len(dot_blocks) == 1
    assert "Misconfigurations" not in dot_blocks[0]

    synthetic = {
        "Results": [
            {
                "Target": ".",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AWS-9999",
                        "Title": "made up for this test",
                        "Resolution": "n/a",
                        "Severity": "LOW",
                        "CauseMetadata": {"Resource": "aws_made_up_thing.example"},
                    }
                ],
            }
        ]
    }
    result = TrivyAdapter().parse(synthetic, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.file_path == ""


# --- fingerprint: unresolved for every trivy finding, measured not assumed --------


def test_fingerprint_is_none_for_every_finding() -> None:
    """Not because trivy lacks an attribute string to extract - 185 of 332
    (55.7%) `Resolution` fields carry a cleanly quoted token like
    `containers[].securityContext.runAsNonRoot` (spec §6). It is because that
    extracted vocabulary has zero exact-spelling overlap with checkov's
    `evaluated_keys` (18 distinct trivy tokens, 23 distinct checkov keys, 0
    shared spellings) - extracting it would add a field that never matches
    and produce no additional Tier-1 dedupe collapse. Asserted as a property
    over the whole fixture, not a single instance, because the reason is a
    property of the whole vocabulary, not of any one finding.
    """
    for result in (_terraform_result(), _kubernetes_result()):
        assert result.findings
        assert all(f.fingerprint is None for f in result.findings)


# --- taxonomy: both trivy rule families join, unmodified --------------------------


def test_an_aws_rule_resolves_through_the_taxonomy() -> None:
    result = _terraform_result()
    known = next(f for f in result.findings if f.rule_id == "AWS-0028")
    assert known.issue_class == taxonomy.class_for("trivy", "AWS-0028")
    assert not known.is_unmapped


def test_a_ksv_rule_resolves_through_the_taxonomy() -> None:
    result = _kubernetes_result()
    known = next(f for f in result.findings if f.rule_id == "KSV-0001")
    assert known.issue_class == taxonomy.class_for("trivy", "KSV-0001")
    assert not known.is_unmapped


def test_no_finding_is_unmapped_in_corpus_v0() -> None:
    """Every distinct rule id trivy emits in corpus v0 - 47 `AWS-*`, 30 `KSV-*`
    and 2 `DS-*` (79 total, measured directly against `taxonomy.json`) - is a
    row the committed taxonomy already carries, so no finding should take the
    `unmapped:` fallback here. Driven from the adapter's own output, not from
    a restated 79, so a taxonomy edit that drops coverage fails this test.
    """
    for result in (_terraform_result(), _kubernetes_result()):
        assert result.findings
        assert not any(f.is_unmapped for f in result.findings)


def test_an_unrecognized_rule_id_takes_the_unmapped_fallback() -> None:
    """A minimal, hand-built document - corpus v0 maps every rule id it contains
    (previous test), so this id has to be invented rather than found.
    """
    raw = {
        "Results": [
            {
                "Target": "made-up.tf",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AWS-INVENTED-999999",
                        "Title": "not a real trivy rule",
                        "Resolution": "n/a",
                        "Severity": "LOW",
                        "CauseMetadata": {"Resource": "aws_made_up_thing.example"},
                    }
                ],
            }
        ]
    }
    result = TrivyAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.is_unmapped
    assert finding.issue_class == "unmapped:trivy:AWS-INVENTED-999999"


# --- severity: trivy is the one scanner that reliably supplies one ----------------


def test_severity_is_always_present_and_matches_the_rubric() -> None:
    """Unlike checkov (489/489 null in corpus v0), trivy's `Severity` is present
    on every one of the 447 findings across both fixtures and takes exactly one
    of `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` (CLAUDE.md, "Severity in corpus v0,
    measured": "Trivy 447 ... carry exactly four levels") - no `UNKNOWN` token
    observed, so `severity_level` should never fall back to the `unknown` state
    here. Checked per finding against `rubric.normalize_severity` directly,
    rather than only against the four-token vocabulary, so a mapping defect for
    any one token would be caught.
    """
    raw = _raw_misconfigurations("trivy-terraform.json") + _raw_misconfigurations(
        "trivy-kubernetes.json"
    )
    assert raw
    assert all(m.get("Severity") for _, m in raw)
    assert {m["Severity"] for _, m in raw} == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    for result in (_terraform_result(), _kubernetes_result()):
        assert result.findings
        for finding in result.findings:
            assert finding.native_severity is not None
            assert finding.severity_level != "unknown"
            assert finding.severity_level == rubric.normalize_severity(
                "trivy", finding.native_severity
            )


# --- path handling: trivy's own scan-root-relative spelling carries through -------


def test_file_path_is_scan_root_relative_and_never_carries_a_leading_separator() -> None:
    result = _terraform_result()
    assert any(f.file_path == "db-app.tf" for f in result.findings)
    assert not any(f.file_path.startswith(("/", "\\")) for f in result.findings)


def test_kubernetes_file_path_matches_trivys_own_target_spelling() -> None:
    """Trivy's kubernetes `Target` is already the same POSIX-relative spelling
    `discover()` produces (`batch-check/job.yaml`), so no rebasing work is
    actually done here - this pins that no unwanted transformation (a stray
    separator, a dropped path segment) sneaks in regardless.
    """
    result = _kubernetes_result()
    assert any(f.file_path == "batch-check/job.yaml" for f in result.findings)
