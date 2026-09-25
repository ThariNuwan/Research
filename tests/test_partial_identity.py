"""A partially-unresolved identity must never be treated as fully resolved.

Whole-branch review Finding 1. `identity.kubernetes_identity` substitutes the
`<unresolved>` sentinel *per component*, so an identity can read
`apps/v1/Deployment/<unresolved>/<unresolved>` - a string that *contains* the
sentinel without *equalling* it. Before this fix, every downstream consumer
that tested `resource_identity == identity.UNRESOLVED` missed that case:
`dedupe.py` grouped on it as though it were a real, distinct resource, and the
adapters left `identity_kind` at `"kubernetes"` (so `report.py` counted it as
resolved and `context_eligible` stayed `True`, in violation of spec §2.1).

`identity.is_unusable` is the one predicate that now backs every one of those
consumers - equality with the sentinel, containment of it, and the empty/
whitespace-only case are all covered by one definition, tested directly below.
The rest of this module reproduces the reviewer's end-to-end scenario: two
Kubernetes manifests whose `metadata.name` (and, here, `metadata.namespace`)
are *quoted* Helm templates - valid YAML, so `discover()` and `build_index()`
parse them cleanly, unlike corpus v0's one Helm chart, which uses the
unquoted form and fails to parse at all. Corpus v0 therefore never exercises
this branch; the next sub-project's corpus, authored from open-source charts,
ordinarily will.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacrisk import identity
from iacrisk.dedupe import deduplicate
from iacrisk.input import discover
from iacrisk.report import build_report
from iacrisk.resources import build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.trivy import TrivyAdapter

# --- identity.is_unusable: the predicate directly -----------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (identity.UNRESOLVED, True),
        ("apps/v1/Deployment/<unresolved>/<unresolved>", True),
        ("apps/v1/Deployment/default/<unresolved>", True),
        ("", True),
        ("   ", True),
        ("\t\n", True),
        ("aws_s3_bucket.data", False),
        ("apps/v1/Deployment/default/api", False),
    ],
    ids=[
        "bare-sentinel",
        "sentinel-in-both-components",
        "sentinel-in-one-component",
        "empty-string",
        "whitespace-only",
        "tab-and-newline-only",
        "a-genuinely-resolved-terraform-identity",
        "a-genuinely-resolved-kubernetes-identity",
    ],
)
def test_is_unusable_covers_equality_containment_and_blank(value: str, expected: bool) -> None:
    assert identity.is_unusable(value) is expected


# --- end-to-end: quoted, templated Helm names through the real pipeline -------------


def _write_templated_deployment(path: Path, suffix: str, container: str) -> None:
    """One Deployment manifest whose `metadata.name` and `metadata.namespace`
    are quoted Helm templates - valid YAML (quoted), unlike corpus v0's one
    Helm chart, which is unquoted and fails to parse at all.
    """
    path.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        f'  name: "{{{{ .Release.Name }}}}-{suffix}"\n'
        '  namespace: "{{ .Release.Namespace }}"\n'
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        f"        - name: {container}\n"
        "          image: nginx:latest\n",
        encoding="utf-8",
        newline="\n",
    )


def _synthetic_trivy_run() -> dict[str, object]:
    """One trivy `Results` document flagging both templated Deployments.

    `KSV-0001` is a real, mapped rule id (used elsewhere in the fixtures), so
    both findings share one real `issue_class` rather than each taking its own
    `unmapped:` fallback - what the dedupe-exclusion assertion below needs to
    be a meaningful check of `(resource_identity, issue_class)` grouping,
    not merely of two findings that never shared a class to begin with.
    Trivy's Kubernetes resolution is by line alone (module docstring,
    `trivy.py`), so `StartLine`/`EndLine` at line 2 - `kind: Deployment`,
    inside the document span and above the container block - is enough.
    """
    return {
        "Results": [
            {
                "Target": "web.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "Misconfigurations": [
                    {
                        "ID": "KSV-0001",
                        "Title": "synthetic finding, whole-branch review Finding 1",
                        "Resolution": "n/a",
                        "Severity": "LOW",
                        "CauseMetadata": {"StartLine": 2, "EndLine": 2},
                    }
                ],
            },
            {
                "Target": "api.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "Misconfigurations": [
                    {
                        "ID": "KSV-0001",
                        "Title": "synthetic finding, whole-branch review Finding 1",
                        "Resolution": "n/a",
                        "Severity": "LOW",
                        "CauseMetadata": {"StartLine": 2, "EndLine": 2},
                    }
                ],
            },
        ]
    }


def test_quoted_helm_templated_names_are_unresolved_end_to_end(tmp_path: Path) -> None:
    _write_templated_deployment(tmp_path / "web.yaml", "web", "web")
    _write_templated_deployment(tmp_path / "api.yaml", "api", "api")

    discovery = discover(tmp_path)
    index = build_index(discovery)
    assert index.unparseable == ()  # both files are valid, quoted YAML

    result = TrivyAdapter().parse(_synthetic_trivy_run(), tmp_path, index)
    assert len(result.findings) == 2
    web_finding, api_finding = result.findings

    # The identity itself carries the informative partial string, not the bare
    # sentinel - both components were substituted individually, so both render
    # `<unresolved>`, and the two Deployments' identities collide as a string
    # even though they are two different resources in two different files.
    for finding in (web_finding, api_finding):
        assert finding.resource_identity == "apps/v1/Deployment/<unresolved>/<unresolved>"
        assert identity.is_unusable(finding.resource_identity)

    # The load-bearing assertion: identity_kind is "unresolved", not
    # "kubernetes" - this is what fixes context_eligible and report.py's
    # counting downstream without either of them needing to re-test the string.
    for finding in (web_finding, api_finding):
        assert finding.identity_kind == "unresolved"
        assert finding.context_eligible is False

    # report.py: the headline retention metric must not claim these are
    # resolved just because `identity_kind` used to say "kubernetes".
    adapter_result = AdapterResult(findings=result.findings, dropped=())
    dedupe_result = deduplicate(result.findings)
    report = build_report(
        {("trivy", "kubernetes"): adapter_result}, dedupe_result, frozenset(index.unparseable)
    )
    coverage = report.scanners[("trivy", "kubernetes")]
    assert coverage.identity_unresolved == 2
    assert coverage.identity_resolved == 0
    assert coverage.identity_resolution_rate == 0.0
    assert coverage.identity_resolution_rate != 1.0

    # dedupe.py: two different workloads whose identities collapsed to one
    # string by coincidence of both being unresolved must not be treated as
    # the same resource - in neither tier, even though they share the same
    # (colliding) resource_identity and the same issue_class.
    assert dedupe_result.groups == ()
    assert dedupe_result.candidates == ()
