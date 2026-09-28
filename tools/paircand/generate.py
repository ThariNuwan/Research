"""Propose contrastive-pair candidates from corpus v0's normalized findings.

A research instrument, beside `tools/harvest/`: outside `src/` because it is not
part of the artifact, and outside `eval/` because `eval/` may not import the
framework it grades (`tests/test_architecture.py`). This is the first
`tools/ -> iacrisk` import in the repository, and the direction is deliberate -
an instrument consuming the artifact. The reverse stays forbidden.

It proposes; it does not judge. There is no class-to-factor mapping in the data
(design spec section 1), so single-factor purity cannot be established here and
is not claimed: the output records exactly which classes differ, and a human
names the factor and argues purity in the pair's rationale.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.resources import CLUSTER_SCOPED_KINDS, build_index
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"
OUTPUT = REPO_ROOT / "artifacts" / "pair-candidates.json"

PAIRABLE_KINDS = ("terraform", "kubernetes")


@dataclass(frozen=True)
class Candidate:
    """Two same-type resources whose issue-class sets differ, and how they differ."""

    grouping_type: str
    a: str
    b: str
    only_a: tuple[str, ...]
    only_b: tuple[str, ...]
    shared: int


@dataclass(frozen=True)
class CandidateReport:
    """Candidates plus the denominators that make their count interpretable.

    `considered` and `empty_difference` are reported because "120 usable
    candidates" says nothing without how many combinations were examined.
    `clean_severity_pairs` is a deliberate negative: design spec section 1
    measured it at 0, and recomputing it keeps that claim re-derivable rather
    than a one-time observation.
    """

    considered: int
    empty_difference: int
    candidates: tuple[Candidate, ...]
    clean_severity_pairs: int


def grouping_type(identity: str, identity_kind: str) -> str:
    """The bucket two identities must share before they are worth comparing.

    Terraform: the resource type before the first dot.

    Kubernetes has two shapes, because `identity.kubernetes_identity` itself
    built the string two ways: a namespaced identity is
    `apiVersion/Kind/namespace/name[ [container=...]]`, so the bucket drops
    the last two segments (namespace and name); a cluster-scoped identity
    carries no namespace component at all
    (`apiVersion/Kind/name`), so dropping two segments would strip the Kind
    too and leave a bare apiVersion. Segment count alone cannot distinguish
    them - `v1/Service/default/name` and
    `rbac.authorization.k8s.io/v1/ClusterRoleBinding/superadmin` are both
    four segments - so the second-from-last segment is tested against
    `CLUSTER_SCOPED_KINDS`, imported rather than restated so this bucket
    can never drift from whatever `identity.py` treated as cluster-scoped
    when it built the string in the first place; a Kind that set does not
    cover carries a namespace in its identity anyway, so mirroring the same
    constant is correct by construction, not by coincidence.

    A grouping heuristic for *proposal* only. It is never used as an identity
    and never written into ground truth.
    """
    if identity_kind == "terraform":
        return identity.split(".", 1)[0]
    parts = identity.split("/")
    if len(parts) >= 3 and parts[-2] in CLUSTER_SCOPED_KINDS:
        return "/".join(parts[:-1])
    if len(parts) >= 3:
        return "/".join(parts[:-2])
    return identity


def enumerate_candidates(findings: Sequence[NormalizedFinding]) -> CandidateReport:
    """Every same-type resource combination, split into usable and empty-difference."""
    classes: dict[str, set[str]] = defaultdict(set)
    severities: dict[str, set[int]] = defaultdict(set)
    kinds: dict[str, str] = {}
    for finding in findings:
        if finding.identity_kind not in PAIRABLE_KINDS:
            continue
        classes[finding.resource_identity].add(finding.issue_class)
        kinds[finding.resource_identity] = finding.identity_kind
        if isinstance(finding.severity_level, int):
            severities[finding.resource_identity].add(finding.severity_level)

    buckets: dict[str, list[str]] = defaultdict(list)
    for identity, kind in kinds.items():
        buckets[grouping_type(identity, kind)].append(identity)

    considered = 0
    empty_difference = 0
    clean_severity_pairs = 0
    candidates: list[Candidate] = []
    for bucket, identities in sorted(buckets.items()):
        for a, b in combinations(sorted(identities), 2):
            considered += 1
            only_a = classes[a] - classes[b]
            only_b = classes[b] - classes[a]
            if not only_a and not only_b:
                empty_difference += 1
                if severities[a] and severities[b] and max(severities[a]) != max(severities[b]):
                    clean_severity_pairs += 1
                continue
            candidates.append(
                Candidate(
                    grouping_type=bucket,
                    a=a,
                    b=b,
                    only_a=tuple(sorted(only_a)),
                    only_b=tuple(sorted(only_b)),
                    shared=len(classes[a] & classes[b]),
                )
            )
    return CandidateReport(
        considered=considered,
        empty_difference=empty_difference,
        candidates=tuple(candidates),
        clean_severity_pairs=clean_severity_pairs,
    )


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def real_findings() -> list[NormalizedFinding]:
    """The five corpus v0 adapter runs. Scan roots are absolute: `rebase_to_scan_root`
    raises on tfsec's absolute Windows paths when given a relative root.
    """
    index = build_index(discover(KUBERNETES_ROOT))
    findings: list[NormalizedFinding] = []
    for result in (
        CheckovAdapter().parse(_load("checkov-terraform.json"), TERRAFORM_ROOT, None),
        TrivyAdapter().parse(_load("trivy-terraform.json"), TERRAFORM_ROOT, None),
        TfsecAdapter().parse(_load("tfsec-terraform.json"), TERRAFORM_ROOT, None),
        CheckovAdapter().parse(_load("checkov-kubernetes.json"), KUBERNETES_ROOT, index),
        TrivyAdapter().parse(_load("trivy-kubernetes.json"), KUBERNETES_ROOT, index),
    ):
        findings.extend(result.findings)
    return findings


def to_json(report: CandidateReport) -> dict[str, object]:
    """JSON-safe primitives, candidate order preserved."""
    return {
        "schema_version": 1,
        "considered": report.considered,
        "empty_difference": report.empty_difference,
        "usable": len(report.candidates),
        "clean_severity_pairs": report.clean_severity_pairs,
        "candidates": [
            {
                "grouping_type": c.grouping_type,
                "a": c.a,
                "b": c.b,
                "only_a": list(c.only_a),
                "only_b": list(c.only_b),
                "shared": c.shared,
            }
            for c in report.candidates
        ],
    }


def main(argv: list[str] | None = None) -> int:
    report = enumerate_candidates(real_findings())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(to_json(report), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"considered={report.considered} empty_difference={report.empty_difference} "
        f"usable={len(report.candidates)} clean_severity_pairs={report.clean_severity_pairs}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
