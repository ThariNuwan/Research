import json
from pathlib import Path
from typing import Any

from iacrisk.finding import NormalizedFinding
from tools.paircand.generate import enumerate_candidates, grouping_type, real_findings, to_json

# `tools` is a package at the repository root and `pythonpath = ["src", "."]` in
# pyproject.toml, so this is the same import form `tests/harvest/test_run.py`
# already uses (`from tools.harvest.run import ...`). `tools/paircand/__init__.py`
# is required; a `tests/paircand/__init__.py` is not, and must not be added.

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PAIR_CANDIDATES = REPO_ROOT / "artifacts" / "pair-candidates.json"


def _f(
    identity: str, issue_class: str, kind: str = "terraform", severity: int | str = 3
) -> NormalizedFinding:
    return NormalizedFinding(
        scanner="checkov",
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=severity,
        platform="terraform",
        resource_identity=identity,
        identity_kind=kind,
        file_path="x.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )


def test_differing_class_sets_are_emitted_with_the_difference_in_both_directions() -> None:
    report = enumerate_candidates(
        [
            _f("aws_s3_bucket.a", "storage-encryption-at-rest"),
            _f("aws_s3_bucket.a", "storage-logging-audit"),
            _f("aws_s3_bucket.b", "storage-logging-audit"),
        ]
    )
    assert report.considered == 1
    assert report.empty_difference == 0
    (candidate,) = report.candidates
    assert candidate.grouping_type == "aws_s3_bucket"
    assert candidate.only_a == ("storage-encryption-at-rest",)
    assert candidate.only_b == ()
    assert candidate.shared == 1


def test_identical_class_sets_are_counted_but_not_emitted() -> None:
    report = enumerate_candidates(
        [
            _f("aws_rds_cluster.one", "iam-authentication-controls"),
            _f("aws_rds_cluster.two", "iam-authentication-controls"),
        ]
    )
    assert report.considered == 1
    assert report.empty_difference == 1
    assert report.candidates == ()


def test_resources_of_different_types_are_never_compared() -> None:
    report = enumerate_candidates(
        [
            _f("aws_s3_bucket.a", "storage-logging-audit"),
            _f("aws_vpc.b", "networking-flow-logging"),
        ]
    )
    assert report.considered == 0
    assert report.candidates == ()


def test_clean_severity_pairs_counts_identical_class_sets_with_differing_severity() -> None:
    report = enumerate_candidates(
        [
            _f("aws_s3_bucket.a", "storage-logging-audit", severity=2),
            _f("aws_s3_bucket.b", "storage-logging-audit", severity=4),
        ]
    )
    assert report.clean_severity_pairs == 1


def test_an_unknown_severity_never_counts_toward_a_severity_pair() -> None:
    report = enumerate_candidates(
        [
            _f("aws_s3_bucket.a", "storage-logging-audit", severity="unknown"),
            _f("aws_s3_bucket.b", "storage-logging-audit", severity=4),
        ]
    )
    assert report.clean_severity_pairs == 0


def test_kubernetes_identities_group_by_api_version_and_kind() -> None:
    """Namespaced identities drop namespace and name; cluster-scoped identities
    (no namespace component to begin with) drop only name. Segment count alone
    cannot tell the two shapes apart - `v1/Service/.../...` and
    `rbac.../v1/ClusterRoleBinding/...` are both four segments - so the
    cluster-scoped cases here are the ones that would catch a regression to
    an unconditional two-segment drop.
    """
    assert grouping_type("apps/v1/Deployment/default/web", "kubernetes") == "apps/v1/Deployment"
    assert grouping_type("batch/v1/Job/default/j [container=c]", "kubernetes") == "batch/v1/Job"
    assert grouping_type("v1/Service/default/health-check-service", "kubernetes") == "v1/Service"
    assert (
        grouping_type("rbac.authorization.k8s.io/v1/ClusterRoleBinding/superadmin", "kubernetes")
        == "rbac.authorization.k8s.io/v1/ClusterRoleBinding"
    )
    assert grouping_type("v1/Namespace/kube-system", "kubernetes") == "v1/Namespace"
    assert grouping_type("aws_s3_bucket.data", "terraform") == "aws_s3_bucket"


def test_unresolved_identities_are_excluded_entirely() -> None:
    """Exclusion happens on `identity_kind`, before grouping.

    The two findings deliberately carry *distinct* identity strings that
    still share a grouping_type (`apps/v1/Deployment`) and have differing
    issue classes: with the `identity_kind` exclusion removed, this is
    exactly one usable candidate, so a broken exclusion cannot pass by
    accident through a single-identity bucket collapsing to zero
    combinations regardless of whether the exclusion ran.
    """
    report = enumerate_candidates(
        [
            _f(
                "apps/v1/Deployment/<unresolved>/<unresolved>",
                "storage-logging-audit",
                kind="unresolved",
            ),
            _f(
                "apps/v1/Deployment/default/<unresolved>",
                "storage-encryption-at-rest",
                kind="unresolved",
            ),
        ]
    )
    assert report.considered == 0
    assert report.candidates == ()


def test_empty_input_produces_an_all_zero_report() -> None:
    report = enumerate_candidates([])
    assert report.considered == 0
    assert report.empty_difference == 0
    assert report.candidates == ()
    assert report.clean_severity_pairs == 0


def test_real_corpus_figures_are_derived_not_restated() -> None:
    """Regenerates the report from the fixtures and checks it against the headline
    figures design spec section 1 measures (249 considered, 129 empty-difference,
    120 usable candidates), so a change to the adapters or fixtures is caught here
    rather than passing silently.

    An earlier version of this test asserted
    `report.considered == report.empty_difference + len(report.candidates)`, which
    is a tautology of `enumerate_candidates`'s own control flow: every combination
    increments exactly one of the two branches, so the identity holds for any
    input whatsoever and cannot fail. Its docstring also claimed a separate
    `main()` tripwire existed to catch drift; no such test existed anywhere in
    this repository. `test_pair_candidates_artifact_matches_a_fresh_regeneration`
    below is that tripwire, added alongside this fix.
    """
    report = enumerate_candidates(real_findings())
    assert report.considered == 249
    assert report.empty_difference == 129
    assert len(report.candidates) == 120
    assert report.clean_severity_pairs == 0
    assert any(c.only_a and c.only_b for c in report.candidates)


def test_pair_candidates_artifact_matches_a_fresh_regeneration() -> None:
    """The missing tripwire: `artifacts/pair-candidates.json` compared against a
    fresh `enumerate_candidates()` run over the committed corpus v0 fixtures,
    the same discipline `tests/harvest/test_run.py`'s
    `test_the_inventory_reproduces_the_row_counts_the_fixtures_yield` applies to
    `artifacts/rule-inventory.json`. Without this, spec section 1's headline
    candidate figures (249/129/120, and the 82/21/9/7/1 class-family split) and
    the committed candidate list can drift from the fixtures that produced them
    with nothing to notice - unlike `tools/harvest/`'s output, which is pinned
    against goldens.

    Compared as sets rather than ordered lists: nothing in `enumerate_candidates`
    promises a stable candidate order across a future refactor, only a stable
    set of (grouping_type, a, b, only_a, only_b, shared) tuples.
    """
    committed = json.loads(PAIR_CANDIDATES.read_bytes())
    fresh = to_json(enumerate_candidates(real_findings()))

    assert committed["considered"] == fresh["considered"]
    assert committed["empty_difference"] == fresh["empty_difference"]
    assert committed["usable"] == fresh["usable"]
    assert committed["clean_severity_pairs"] == fresh["clean_severity_pairs"]

    def _keys(candidates: object) -> set[tuple[Any, ...]]:
        assert isinstance(candidates, list)
        return {
            (
                c["grouping_type"],
                c["a"],
                c["b"],
                tuple(c["only_a"]),
                tuple(c["only_b"]),
                c["shared"],
            )
            for c in candidates
        }

    assert _keys(committed["candidates"]) == _keys(fresh["candidates"])
