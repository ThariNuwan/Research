from iacrisk.finding import NormalizedFinding
from tools.paircand.generate import enumerate_candidates, grouping_type, real_findings

# `tools` is a package at the repository root and `pythonpath = ["src", "."]` in
# pyproject.toml, so this is the same import form `tests/harvest/test_run.py`
# already uses (`from tools.harvest.run import ...`). `tools/paircand/__init__.py`
# is required; a `tests/paircand/__init__.py` is not, and must not be added.


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
    assert grouping_type("apps/v1/Deployment/default/web", "kubernetes") == "apps/v1/Deployment"
    assert grouping_type("batch/v1/Job/default/j [container=c]", "kubernetes") == "batch/v1/Job"
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


def test_real_corpus_figures_are_derived_not_restated() -> None:
    """Regenerates the report from the fixtures rather than asserting the printed
    numbers directly, so a change to the adapters or fixtures is caught here
    instead of only by the separate `main()` tripwire.
    """
    report = enumerate_candidates(real_findings())
    assert report.considered == report.empty_difference + len(report.candidates)
    assert report.clean_severity_pairs == 0
    assert any(c.only_a and c.only_b for c in report.candidates)
