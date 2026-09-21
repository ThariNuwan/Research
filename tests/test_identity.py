"""Identity is defined for every resource shape corpus v0 actually contains (spec 5.5).

Path normalization is the load-bearing piece: Checkov emits mixed separators for
the same file across framework blocks, so without it the context-join silently
misses - and a silent miss is the worst failure mode available here.
"""

from __future__ import annotations

import pytest

from iacrisk import identity, taxonomy


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("\\ec2.tf", "ec2.tf"),  # checkov's backslash spelling
        ("/ec2.tf", "ec2.tf"),  # checkov's forward-slash spelling of the same file
        ("ec2.tf", "ec2.tf"),  # and the bare one
        ("/resources\\Dockerfile", "resources/Dockerfile"),  # mixed in one path
        ("\\resources\\db\\main.tf", "resources/db/main.tf"),
        ("//double.tf", "double.tf"),
        ("", ""),
    ],
)
def test_normalize_path_collapses_every_observed_spelling(raw: str, expected: str) -> None:
    """Spec section 5.3: replace backslashes explicitly, then strip the leading separator.

    PurePosixPath does not translate backslashes on Windows, which is exactly why
    this is character replacement rather than a path-library call.
    """
    assert identity.normalize_path(raw) == expected


def test_the_three_observed_spellings_of_one_file_converge() -> None:
    """The property that matters: no single spelling per file can be assumed."""
    spellings = ["\\ec2.tf", "/ec2.tf", "ec2.tf"]

    assert len({identity.normalize_path(spelling) for spelling in spellings}) == 1


def test_terraform_root_module_resource_is_the_bare_address() -> None:
    """The shape the entire TF corpus exercises: 39 resource types, no modules."""
    assert identity.terraform_identity("aws_s3_bucket", "data") == "aws_s3_bucket.data"


def test_terraform_count_index_is_rendered_unquoted() -> None:
    """The one instance-key case in corpus v0: aws_neptune_cluster_instance.default."""
    result = identity.terraform_identity("aws_neptune_cluster_instance", "default", instance_key=0)

    assert result == "aws_neptune_cluster_instance.default [0]"


def test_terraform_for_each_key_is_rendered_quoted() -> None:
    """Quoting is what keeps count index 0 distinct from for_each key "0"."""
    counted = identity.terraform_identity("aws_s3_bucket", "b", instance_key=0)
    keyed = identity.terraform_identity("aws_s3_bucket", "b", instance_key="0")

    assert counted == "aws_s3_bucket.b [0]"
    assert keyed == 'aws_s3_bucket.b ["0"]'
    assert counted != keyed


def test_terraform_module_path_disambiguates_duplicate_local_names() -> None:
    """Not exercised by corpus v0 - defined for robustness, and stated as such."""
    result = identity.terraform_identity("aws_s3_bucket", "data", module_path="module.storage")

    assert result == "module.storage :: aws_s3_bucket.data"


def test_terraform_unresolvable_instance_key_is_explicit() -> None:
    """Spec section 5.1: never silently merged into the un-keyed identity."""
    result = identity.terraform_identity("aws_instance", "web", instance_key=identity.UNRESOLVED)

    assert result == "aws_instance.web [<unresolved>]"
    assert result != identity.terraform_identity("aws_instance", "web")


def test_terraform_boolean_instance_key_is_rejected() -> None:
    """bool subclasses int; left alone it would render `[True]` and look deliberate."""
    with pytest.raises(TypeError, match="bool"):
        identity.terraform_identity("aws_s3_bucket", "b", instance_key=True)


def test_kubernetes_namespaced_identity() -> None:
    assert (
        identity.kubernetes_identity("apps/v1", "Deployment", "api", namespace="prod")
        == "apps/v1/Deployment/prod/api"
    )


@pytest.mark.parametrize("kind", ["Namespace", "ClusterRoleBinding", "ClusterPolicy"])
def test_kubernetes_cluster_scoped_kinds_omit_the_namespace_component(kind: str) -> None:
    """All three are present in the kubernetes-goat scenarios (spec section 5.5)."""
    result = identity.kubernetes_identity("v1", kind, "big-monolith")

    assert result == f"v1/{kind}/big-monolith"
    assert "//" not in result


def test_kubernetes_container_scoped_identity() -> None:
    """internal-proxy has two containers; health-check has an initContainer too."""
    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
    )

    assert result == "apps/v1/Deployment/default/internal-proxy [container=nginx]"


def test_two_containers_in_one_pod_get_distinct_identities() -> None:
    """Without the container component the multi-container pod collapses to one row."""
    first = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
    )
    second = identity.kubernetes_identity(
        "apps/v1", "Deployment", "internal-proxy", namespace="default", container="proxy"
    )

    assert first != second


def test_kubernetes_omitted_namespace_uses_the_documented_default() -> None:
    """Spec section 5.2: an omitted metadata.namespace takes the documented default."""
    assert identity.DEFAULT_NAMESPACE == "default"

    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "api", namespace=identity.DEFAULT_NAMESPACE
    )

    assert result == "apps/v1/Deployment/default/api"


@pytest.mark.parametrize(
    "value",
    ["{{ .Release.Name }}", "{{ .Release.Name }}-db", "prefix-{{ .Values.env }}"],
)
def test_is_templated_detects_helm_interpolation(value: str) -> None:
    assert identity.is_templated(value)


@pytest.mark.parametrize("value", ["metadata-db", "default", "nginx", ""])
def test_is_templated_is_precise_not_merely_wide(value: str) -> None:
    assert not identity.is_templated(value)


def test_kubernetes_helm_templated_components_become_unresolved() -> None:
    """The metadata-db scenario: the K8s analogue of the TF dynamic-key case (5.2)."""
    result = identity.kubernetes_identity(
        "apps/v1",
        "Deployment",
        "{{ .Release.Name }}-metadata-db",
        namespace="{{ .Release.Namespace }}",
        container="{{ .Chart.Name }}",
    )

    assert result == "apps/v1/Deployment/<unresolved>/<unresolved> [container=<unresolved>]"


def test_a_partially_templated_resource_keeps_the_components_it_resolved() -> None:
    """Marking the whole identity unresolved would throw away real information."""
    result = identity.kubernetes_identity(
        "apps/v1", "Deployment", "{{ .Release.Name }}-db", namespace="prod"
    )

    assert result == "apps/v1/Deployment/prod/<unresolved>"


def test_dedupe_key_is_the_three_spec_components() -> None:
    """Spec section 5.4: (resource identity, normalized issue class, fingerprint)."""
    key = identity.dedupe_key(
        "aws_s3_bucket.data", "storage-encryption-at-rest", "server_side_encryption_configuration"
    )

    assert key == (
        "aws_s3_bucket.data",
        "storage-encryption-at-rest",
        "server_side_encryption_configuration",
    )


def test_cross_scanner_twins_on_one_resource_collapse_to_one_key() -> None:
    """The deduplication half of the Q7/Q8 alert-reduction number.

    The two scanners emit different rule ids for the same Aqua rule, so the
    collapse cannot come from this key alone - it comes from the taxonomy mapping
    both ids to one class (the section 2.2 co-location guarantee), and from this
    key carrying the class rather than the rule id. Deriving each class from its
    own scanner's rule id is what makes this a real check: passing the same class
    string twice by hand would assert nothing but that equal inputs compare equal.

    This is the necessary condition, not the whole claim. Demonstrating that two
    scanners' actual output for one violation produces matching triples needs a
    caller that computes the fingerprint, which is S3's job.
    """
    trivy_class = taxonomy.class_for("trivy", "AWS-0026")
    tfsec_class = taxonomy.class_for("tfsec", "AVD-AWS-0026")

    assert trivy_class == tfsec_class == "storage-encryption-at-rest"

    trivy = identity.dedupe_key("aws_s3_bucket.data", trivy_class, "sse")
    tfsec = identity.dedupe_key("aws_s3_bucket.data", tfsec_class, "sse")

    assert trivy == tfsec
    assert len({trivy, tfsec}) == 1


def test_different_violations_on_one_resource_stay_distinct() -> None:
    """The fingerprint is what stops two real problems collapsing into one row."""
    first = identity.dedupe_key(
        "aws_security_group.web", "networking-ingress-exposure", "ingress[0]"
    )
    second = identity.dedupe_key(
        "aws_security_group.web", "networking-ingress-exposure", "ingress[1]"
    )

    assert first != second


@pytest.mark.parametrize("position", [0, 1, 2])
def test_an_empty_dedupe_component_is_rejected(position: int) -> None:
    """No component may be empty; the parametrize covers all three positions.

    An empty fingerprint would collapse materially different violations on one
    resource, and an empty identity or class would merge unrelated findings -
    both are the over-collapse this key exists to prevent.
    """
    parts = ["aws_s3_bucket.data", "storage-encryption-at-rest", "sse"]
    parts[position] = ""

    with pytest.raises(ValueError, match="empty"):
        identity.dedupe_key(*parts)
