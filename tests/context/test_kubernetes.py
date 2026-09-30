from pathlib import Path

from iacrisk.context.kubernetes import build_body_index, lookup


def test_lookup_falls_back_from_a_container_identity_to_its_workload() -> None:
    """identity.kubernetes_identity renders a container-scoped finding as
    `apps/v1/Deployment/default/web [container=c]`, while this index is keyed on the
    workload alone. Measured over corpus v0 before this fallback existed: 0 of 217
    container-scoped identities matched, so every one resolved all three parsed factors
    as unresolved. A container's exposure, privilege and encryption are properties of its
    enclosing workload's spec, so reading the workload's body is correct rather than
    convenient.
    """
    index = {"apps/v1/Deployment/default/web": {"kind": "Deployment", "spec": {}}}
    assert lookup(index, "apps/v1/Deployment/default/web") is not None
    assert lookup(index, "apps/v1/Deployment/default/web [container=app]") is not None
    assert lookup(index, "apps/v1/Deployment/default/other [container=app]") is None
    assert lookup(index, "apps/v1/Deployment/default/other") is None


def test_lookup_prefers_an_exact_match_over_the_fallback() -> None:
    index = {
        "apps/v1/Deployment/default/web": {"kind": "Deployment", "marker": "workload"},
        "apps/v1/Deployment/default/web [container=app]": {"kind": "Pod", "marker": "exact"},
    }
    found = lookup(index, "apps/v1/Deployment/default/web [container=app]")
    assert found is not None and found["marker"] == "exact"


def test_the_index_is_keyed_on_canonical_kubernetes_identity(tmp_path: Path) -> None:
    """Keyed by identity.kubernetes_identity, the same function S3a's ResourceIndex
    uses, so the two agree by construction rather than by coincidence: this module
    supplies attribute values for an identity S3a already knows how to produce.
    """
    manifest = tmp_path / "svc.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: web\n"
        "  namespace: default\n"
        "spec:\n"
        "  type: LoadBalancer\n",
        encoding="utf-8",
    )
    index = build_body_index([manifest])
    assert "v1/Service/default/web" in index
    assert index["v1/Service/default/web"]["spec"]["type"] == "LoadBalancer"


def test_multi_document_yaml_is_expanded(tmp_path: Path) -> None:
    manifest = tmp_path / "multi.yaml"
    manifest.write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: a\n  namespace: ns\n"
        "---\n"
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ns\n",
        encoding="utf-8",
    )
    index = build_body_index([manifest])
    assert "v1/Service/ns/a" in index
    assert "v1/Namespace/ns" in index


def test_an_unparseable_manifest_is_skipped_not_raised(tmp_path: Path) -> None:
    """Matching terraform.build_index: one malformed manifest must not remove every
    other resource from context extraction.
    """
    good = tmp_path / "good.yaml"
    good.write_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: ok\n", encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: v1\n\tkind: [unclosed\n", encoding="utf-8")

    index = build_body_index([good, bad])
    assert len(index) == 1
    assert "v1/Service/ok" in index


def test_documents_without_the_required_metadata_are_skipped(tmp_path: Path) -> None:
    """A document with no kind, no apiVersion or no name has no canonical identity, so
    there is nothing to key it on. Skipping is the only option that does not invent one.
    """
    manifest = tmp_path / "partial.yaml"
    manifest.write_text(
        "apiVersion: v1\nkind: Service\n"
        "---\n"
        "kind: Service\nmetadata:\n  name: no-api-version\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: fine\n",
        encoding="utf-8",
    )
    index = build_body_index([manifest])
    assert list(index) == ["v1/Service/fine"]


def test_a_real_corpus_manifest_directory_yields_bodies_with_specs() -> None:
    """The one test positioned to check real-shape coverage, so it checks a real property.

    Two earlier weaknesses: it returned silently when the vendored corpus was absent, making
    a missing corpus indistinguishable from a passing check; and it asserted only that each
    body carries a `kind`, which says nothing about the `spec` that is the entire reason
    layer 3 reads bodies rather than reusing S3a's index (spec section 0.1).

    The branch's own lesson from the container-identity defect is that a real-corpus check is
    what finds shape mismatches a hand-built fixture cannot.
    """
    root = Path(__file__).resolve().parent.parent.parent / "corpus" / "vendor" / "kubernetes-goat"
    assert root.exists(), (
        f"vendored corpus missing at {root} - re-run tools/vendor_corpus.ps1 rather than "
        f"letting this check pass silently"
    )
    files = sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
    index = build_body_index(files)
    assert index, "expected at least one indexable manifest in the vendored corpus"
    assert all("kind" in body for body in index.values())

    # A spec is what layer 3 came here for. Not every kind has one (a Namespace does not),
    # so assert that the workload and service kinds that do carry it actually do.
    spec_bearing = {
        identity: body
        for identity, body in index.items()
        if body.get("kind") in {"Deployment", "Service", "Job", "Pod", "StatefulSet", "DaemonSet"}
    }
    assert spec_bearing, "expected at least one workload or service in the vendored corpus"
    missing = [i for i, b in spec_bearing.items() if not isinstance(b.get("spec"), dict)]
    assert not missing, f"spec-bearing kinds indexed without a readable spec: {missing}"
