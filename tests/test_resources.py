"""Kubernetes identity comes from the manifests, because the scanners do not supply it.

Trivy reports no resource for Kubernetes at all and checkov omits apiVersion, so
without this index 332 findings have no identity and every checkov identity is
incomplete. The index is also where the corpus's four unparseable Helm templates
become an explicit unresolved path rather than a silent gap.

Every count here is re-derived from the corpus at test time, by a different YAML
entry point than the index uses - `yaml.safe_load_all` against the index's
`yaml.compose_all` - so a test fails when the corpus changes rather than
restating a number the index itself produced.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from iacrisk import identity
from iacrisk.input import DiscoveryResult, discover, is_manifest_document
from iacrisk.resources import CLUSTER_SCOPED_KINDS, ResourceEntry, ResourceIndex, build_index

REPO_ROOT = Path(__file__).resolve().parent.parent
K8S_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def _discovery() -> DiscoveryResult:
    return discover(K8S_ROOT)


def _index() -> ResourceIndex:
    return build_index(_discovery())


def _documents_from_corpus() -> set[tuple[str, str, str, str | None]]:
    """(relative_path, kind, name, declared namespace) for every manifest document.

    Derived with `safe_load_all`, which is not the entry point the index uses, so
    this is an independent reading of the same files rather than an echo.
    """
    found: set[tuple[str, str, str, str | None]] = set()
    for discovered in _discovery().files:
        text = discovered.path.read_text(encoding="utf-8", errors="replace")
        for doc in yaml.safe_load_all(text):
            if not is_manifest_document(doc):
                continue
            assert isinstance(doc, dict)
            metadata = doc.get("metadata") or {}
            found.add(
                (
                    discovered.relative_path,
                    str(doc["kind"]),
                    str(metadata.get("name")),
                    metadata.get("namespace"),
                )
            )
    return found


def _container_names_from_corpus() -> set[tuple[str, str]]:
    """(relative_path, container name) for every containers/initContainers entry."""
    found: set[tuple[str, str]] = set()

    def walk(node: object, relative_path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("containers", "initContainers") and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and item.get("name"):
                            found.add((relative_path, str(item["name"])))
                walk(value, relative_path)
        elif isinstance(node, list):
            for item in node:
                walk(item, relative_path)

    for discovered in _discovery().files:
        text = discovered.path.read_text(encoding="utf-8", errors="replace")
        for doc in yaml.safe_load_all(text):
            walk(doc, discovered.relative_path)
    return found


def _documents(index: ResourceIndex) -> list[ResourceEntry]:
    return [e for e in index.entries if e.container is None]


def _containers(index: ResourceIndex) -> list[ResourceEntry]:
    return [e for e in index.entries if e.container is not None]


def _enclosing_document(index: ResourceIndex, container: ResourceEntry) -> ResourceEntry:
    return next(
        e
        for e in _documents(index)
        if e.relative_path == container.relative_path
        and e.start_line <= container.start_line
        and container.end_line <= e.end_line
    )


def test_the_index_is_non_empty_and_carries_the_workload_kinds() -> None:
    """Renamed from the plan's `covers_the_parseable_manifests`: this body checks
    presence, not coverage. Coverage is the next test, against a second reading."""
    index = _index()

    assert index.entries, "index is empty"
    kinds = {e.kind for e in index.entries}
    assert {"Deployment", "Service", "Job"} <= kinds, f"missing expected kinds: {kinds}"


def test_every_manifest_document_in_the_corpus_is_indexed_exactly_once() -> None:
    """Coverage is asserted against a second reading of the corpus, not a literal."""
    index = _index()

    indexed = [(e.relative_path, e.kind, e.name) for e in _documents(index)]

    assert len(indexed) == len(set(indexed)), "a document was indexed twice"
    assert set(indexed) == {(path, kind, name) for path, kind, name, _ in _documents_from_corpus()}


def test_cluster_scoped_kinds_omit_the_namespace_component() -> None:
    """S1 spec section 5.2, first bullet, and its `S3 is what knows the kind` note.

    `Namespace`, `ClusterRoleBinding` and `ClusterPolicy` are all in the corpus.
    They are not namespaced, so they take no namespace component at all - and
    they are not `namespace_defaulted` either, because nothing was defaulted.
    """
    index = _index()

    cluster_scoped = [e for e in index.entries if e.kind in CLUSTER_SCOPED_KINDS]
    assert cluster_scoped, "corpus should contain cluster-scoped kinds"
    for entry in cluster_scoped:
        assert entry.namespace is None
        assert entry.namespace_defaulted is False
        assert entry.to_identity() == f"{entry.api_version}/{entry.kind}/{entry.name}"


def test_an_omitted_namespace_is_defaulted_and_flagged() -> None:
    """Defaulting silently would make a namespaced resource indistinguishable
    from a cluster-scoped one - the conflation S1 pinned apart."""
    index = _index()

    defaulted = [e for e in index.entries if e.namespace_defaulted]
    assert defaulted, "corpus has manifests with no metadata.namespace"
    assert all(e.namespace == identity.DEFAULT_NAMESPACE for e in defaulted)
    assert all(e.kind not in CLUSTER_SCOPED_KINDS for e in defaulted)


def test_a_declared_namespace_is_carried_through_unflagged() -> None:
    """The flag must mean `this was defaulted`, not `this says default`."""
    index = _index()
    declared = {
        (path, kind, name): namespace
        for path, kind, name, namespace in _documents_from_corpus()
        if namespace is not None
    }
    assert declared, "corpus has manifests with a declared metadata.namespace"

    for entry in _documents(index):
        key = (entry.relative_path, entry.kind, entry.name)
        if key in declared:
            assert entry.namespace == declared[key]
            assert entry.namespace_defaulted is False


def test_container_entries_exist_and_are_distinct_from_their_workload() -> None:
    index = _index()

    containers = _containers(index)
    assert containers, "no container entries indexed"
    for entry in containers:
        assert entry.container is not None
        assert f"container={entry.container}" in entry.to_identity()
        assert entry.to_identity() != _enclosing_document(index, entry).to_identity()


def test_every_container_declared_in_the_corpus_is_indexed() -> None:
    """Re-derived from the manifests: a dropped container is a lost identity."""
    index = _index()

    indexed = {(e.relative_path, e.container) for e in _containers(index)}

    assert indexed == _container_names_from_corpus()


def test_a_container_carries_its_workloads_identity_components() -> None:
    index = _index()

    for entry in _containers(index):
        document = _enclosing_document(index, entry)
        assert (entry.api_version, entry.kind, entry.namespace, entry.name) == (
            document.api_version,
            document.kind,
            document.namespace,
            document.name,
        )


def test_container_spans_nest_strictly_inside_their_workload_span() -> None:
    """The nesting the by-line tie-break depends on, checked rather than assumed."""
    index = _index()

    for entry in _containers(index):
        document = _enclosing_document(index, entry)
        assert document.start_line < entry.start_line
        assert entry.end_line <= document.end_line
        assert (entry.end_line - entry.start_line) < (document.end_line - document.start_line)


def test_by_line_returns_the_innermost_match() -> None:
    """Spans nest workload-to-container, so the container must win (spec 4).

    Returning the workload for a container's line would collapse every container
    finding onto its parent and lose the [container=...] component.
    """
    index = _index()
    container = next(e for e in index.entries if e.container)

    found = index.by_line(container.relative_path, container.start_line)

    assert found is not None
    assert found.container == container.container


def test_every_line_of_every_container_span_resolves_to_that_container() -> None:
    """Demonstrated over every indexed container line, not argued from one case.

    `internal-proxy` declares two containers in one pod, so this also shows a
    line does not leak from one sibling container into the other.
    """
    index = _index()

    for entry in _containers(index):
        for line in range(entry.start_line, entry.end_line + 1):
            found = index.by_line(entry.relative_path, line)
            assert found is not None, f"{entry.relative_path}:{line} resolved to nothing"
            assert found.container == entry.container, (
                f"{entry.relative_path}:{line} resolved to {found.container!r}, "
                f"expected {entry.container!r}"
            )


def test_a_workload_line_outside_its_container_block_resolves_to_the_document() -> None:
    """The other direction: innermost must not mean `always the container`."""
    index = _index()

    checked = 0
    for entry in _containers(index):
        document = _enclosing_document(index, entry)
        found = index.by_line(document.relative_path, document.start_line)
        assert found is not None
        assert found.container is None, f"{document.relative_path} line 1 gave a container"
        assert found.name == document.name
        checked += 1
    assert checked, "no container/document pair to check"


def test_by_line_outside_every_span_is_none_not_the_nearest() -> None:
    """A guess presented as a lookup is worse than an explicit unresolved.

    The third case is the one that separates the two behaviours: a file whose
    first document starts below line 1 opens with a comment block belonging to
    no entry, and an implementation that answered with the nearest document
    would return that file's first document for it.
    """
    index = _index()

    assert index.by_line("no/such/file.yaml", 1) is None
    assert index.by_line(index.entries[0].relative_path, 10_000) is None

    first_line_of: dict[str, int] = {}
    for entry in _documents(index):
        first_line_of[entry.relative_path] = min(
            entry.start_line, first_line_of.get(entry.relative_path, entry.start_line)
        )
    with_preamble = [path for path, line in first_line_of.items() if line > 1]
    assert with_preamble, "corpus should contain a manifest with a leading comment block"
    for path in with_preamble:
        assert index.by_line(path, 1) is None


def test_by_address_resolves_a_kind_namespace_name_address() -> None:
    """Checkov's address shape: Kind.namespace.name, with no apiVersion."""
    index = _index()
    workload = next(e for e in _documents(index) if e.kind == "Deployment")

    found = index.by_address(workload.kind, workload.namespace, workload.name)

    assert found is not None
    assert found.name == workload.name
    assert found.api_version, "apiVersion is what the index adds over checkov's address"


def test_by_address_reaches_a_container_through_the_optional_component() -> None:
    index = _index()
    container = _containers(index)[0]

    found = index.by_address(
        container.kind, container.namespace, container.name, container.container
    )

    assert found is not None
    assert found.container == container.container


def test_by_address_without_a_container_never_returns_a_container_entry() -> None:
    """Otherwise a workload address could silently acquire a container component."""
    index = _index()

    for entry in _containers(index):
        found = index.by_address(entry.kind, entry.namespace, entry.name)
        assert found is not None
        assert found.container is None


def test_by_address_round_trips_a_cluster_scoped_entry_addressed_with_none() -> None:
    """The `namespace=None` half of the address space, otherwise never called.

    Every other `by_address` test here passes a namespaced workload or
    container, so nothing would fail if `None` stopped matching - if a caller
    normalized it to `""`, or if `namespace` were narrowed back to `str`. That
    is the one address shape a cluster-scoped kind has.
    """
    index = _index()
    cluster_scoped = [e for e in index.entries if e.kind in CLUSTER_SCOPED_KINDS]
    assert cluster_scoped, "corpus should contain cluster-scoped kinds"

    for entry in cluster_scoped:
        found = index.by_address(entry.kind, None, entry.name)

        assert found is not None, f"{entry.kind}/{entry.name} is unaddressable"
        assert found == entry
        assert found.to_identity() == f"{entry.api_version}/{entry.kind}/{entry.name}"
        assert f"/{identity.DEFAULT_NAMESPACE}/" not in found.to_identity()


def test_by_address_that_matches_nothing_is_none() -> None:
    index = _index()

    assert index.by_address("Deployment", "default", "no-such-workload") is None


def test_addresses_repeated_across_files_agree_on_identity() -> None:
    """The corpus declares one address in two files; by_address returns one entry.

    The duplicates differ only in file and span, so the identity by_address
    yields is well-defined even where the file it came from is not - which is
    what the docstring on by_address states, checked here rather than assumed.
    """
    index = _index()
    by_address: dict[tuple[str, str | None, str, str | None], list[ResourceEntry]] = {}
    for entry in index.entries:
        by_address.setdefault(
            (entry.kind, entry.namespace, entry.name, entry.container), []
        ).append(entry)

    repeated = [group for group in by_address.values() if len(group) > 1]
    assert repeated, "corpus should contain at least one repeated address"
    for group in repeated:
        assert len({e.to_identity() for e in group}) == 1


def test_unparseable_files_are_recorded_and_yield_no_entries() -> None:
    """The four Helm templates: findings landing there take <unresolved>."""
    index = _index()

    assert index.unparseable, "unparseable files should be recorded"
    assert all("metadata-db" in p for p in index.unparseable)
    for path in index.unparseable:
        assert index.by_line(path, 1) is None


def test_unparseable_carries_discoverys_finding_through() -> None:
    """The index must not quietly re-classify what discovery could not parse.

    Equality, not containment: `build_index` may add a file of its own where
    composing fails, and over this corpus it adds none - `compose` is a
    sub-stage of the load discovery performs, so it cannot fail where that
    succeeded. A path appearing here that discovery did not report would mean
    that reasoning no longer holds.
    """
    discovery = _discovery()
    index = build_index(discovery)

    assert set(discovery.unparseable) == set(index.unparseable)
    indexed_paths = {e.relative_path for e in index.entries}
    assert not (indexed_paths & set(index.unparseable))


def test_to_identity_matches_the_s1_formatter() -> None:
    """The index must not invent its own identity spelling - on either entry shape."""
    index = _index()

    for entry in index.entries:
        assert entry.to_identity() == identity.kubernetes_identity(
            entry.api_version,
            entry.kind,
            entry.name,
            namespace=entry.namespace,
            container=entry.container,
        )
