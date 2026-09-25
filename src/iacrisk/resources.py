"""The Kubernetes resource index (design spec §4).

Kubernetes identity has to be read out of the manifests because the scanners do
not supply it. Measured on the committed fixtures: trivy reports no resource for
Kubernetes at all (0 of 332 findings) and states it only in prose, leaving a file
and a start line as the only structured handle; checkov reports
`Kind.namespace.name`, which is S1's Kubernetes identity minus the `apiVersion`
component it leads with. So this module parses the manifests once and offers the
two lookups those two shapes can actually reach: by file and line, and by kind,
namespace and name.

Three states are kept explicit rather than collapsed, because each collapse
would be invisible downstream:

- **Cluster-scoped kinds take no namespace component** and namespaced documents
  whose `metadata.namespace` is absent take `identity.DEFAULT_NAMESPACE` with
  `namespace_defaulted` set. S1 §5.2 defines both outcomes and
  `tests/test_identity.py::test_kubernetes_namespace_none_omits_the_component`
  records that the choice between them belongs to whoever knows the kind. This
  module is what knows the kind, so it is where the choice is made.
- **The innermost span wins a by-line lookup.** A container's lines fall inside
  its workload's, so a line that matches both resolves to the container. The
  workload would otherwise absorb every container-scoped finding and the
  `[container=…]` component would never be produced at all.
- **A line matching no span returns `None`.** Not the nearest document: the
  nearest document is a guess, and a guess returned from a lookup is
  indistinguishable from a fact.

A file that fails to parse yields no entries and is listed in
`ResourceIndex.unparseable`, so the absence is addressable rather than silent.
Corpus v0's four `metadata-db/templates/` Helm templates are that case.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import yaml

from iacrisk import identity
from iacrisk.input import DiscoveryResult, is_manifest_document

CONTAINER_KEYS = ("containers", "initContainers")
"""The mapping keys whose sequence items are container definitions.

Structural rather than path-anchored: any mapping carrying one of these keys is
treated as a pod spec, so `spec.containers` (a bare Pod), a workload's
`spec.template.spec.containers` and a CronJob's deeper nesting are all reached
without enumerating paths. Measured on corpus v0 this yields exactly the 17
container names the manifests declare, with no false positive from the kyverno
`ClusterPolicy` also present there.
"""

CLUSTER_SCOPED_KINDS = frozenset({"Namespace", "ClusterRoleBinding", "ClusterPolicy"})
"""Kinds whose identity carries no namespace component.

These three, and no more, are what S1 §5.2 names and §5.5 confirms present in
the corpus; `tests/test_identity.py` parametrizes the formatter over the same
three. Closed on purpose, like `finding.IDENTITY_KINDS`: this is not the
complete set of cluster-scoped Kubernetes kinds, and it is not derivable from a
manifest, since a cluster-scoped document and a namespaced one that omits its
namespace look identical on disk. A cluster-scoped kind outside this set is
therefore indexed as namespaced-and-defaulted - wrong, but flagged
(`namespace_defaulted`) rather than silent, and correctable by one edit here.
"""


@dataclass(frozen=True)
class ResourceEntry:
    """One indexed manifest document, or one container within one.

    A container entry repeats its workload's `api_version`, `kind`, `namespace`
    and `name` and adds `container`, so it renders as the workload's identity
    with the `[container=…]` component appended - which is what keeps two
    containers in one pod from sharing an identity.

    `namespace` is `None` only for a cluster-scoped kind. `namespace_defaulted`
    says the namespace was absent from the manifest and `DEFAULT_NAMESPACE` was
    applied here; the two fields together distinguish three of the four states
    a manifest can be in (declared, defaulted, not namespaced at all) - **not**
    all four. A templated, still-Helm-unresolved namespace (`namespace: "{{
    .Release.Namespace }}"`) is a fourth: it is neither absent (so
    `namespace_defaulted` is `False`) nor a genuine declared value, and
    `identity.kubernetes_identity` renders it as the `identity.UNRESOLVED`
    component rather than the literal template string - a distinction these two
    fields alone do not carry (whole-branch review Finding 1's docstring
    correction; the value itself is caught downstream by
    `identity.is_unusable`, which is what `dedupe.py` and the adapters key
    unresolved-identity handling off of, not this dataclass's own fields).

    `start_line` and `end_line` are 1-based and inclusive, and span only the
    content of the document or container - leading comments, the `---` separator
    and trailing blank lines belong to no entry.
    """

    api_version: str
    kind: str
    namespace: str | None
    name: str
    container: str | None
    start_line: int
    end_line: int
    relative_path: str
    namespace_defaulted: bool

    def to_identity(self) -> str:
        """Render this entry through S1's formatter, which owns the spelling."""
        return identity.kubernetes_identity(
            self.api_version,
            self.kind,
            self.name,
            namespace=self.namespace,
            container=self.container,
        )


class ResourceIndex:
    """Indexed manifests plus the files that could not be parsed into any.

    `entries` is ordered: files in discovery order, documents in the order they
    appear in each file, each document immediately followed by its containers in
    declaration order.
    """

    def __init__(self, entries: tuple[ResourceEntry, ...], unparseable: tuple[str, ...]) -> None:
        self.entries = entries
        self.unparseable = unparseable

    def by_line(self, relative_path: str, line: int) -> ResourceEntry | None:
        """The innermost entry whose span contains `line`, or `None`.

        Container spans sit inside workload spans, so the narrowest match wins;
        returning the workload would drop the container component. Documents
        within a file do not nest - multi-document YAML is sequential - so a
        container against its own workload is the only nesting this resolves.

        The second sort key only makes the order total. A container span is
        strictly narrower than its workload's, which always also covers the
        `apiVersion`, `kind` and `metadata` lines outside the pod spec, so the tie
        it breaks does not arise in corpus v0; without it the result would fall
        back to insertion order, which is not a stated guarantee.

        One tie has no principled winner: containers written as a flow sequence
        on one physical line - `containers: [{name: a}, {name: b}]` - have
        identical spans, and a line is genuinely ambiguous between them. The
        first in `entries` order is returned, which is declaration order and
        nothing more; do not read it as a choice. Corpus v0 writes every
        container as a block sequence, so this shape is described here rather
        than exercised.

        `None` means no span contains the line - an unparseable file, a line in
        a leading comment block, or a file that is not a manifest at all. It is
        never the nearest entry.
        """
        matches = [
            e
            for e in self.entries
            if e.relative_path == relative_path and e.start_line <= line <= e.end_line
        ]
        if not matches:
            return None
        return min(matches, key=lambda e: (e.end_line - e.start_line, e.container is None))

    def by_address(
        self, kind: str, namespace: str | None, name: str, container: str | None = None
    ) -> ResourceEntry | None:
        """The entry at `kind`/`namespace`/`name`, optionally narrowed to a container.

        `namespace` is matched as stored, so a cluster-scoped entry is addressed
        with `None` and a document whose namespace was defaulted is addressed
        with `identity.DEFAULT_NAMESPACE`. `container=None` matches the document
        entry itself and never a container within it, so a workload address
        cannot silently acquire a container component.

        An address is not unique across files: corpus v0 indexes
        `Service/default/health-check-service` from two of them. Entries repeating
        an address agree on every identity component and differ only in
        `relative_path` and span, so the identity this returns is well-defined
        where the file it came from is not. The first match in `entries` order
        is returned, which makes that choice deterministic rather than correct.
        """
        for entry in self.entries:
            if (
                entry.kind == kind
                and entry.namespace == namespace
                and entry.name == name
                and entry.container == container
            ):
                return entry
        return None


def _mapping_value(node: yaml.Node | None, key: str) -> yaml.Node | None:
    """The value node for `key` in a mapping node, or `None`."""
    if not isinstance(node, yaml.MappingNode):
        return None
    pairs: list[tuple[yaml.Node, yaml.Node]] = node.value
    for key_node, value_node in pairs:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            return value_node
    return None


def _scalar(node: yaml.Node | None, key: str) -> str | None:
    """The scalar value for `key` in a mapping node, or `None` if absent or not scalar."""
    value = _mapping_value(node, key)
    if not isinstance(value, yaml.ScalarNode):
        return None
    return str(value.value)


def _mark_line(mark: yaml.error.Mark) -> int:
    """The 1-based line an end mark points just past the end of.

    Marks are 0-based and end marks are exclusive, but their column decides what
    the exclusive position means: a mark at column 0 sits at the start of the
    line after the content, so the content ended on the previous line, which is
    `line` once 1-based; a mark past column 0 sits on the content's own last
    line, which is `line + 1`.
    """
    return mark.line if mark.column == 0 else mark.line + 1


def _last_content_line(node: yaml.Node) -> int:
    """The 1-based last line this node's content occupies.

    Read from the deepest scalars rather than from the node's own `end_mark`,
    because a block collection's end mark is set where the parser stopped, which
    is the *start of the next token* and so can be a line the node does not own.
    Measured: in `docker-bench-security/deployment.yaml` the `initContainers`
    item ends at the `containers:` key on the following line, and trusting that
    mark would overlap the next container's span. A scalar's end mark is exact,
    so the deepest ones bound the node honestly.
    """
    if isinstance(node, yaml.ScalarNode):
        return _mark_line(node.end_mark)
    if isinstance(node, yaml.MappingNode):
        children = [child for pair in node.value for child in pair]
    elif isinstance(node, yaml.SequenceNode):
        children = list(node.value)
    else:  # pragma: no cover - compose_all yields only the three node types
        children = []
    if not children:
        return _mark_line(node.end_mark)
    return max(_last_content_line(child) for child in children)


def _container_nodes(node: yaml.Node) -> Iterator[tuple[str, yaml.Node]]:
    """Every `(container name, container node)` reachable under `node`.

    A container is a mapping item of a `containers` or `initContainers`
    sequence that carries a scalar `name`. An item without one is skipped: it
    has no container component to contribute, and inventing one would be worse
    than leaving the finding on the workload.
    """
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            if (
                isinstance(key_node, yaml.ScalarNode)
                and key_node.value in CONTAINER_KEYS
                and isinstance(value_node, yaml.SequenceNode)
            ):
                for item in value_node.value:
                    name = _scalar(item, "name")
                    if name is not None:
                        yield name, item
            yield from _container_nodes(value_node)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from _container_nodes(item)


def _entries_for_document(document: yaml.Node, relative_path: str) -> list[ResourceEntry]:
    """One entry for the document plus one per container, or none if it is not a manifest."""
    api_version = _scalar(document, "apiVersion")
    kind = _scalar(document, "kind")
    if api_version is None or kind is None:
        return []
    if not is_manifest_document({"apiVersion": api_version, "kind": kind}):
        return []

    metadata = _mapping_value(document, "metadata")
    # A manifest with no readable `metadata.name` is indexed as unresolved rather
    # than dropped, so it still occupies a span and still answers a lookup. Corpus
    # v0 has no such document, so this is a stated fallback, not a measured one.
    name = _scalar(metadata, "name") or identity.UNRESOLVED

    declared_namespace = _scalar(metadata, "namespace")
    namespace: str | None
    if kind in CLUSTER_SCOPED_KINDS:
        namespace, namespace_defaulted = None, False
    elif declared_namespace is None:
        namespace, namespace_defaulted = identity.DEFAULT_NAMESPACE, True
    else:
        namespace, namespace_defaulted = declared_namespace, False

    def entry(container: str | None, start: int, end: int) -> ResourceEntry:
        return ResourceEntry(
            api_version=api_version,
            kind=kind,
            namespace=namespace,
            name=name,
            container=container,
            start_line=start,
            end_line=end,
            relative_path=relative_path,
            namespace_defaulted=namespace_defaulted,
        )

    entries = [
        entry(None, document.start_mark.line + 1, _last_content_line(document)),
    ]
    entries.extend(
        entry(container, node.start_mark.line + 1, _last_content_line(node))
        for container, node in _container_nodes(document)
    )
    return entries


def build_index(discovery: DiscoveryResult) -> ResourceIndex:
    """Index every Kubernetes file `discovery` found, carrying its unparseable list through.

    Parsing goes through `yaml.compose_all`, whose nodes carry the line marks the
    by-line lookup needs; `is_manifest_document` decides what counts as a
    manifest document, so this module does not hold a second opinion about that.

    A file that discovery parsed but composing rejects is added to `unparseable`
    rather than raised, so one malformed manifest cannot take the whole index
    down. Composing is a strictly earlier stage than the loading discovery does,
    so corpus v0 never exercises this - it is stated as defensive, not measured.
    """
    entries: list[ResourceEntry] = []
    unparseable: list[str] = list(discovery.unparseable)

    for discovered in discovery.files:
        if discovered.platform != "kubernetes":
            continue
        text = discovered.path.read_text(encoding="utf-8", errors="replace")
        try:
            documents = list(yaml.compose_all(text))
        except yaml.YAMLError:
            if discovered.relative_path not in unparseable:
                unparseable.append(discovered.relative_path)
            continue
        for document in documents:
            if document is None:
                continue
            entries.extend(_entries_for_document(document, discovered.relative_path))

    return ResourceIndex(entries=tuple(entries), unparseable=tuple(unparseable))
