"""Reading Kubernetes manifest bodies for layer 3.

S3a's `resources.ResourceIndex` resolves a finding's *identity* from a file and line,
and deliberately carries no attribute values - `ResourceEntry` holds api_version, kind,
namespace, name, container and line spans, and nothing of the spec. Layer 3 needs the
spec itself (a Service's `type`, an RBAC `rules` block), so this module reads bodies.

It does not extend or replace S3a's index. Both key on `identity.kubernetes_identity`,
so the two agree by construction rather than by coincidence: this module supplies
attribute values for an identity S3a's index already knows how to produce.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from iacrisk.identity import kubernetes_identity

__all__ = ["build_body_index", "lookup"]

_CONTAINER_SUFFIX = " [container="


def lookup(
    index: Mapping[str, Mapping[str, Any]], resource_identity: str
) -> Mapping[str, Any] | None:
    """The body for an identity, falling back to the enclosing workload for a container.

    `identity.kubernetes_identity` renders a container-scoped finding as
    `apps/v1/Deployment/default/web [container=c]`, while this index is keyed on the
    workload alone. Without stripping that suffix every container-scoped finding misses
    the index and resolves all three parsed factors as unresolved.

    Measured over corpus v0 before this fallback existed: **0 of 217** container-scoped
    identities matched. A container's exposure, privilege and encryption are properties of
    its enclosing workload's spec, so reading the workload's body is the correct answer
    rather than a convenience.
    """
    direct = index.get(resource_identity)
    if direct is not None:
        return direct
    marker = resource_identity.find(_CONTAINER_SUFFIX)
    if marker == -1:
        return None
    return index.get(resource_identity[:marker])


def build_body_index(files: Iterable[Path]) -> dict[str, dict[str, Any]]:
    """Map canonical Kubernetes identity to the manifest document body.

    Multi-document YAML is expanded, and a document that will not parse is skipped
    rather than raised, matching `terraform.build_index`: one malformed manifest must
    not remove every other resource from context extraction.

    Container-scoped identities are not emitted here. A finding on a container resolves
    its exposure and privilege from the enclosing workload's body, which this index
    already holds under the workload's own identity.
    """
    index: dict[str, dict[str, Any]] = {}
    for path in files:
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError):
            continue
        for document in documents:
            if not isinstance(document, dict):
                continue
            api_version = document.get("apiVersion")
            kind = document.get("kind")
            metadata = document.get("metadata")
            if not isinstance(api_version, str) or not isinstance(kind, str):
                continue
            if not isinstance(metadata, dict):
                continue
            name = metadata.get("name")
            if not isinstance(name, str):
                continue
            namespace = metadata.get("namespace")
            resource_identity = kubernetes_identity(
                api_version,
                kind,
                name=name,
                namespace=namespace if isinstance(namespace, str) else None,
            )
            index[resource_identity] = document
    return index
