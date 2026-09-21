"""Canonical resource identity for Terraform and Kubernetes (design spec section 5).

This is the identity the context-join (PLAN Q4) and the dedupe key (Q8) rest on.
Pure string formatting: no I/O, no scanner coupling, no parsing. Deciding whether
a value is resolvable belongs to the extractor in S3; this module's job is to
render an identity the same way every time, and to make an unresolved component
visible instead of letting it merge silently into a resolved one.
"""

from __future__ import annotations

UNRESOLVED = "<unresolved>"
"""An identity component that could not be resolved from literals.

First-class, never merged into the resolved form and never dropped. Its rate is
reported as the identity fallback rate (PLAN Q9).
"""

DEFAULT_NAMESPACE = "default"
"""Kubernetes' documented default when `metadata.namespace` is omitted.

Applied explicitly and flagged by the caller, rather than left blank - a blank
namespace component would make a namespaced resource look cluster-scoped.
"""


def normalize_path(raw: str) -> str:
    """Collapse a scanner-reported file path to one spelling (spec section 5.3).

    Checkov emits mixed separators for the same file across framework blocks -
    `\\ec2.tf` and `/ec2.tf`, `/resources\\Dockerfile` - so no single spelling per
    file can be assumed. Without this the context-join silently misses.

    Backslash translation is explicit character replacement on purpose:
    `PurePosixPath` does not treat a backslash as a separator, including on
    Windows, so a path library would leave `\\ec2.tf` intact.

    Leading separators are stripped with `lstrip`, which also folds the `//`
    form.

    Scoped to scanner-emitted relative paths. UNC and absolute paths are out of
    scope rather than handled: nothing here rejects one, so a caller that passes
    an absolute path gets a best-effort result, not a guarantee.
    """
    return raw.replace("\\", "/").lstrip("/")


def is_templated(value: str) -> bool:
    """Whether a value carries Helm interpolation and so cannot be resolved statically."""
    return "{{" in value


def _resolved(value: str) -> str:
    return UNRESOLVED if is_templated(value) else value


def _render_instance_key(key: str | int) -> str:
    """Render a `count` index or a `for_each` key.

    Integers render bare and strings render quoted, which is what keeps a count
    index `[0]` distinct from a `for_each` key `["0"]`. `bool` is rejected rather
    than accepted as an `int` subclass: `[True]` would render cleanly and read as
    though someone meant it.
    """
    if isinstance(key, bool):
        raise TypeError(f"instance key must not be a bool, got {key!r}")
    if isinstance(key, int):
        return str(key)
    if key == UNRESOLVED:
        return UNRESOLVED
    return f'"{key}"'


def terraform_identity(
    resource_type: str,
    resource_name: str,
    *,
    module_path: str = "",
    instance_key: str | int | None = None,
) -> str:
    """Canonical Terraform identity: `<module_path> :: <type>.<name> [<instance_key>]`.

    `module_path` is empty for root-module resources, which render as the bare
    `type.name` Terraform itself uses; it is only present to disambiguate
    duplicate local names across modules. `instance_key` is the `for_each` key or
    `count` index where one exists, or `UNRESOLVED` for a dynamic key the
    extractor could not evaluate.

    Corpus v0 exercises the bare form (39 resource types, no modules, no
    `for_each`, no `moved`) and exactly one static `count = 1` index. The module
    and unresolved machinery is defined for robustness and is stated as untested
    by the corpus rather than implied stressed (spec section 5.5).
    """
    address = f"{resource_type}.{resource_name}"
    if module_path:
        address = f"{module_path} :: {address}"
    if instance_key is None:
        return address
    return f"{address} [{_render_instance_key(instance_key)}]"


def kubernetes_identity(
    api_version: str,
    kind: str,
    name: str,
    *,
    namespace: str | None = None,
    container: str | None = None,
) -> str:
    """Canonical Kubernetes identity: `<apiVersion>/<kind>/<namespace>/<name> [container=...]`.

    `namespace=None` omits the component entirely, which is how cluster-scoped
    kinds are written - `Namespace`, `ClusterRoleBinding` and `ClusterPolicy` are
    all present in the corpus. A namespaced resource whose `metadata.namespace`
    was omitted should be passed `DEFAULT_NAMESPACE` explicitly by the caller,
    not `None`.

    `container` distinguishes container-scoped findings inside a multi-container
    pod or an initContainer; without it those findings would collapse onto the
    workload and dedupe would lose them.

    Helm-templated components become `UNRESOLVED` individually, so a partially
    templated resource keeps the components that did resolve.
    """
    parts = [_resolved(api_version), _resolved(kind)]
    if namespace is not None:
        parts.append(_resolved(namespace))
    parts.append(_resolved(name))
    rendered = "/".join(parts)
    if container is not None:
        rendered = f"{rendered} [container={_resolved(container)}]"
    return rendered


def dedupe_key(resource_identity: str, issue_class: str, fingerprint: str) -> tuple[str, str, str]:
    """The Q8 dedupe key (spec section 5.4).

    `(canonical resource identity, normalized issue class, violation fingerprint)`.
    The fingerprint is the specific affected attribute or config path - one IAM
    action, one security-group ingress rule, one Kubernetes container field - so
    materially different violations on one resource are not collapsed into a
    single row.

    Cross-scanner collapsing falls out of this: a trivy rule and its tfsec twin
    share a class by the section 2.2 co-location guarantee, so on one resource
    with one fingerprint they produce one key. Scanner provenance is retained as
    metadata by the caller, never as part of the key.

    Every component must be non-empty. An empty fingerprint would over-collapse
    exactly what this key exists to keep apart, and an empty identity or class
    would merge unrelated findings - so both raise rather than producing a key
    that silently under-counts.
    """
    for label, value in (
        ("resource_identity", resource_identity),
        ("issue_class", issue_class),
        ("fingerprint", fingerprint),
    ):
        if not value:
            raise ValueError(
                f"dedupe key component {label!r} is empty; an empty component would "
                "collapse findings this key exists to keep distinct"
            )
    return (resource_identity, issue_class, fingerprint)
