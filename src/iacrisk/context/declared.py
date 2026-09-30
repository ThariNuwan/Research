"""The PLAN Q4 declared-context join.

Sensitivity and criticality are not recoverable from IaC source, so they enter by
declaration. A missing declared value takes a documented default and is counted in the
default-fallback rate - which is PLAN Q4's path and is deliberately distinct from
PLAN Q9's extractor `unresolved` state. Nothing here reads tags or naming conventions;
that is S3c's, and adding it here would contaminate the primary path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from iacrisk.context.terraform import TerraformResource, attribute, is_literal, unquote
from iacrisk.context.value import FactorValue

__all__ = ["governed_target", "join", "load_declared"]

# Attachment attributes in scope, and nothing beyond them (spec section 3.1): the
# attribute naming the governed resource, and the resource type that name refers to.
_ATTACHMENTS: dict[str, tuple[str, str]] = {
    "aws_s3_bucket_policy": ("bucket", "aws_s3_bucket"),
    "aws_s3_bucket_acl": ("bucket", "aws_s3_bucket"),
    "aws_s3_bucket_public_access_block": ("bucket", "aws_s3_bucket"),
    "aws_iam_role_policy": ("role", "aws_iam_role"),
}


def load_declared(path: Path) -> dict[str, dict[str, int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"declared context at {path} is not an object")
    return data


def governed_target(resource: TerraformResource) -> str | None:
    """The canonical identity of the resource this one governs, or None.

    Returns None for a type with no attachment in scope, for an absent attribute, and
    for an interpolated value - the last because a literals-only read cannot know what
    `${var.b}` names.
    """
    entry = _ATTACHMENTS.get(resource.type)
    if entry is None:
        return None
    attr_name, target_type = entry
    raw = attribute(resource, attr_name)
    if raw is None or not is_literal(raw):
        return None
    if isinstance(raw, list):
        # python-hcl2 wraps some scalars in a one-element list. A longer list names
        # more than one target, and resolving it to the first would silently attach
        # one resource's declared context to a policy governing several.
        if len(raw) != 1:
            return None
        raw = raw[0]
    if not isinstance(raw, str):
        return None
    return f"{target_type}.{unquote(raw)}"


def join(
    identity: str,
    declared: Mapping[str, Mapping[str, int]],
    tf_index: Mapping[str, TerraformResource],
) -> tuple[FactorValue, FactorValue]:
    """Resolve (sensitivity, criticality) for one finding's resource identity.

    Exact match on canonical identity only. No fuzzy matching and no fallback to a
    shorter key, because a near-match join would attach one resource's business
    context to a different resource.
    """
    entry: Mapping[str, int] | None = declared.get(identity)
    source = identity
    if entry is None:
        resource = tf_index.get(identity)
        if resource is not None:
            target = governed_target(resource)
            if target is not None and target in declared:
                entry = declared[target]
                source = target

    if entry is None:
        reason = f"no declared-context match for {identity}"
        return (
            FactorValue.defaulted("sensitivity", reason),
            FactorValue.defaulted("criticality", reason),
        )

    evidence = f"declared context for {source}"
    values: list[FactorValue] = []
    for key in ("sensitivity", "criticality"):
        raw = entry.get(key)
        if raw is None:
            values.append(FactorValue.defaulted(key, f"{key} absent in {evidence}"))
            continue
        if not isinstance(raw, int) or isinstance(raw, bool):
            raise ValueError(f"declared {key} for {source} is not an integer: {raw!r}")
        values.append(FactorValue.resolved(key, raw, evidence))
    return (values[0], values[1])
