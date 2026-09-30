"""Public exposure, resolved only over PLAN Q9's closed supported-pattern list.

Exposure is the one factor whose unresolved policy is `sensitivity-analysed` rather than
conservative-scored: unresolved routes to 3 in the frozen primary model, and S5 sweeps
[2, 5].

**Exposure is inbound reachability.** An egress opening to 0.0.0.0/0 is not inbound and
does not trigger the precedence rule - egress risk belongs to the taxonomy class
`networking-egress-exposure`, which spec section 1.4 records as mapping to no rubric
factor at all. Measured against corpus-v1's networking scenario, which places
`sgr-egress-unrestricted` in its bottom tier despite a literal 0.0.0.0/0: reading egress
as inbound would force that case to 4 and invert the scenario's expected ordering.

**Resolved-negative is not unresolved.** A resource the pattern list covers, read from
literals, with no opening found, resolves to a low level - the extractor looked and
found nothing. Unresolved is for a covered pattern whose value is interpolated, or a
reachability mechanism outside the list entirely. Collapsing the two would route a
security group with no ingress rules to the unresolved default of 3, which the same
scenario places below its interpolated case.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

from iacrisk.context.kubernetes import lookup as k8s_lookup
from iacrisk.context.terraform import (
    TerraformResource,
    attribute,
    is_literal,
    resource_reference,
    unquote,
)
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding

__all__ = ["ANY_SOURCE_CIDRS", "extract", "is_public_cidr"]

ANY_SOURCE_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

_PUBLIC_FLAGS = ("publicly_accessible", "associate_public_ip_address", "map_public_ip_on_launch")

_PAB_BLOCKING_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

_PUBLIC_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})

_KUBERNETES_SERVICE_LEVELS = {
    # NodePort is 2 by ruling (spec section 4.5): the rubric's level-2 text conditions on
    # "exposed only through a node firewall", which no manifest reveals. Marking it
    # unresolved would be worse - a NodePort is internet-reachable in principle, and
    # unresolved routes to 3, a level the rubric reserves for identity-gated endpoints.
    "NodePort": (2, "Service type NodePort; node-firewall mediation assumed, not verifiable"),
    "LoadBalancer": (3, "Service type LoadBalancer publishes the service externally"),
    "ClusterIP": (1, "Service type ClusterIP is reachable within the cluster only"),
    "ExternalName": (1, "Service type ExternalName creates no inbound listener"),
}


def is_public_cidr(cidr: str) -> bool:
    """True when `cidr` is internet-routable. Malformed input is not public."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return not network.is_private


def _cidr_level(cidrs: list[str]) -> tuple[int, str]:
    """(level, evidence) from a literal ingress CIDR list, per spec section 4.5.

    No invented prefix-length threshold: any public non-RFC1918 CIDR with a non-zero
    prefix is 2, and an any-source opening is 4 by the precedence rule.
    """
    any_source = sorted(set(cidrs) & ANY_SOURCE_CIDRS)
    if any_source:
        return 4, f"any-source ingress opening {any_source}"
    public = [c for c in cidrs if is_public_cidr(c)]
    if public:
        return 2, f"narrow public ingress CIDR {public}"
    if cidrs:
        return 1, f"RFC1918-only ingress {sorted(cidrs)}"
    return 0, "no ingress CIDR present"


def _literal_cidrs(raw: object) -> list[str] | None:
    """Flatten a literal cidr_blocks value, or None when it is not literal."""
    if not is_literal(raw):
        return None
    if isinstance(raw, str):
        return [unquote(raw)]
    if isinstance(raw, (list, tuple)):
        out: list[str] = []
        for item in raw:
            if isinstance(item, str):
                out.append(unquote(item))
        return out
    return None


def _truthy(raw: object) -> bool | None:
    """A literal boolean, or None when the value is not a readable literal."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        text = unquote(raw).strip().lower()
        if text in {"true", "1"}:
            return True
        if text in {"false", "0"}:
            return False
    return None


def _security_group_rule(resource: TerraformResource) -> tuple[int | None, str]:
    rule_type = attribute(resource, "type")
    if rule_type is None or not is_literal(rule_type):
        return None, "security-group rule type is not a literal"
    direction = unquote(str(rule_type)).strip().lower()
    if direction == "egress":
        return (
            0,
            "egress rule: exposure is inbound reachability, and egress risk maps to "
            "networking-egress-exposure, which no rubric factor covers (spec 1.4)",
        )
    if direction != "ingress":
        return None, f"unrecognised security-group rule type {direction!r}"
    cidrs = _literal_cidrs(attribute(resource, "cidr_blocks"))
    if cidrs is None:
        return None, "ingress cidr_blocks is interpolated, not a literal"
    level, evidence = _cidr_level(cidrs)
    return level, evidence


def _security_group(resource: TerraformResource) -> tuple[int | None, str]:
    raw_ingress = attribute(resource, "ingress")
    if raw_ingress is None:
        return 0, "security group declares no ingress block"
    blocks: list[Any] = list(raw_ingress) if isinstance(raw_ingress, list) else [raw_ingress]
    collected: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        cidrs = _literal_cidrs(block.get("cidr_blocks"))
        if cidrs is None:
            return None, "an ingress block's cidr_blocks is interpolated, not a literal"
        collected.extend(cidrs)
    level, evidence = _cidr_level(collected)
    return level, f"{evidence} across {len(blocks)} ingress block(s)"


def _public_flag(resource: TerraformResource) -> tuple[int | None, str] | None:
    """Pattern 2. None when the resource carries no public flag at all."""
    for flag in _PUBLIC_FLAGS:
        raw = attribute(resource, flag)
        if raw is None:
            continue
        value = _truthy(raw)
        if value is None:
            return None, f"{flag} is not a readable literal"
        if value:
            return 3, f"{flag}=true is a directly internet-exposed managed endpoint"
        return 0, f"{flag}=false"
    return None


def _bucket_publicness(
    resource: TerraformResource, tf_index: Mapping[str, TerraformResource]
) -> tuple[int | None, str]:
    """Pattern 3, over the enumerated combinations only (spec section 4.4).

    Level 5 requires public-access-block disabled **plus** a public ACL or a public
    policy statement. A partial or cross-resource combination outside the enumeration is
    unresolved, not private - the failure this exists to prevent is a bucket scoring 0
    because its publicness was spread across three resources read separately.
    """
    attached = [
        other
        for other in tf_index.values()
        if other.type
        in {
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_acl",
            "aws_s3_bucket_policy",
        }
        and _bucket_target(other) == resource.identity
    ]
    pab = [a for a in attached if a.type == "aws_s3_bucket_public_access_block"]
    acls = [a for a in attached if a.type == "aws_s3_bucket_acl"]
    policies = [a for a in attached if a.type == "aws_s3_bucket_policy"]

    if not pab:
        return None, "no public-access-block resource attached to this bucket"

    blocking: list[bool] = []
    for block in pab:
        for flag in _PAB_BLOCKING_FLAGS:
            value = _truthy(attribute(block, flag))
            if value is None:
                return None, f"public-access-block {flag} is not a readable literal"
            blocking.append(value)
    if all(blocking):
        return 0, "public-access-block fully enabled and no public ACL or policy"

    public_acl = any(
        (raw := attribute(a, "acl")) is not None
        and is_literal(raw)
        and unquote(str(raw)) in _PUBLIC_ACLS
        for a in acls
    )
    public_policy = any(_has_public_principal(p) for p in policies)
    if public_acl or public_policy:
        reason = "public ACL" if public_acl else "public policy statement"
        return 5, f"public-access-block disabled plus a {reason}: content is world-readable"
    return (
        None,
        "public-access-block disabled but neither a public ACL nor a public policy was "
        "readable - outside the enumerated combinations, so not assumed private",
    )


def _bucket_target(resource: TerraformResource) -> str | None:
    raw = attribute(resource, "bucket")
    if raw is None:
        return None
    referenced = resource_reference(raw)
    if referenced is not None and referenced.startswith("aws_s3_bucket."):
        return referenced
    return None


def _has_public_principal(policy_resource: TerraformResource) -> bool:
    """A `Principal = "*"` with `Effect = "Allow"` anywhere in the policy text.

    Read off the raw source rather than a parsed document: the policy arrives as a
    `${jsonencode({...})}` expression, and a public principal is a textual property of
    it that does not need the full parse Task 5 performs for privilege.
    """
    raw = attribute(policy_resource, "policy")
    if raw is None:
        return False
    text = str(raw)
    return '"*"' in text and "Principal" in text and "Allow" in text


def _kubernetes(identity: str, body: Mapping[str, Any]) -> FactorValue:
    kind = body.get("kind")
    if kind == "Ingress":
        return FactorValue.resolved(
            "exposure", 3, f"{identity} is an Ingress, publishing an external route"
        )
    if kind != "Service":
        return FactorValue.unresolved(
            "exposure", f"{identity} kind {kind!r} is outside the supported pattern list"
        )
    spec = body.get("spec")
    if not isinstance(spec, dict):
        return FactorValue.unresolved("exposure", f"{identity} has no readable spec")
    # A Service with no explicit type is ClusterIP, which is the Kubernetes API's own
    # documented default rather than an assumption this extractor is making.
    service_type = spec.get("type", "ClusterIP")
    entry = _KUBERNETES_SERVICE_LEVELS.get(str(service_type))
    if entry is None:
        return FactorValue.unresolved(
            "exposure", f"{identity} Service type {service_type!r} is unrecognised"
        )
    level, evidence = entry
    return FactorValue.resolved("exposure", level, f"{identity}: {evidence}")


_SG_REFERENCE_ATTRS = ("vpc_security_group_ids", "security_groups", "security_group_id")


def _referenced_security_groups(
    resource: TerraformResource,
) -> tuple[list[str], list[str]]:
    """(resolved security-group identities, reasons a reference could not be resolved)."""
    found: list[str] = []
    blocked: list[str] = []
    for attr in _SG_REFERENCE_ATTRS:
        raw = attribute(resource, attr)
        if raw is None:
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            referenced = resource_reference(item)
            if referenced is not None and referenced.startswith("aws_security_group."):
                found.append(referenced)
            else:
                blocked.append(f"{attr} entry is not a resolvable security-group address")
    return found, blocked


def _rules_attached_to(
    group_identity: str, tf_index: Mapping[str, TerraformResource]
) -> list[TerraformResource]:
    """Standalone `aws_security_group_rule` resources naming this group."""
    attached: list[TerraformResource] = []
    for other in tf_index.values():
        if other.type != "aws_security_group_rule":
            continue
        if resource_reference(attribute(other, "security_group_id")) == group_identity:
            attached.append(other)
    return attached


def _from_attached_security_groups(
    resource: TerraformResource, tf_index: Mapping[str, TerraformResource]
) -> tuple[int | None, str] | None:
    """Spec section 4.1 pattern 1 and section 4.3: attribute a group's opening to its target.

    Without this, a compute or load-balancer resource sitting behind a security group whose
    ingress is open to 0.0.0.0/0 resolves `unresolved` and the precedence rule never fires -
    measured on corpus v0, 25 findings across `aws_instance.web_host`, `aws_instance.db_app`
    and `aws_elb.weblb`, all three of which literally reference
    `aws_security_group.web-node`, which itself resolves 4.

    A target aggregates the group's **inline** blocks and the **standalone rules** attached
    to it, because everything governing the target's reachability bears on the target. A
    group evaluated as a finding subject in its own right does not aggregate standalone
    rules (see `_security_group`), since those rules are separately finding-bearing
    resources whose exposure is computed directly and aggregating would double-count them.
    """
    groups, blocked = _referenced_security_groups(resource)
    if not groups and not blocked:
        return None

    candidates: list[tuple[int, str]] = []
    blockers: list[str] = list(blocked)

    for group_identity in groups:
        group = tf_index.get(group_identity)
        if group is None:
            blockers.append(f"{group_identity} is referenced but not indexed")
            continue
        level, evidence = _security_group(group)
        if level is None:
            blockers.append(f"via {group_identity}: {evidence}")
        else:
            candidates.append((level, f"via {group_identity}: {evidence}"))
        for rule in _rules_attached_to(group_identity, tf_index):
            rule_level, rule_evidence = _security_group_rule(rule)
            if rule_level is None:
                blockers.append(f"via {group_identity} rule {rule.identity}: {rule_evidence}")
            else:
                candidates.append(
                    (rule_level, f"via {group_identity} rule {rule.identity}: {rule_evidence}")
                )

    if candidates:
        # An any-source opening anywhere among the attached groups dominates: the
        # precedence rule forbids a lower-scoring sibling from pulling it down.
        return max(candidates, key=lambda pair: pair[0])
    return None, "; ".join(blockers)


def extract(
    finding: NormalizedFinding,
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> FactorValue:
    """Resolve the exposure factor for one finding, or mark it unresolved.

    Never rewrites the finding's identity. Spec section 4.3 attributes exposure to the
    target rather than the rule resource, and that attribution changes the *factor* -
    rewriting `resource_identity` would undo S3a's dedupe separation of rule-level from
    target-level findings. `_from_attached_security_groups` is where that attribution
    happens.
    """
    identity = finding.resource_identity
    if k8s_index is not None:
        body = k8s_lookup(k8s_index, identity)
        if body is not None:
            return _kubernetes(identity, body)

    resource = tf_index.get(identity)
    if resource is None:
        return FactorValue.unresolved("exposure", f"no resource body indexed for {identity}")

    candidates: list[tuple[int, str]] = []
    blockers: list[str] = []

    for outcome in (
        _security_group_rule(resource) if resource.type == "aws_security_group_rule" else None,
        _security_group(resource) if resource.type == "aws_security_group" else None,
        _public_flag(resource),
        _bucket_publicness(resource, tf_index) if resource.type == "aws_s3_bucket" else None,
        # Target attribution. Excluded for the two security-group types themselves: a rule's
        # `security_group_id` names its parent rather than a target, and a group is scored on
        # what it declares.
        _from_attached_security_groups(resource, tf_index)
        if resource.type not in {"aws_security_group", "aws_security_group_rule"}
        else None,
    ):
        if outcome is None:
            continue
        level, evidence = outcome
        if level is None:
            blockers.append(evidence)
        else:
            candidates.append((level, evidence))

    if candidates:
        level, evidence = max(candidates, key=lambda pair: pair[0])
        value = FactorValue.resolved("exposure", level, evidence)
        # The rubric's precedence_rule, asserted rather than trusted: an any-source
        # opening can never be pulled below 4 by another branch scoring lower.
        if "any-source ingress opening" in evidence and level < 4:
            raise AssertionError(
                f"precedence violation: any-source opening resolved to {level} for {identity}"
            )
        return value

    if blockers:
        return FactorValue.unresolved("exposure", "; ".join(blockers))
    return FactorValue.unresolved(
        "exposure",
        f"{resource.type} matches no supported exposure pattern "
        f"(security-group ingress, public flag, bucket publicness, K8s Service/Ingress)",
    )
