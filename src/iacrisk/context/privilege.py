"""IAM privilege scope, read from literal policy documents and RBAC rules.

Privilege carries `unresolved_default = 4`, so failing to parse policy documents would
leave every IAM finding unresolved, contribute 4 to every score, and feed the washout
spec section 1.1 measures directly. Parsing is therefore not optional.

Two policy-document forms exist in this corpus and **neither is plain JSON**:

* a **heredoc** - `"<<EOF\\n{...}\\nEOF"` - whose body is JSON once the outer quotes and
  the heredoc markers are stripped;
* a **`jsonencode(...)` expression** carrying HCL object syntax (`Effect = "Allow"`, bare
  keys, no colons), which `json.loads` cannot read. It is re-parsed with hcl2 and then
  deep-unquoted, because hcl2 retains quotes on every string.

Anything else - a bare variable, a `data.aws_iam_policy_document` reference, an
AWS-managed policy ARN - is `unresolved`, never a guess and never a reassuring zero.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

import hcl2

from iacrisk.context.kubernetes import lookup as k8s_lookup
from iacrisk.context.terraform import TerraformResource, attribute, unquote
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding

__all__ = [
    "action_services",
    "extract",
    "parse_policy_document",
    "privilege_level",
]

_HEREDOC = re.compile(r"^<<-?([A-Za-z0-9_]+)\s*\n(.*)\n\s*\1\s*$", re.S)
_JSONENCODE = re.compile(r"^\$\{\s*jsonencode\((.*)\)\s*\}$", re.S)

# An AWS-managed policy's contents are not in the repository, and fetching them needs a
# live account - outside static pre-deployment analysis (spec section 5.2, decision 6).
_MANAGED_ARN_PREFIX = "arn:aws:iam::aws:policy/"

# Attributes carrying a PERMISSION grant. `assume_role_policy` is deliberately absent:
# it is a trust policy (decision 12, see `_is_trust_statement`).
_PERMISSION_ATTRS = ("policy",)

_ESCALATION_VERBS = frozenset({"create", "bind", "escalate", "impersonate", "*"})
_RBAC_SENSITIVE_RESOURCES = frozenset({"secrets", "pods/exec", "roles", "clusterroles"})


def _deep_unquote(value: Any) -> Any:
    """Strip hcl2's retained quotes throughout a parsed structure."""
    if isinstance(value, str):
        return unquote(value)
    if isinstance(value, dict):
        return {_deep_unquote(k): _deep_unquote(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_unquote(v) for v in value]
    return value


def parse_policy_document(raw: object) -> dict[str, Any] | None:
    """A policy document as a dict, or None when it is not a literal read.

    None is a first-class answer meaning "the caller must mark this unresolved", not an
    error and not an empty policy.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        if len(raw) != 1:
            return None
        raw = raw[0]
    if not isinstance(raw, str):
        return None
    text = unquote(raw).strip()

    heredoc = _HEREDOC.match(text)
    if heredoc is not None:
        try:
            parsed = json.loads(heredoc.group(2))
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    encoded = _JSONENCODE.match(text)
    if encoded is not None:
        try:
            reparsed = hcl2.loads("x = " + encoded.group(1))["x"]
        except Exception:
            # hcl2 raises lark parse errors; enumerating a third-party grammar's
            # exception types would couple this module to lark's internals for no gain.
            return None
        cleaned = _deep_unquote(reparsed)
        return cleaned if isinstance(cleaned, dict) else None

    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    return None


def action_services(actions: list[str]) -> set[str]:
    """The AWS service prefixes an action list touches. A bare `*` stays `*`."""
    services: set[str] = set()
    for action in actions:
        if action == "*":
            services.add("*")
        else:
            services.add(action.split(":", 1)[0])
    return services


def privilege_level(actions: list[str], resources: list[str]) -> int:
    """Action breadth AND resource breadth, jointly - spec section 5.4.

    Reading action breadth alone collapses an `s3:*`-on-one-bucket policy and an
    `s3:*`-on-`*` policy to the same level, which costs the corpus one of its two
    privilege mechanism pairs with no test failing. The rubric's L2 says "bounded
    resource set within a single service" and L3 says "full control of one service",
    so both clauses are read.
    """
    services = action_services(actions)
    unbounded_resource = any(r == "*" for r in resources)
    if "*" in services:
        return 5 if unbounded_resource else 4
    if not unbounded_resource:
        return 2 if any(a.endswith(":*") for a in actions) else 1
    return 4 if len(services) > 1 else 3


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _is_trust_statement(statement: Mapping[str, Any]) -> bool:
    """True for a statement carrying a `Principal` and no `Resource`.

    That shape is a trust policy. It is NOT a test for resource policies in general: a
    bucket policy carries both a `Principal` and a `Resource`, so it is scored on the
    permission ladder like any other grant - which is defensible, since the rubric's
    privilege factor names "policy" among the things whose granted breadth it measures.
    An earlier version of this docstring said "trust or resource policy", which claimed an
    exclusion the function does not perform.

    Decision 12. Measured on TerraGoat's `aws_iam_role.ec2role`: its `assume_role_policy`
    carries `Action = "sts:AssumeRole"`, a `Principal`, and **no Resource**. Such a
    statement declares who may assume the role; it grants no permission *to* the role.
    Scoring it on the permission ladder reads the grant backwards - `sts:AssumeRole`
    would land at 4 as an escalation enabler when it is the role's own trust boundary.
    """
    return "Principal" in statement and "Resource" not in statement


def _statement_levels(document: Mapping[str, Any]) -> list[int]:
    raw_statements = document.get("Statement")
    statements: list[Any]
    if isinstance(raw_statements, dict):
        statements = [raw_statements]
    elif isinstance(raw_statements, list):
        statements = raw_statements
    else:
        return []

    levels: list[int] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect", "Allow")) != "Allow":
            continue
        if _is_trust_statement(statement):
            continue
        actions = _as_list(statement.get("Action"))
        if not actions:
            continue
        # Conditions are deliberately not evaluated and never reduce a level (spec
        # section 5.3): the extractor cannot establish that a condition is restrictive,
        # and treating an unevaluated one as mitigating is the false-reassurance failure
        # mode PLAN Q9 forbids.
        levels.append(privilege_level(actions, _as_list(statement.get("Resource"))))
    return levels


def _managed_attachment(resource: TerraformResource) -> str | None:
    for attr in ("policy_arn", "managed_policy_arns"):
        raw = attribute(resource, attr)
        for candidate in _as_list(raw if not isinstance(raw, str) else [raw]):
            if _MANAGED_ARN_PREFIX in unquote(candidate):
                return unquote(candidate)
    return None


def _kubernetes(identity: str, body: Mapping[str, Any]) -> FactorValue:
    kind = str(body.get("kind", ""))

    if kind in {"RoleBinding", "ClusterRoleBinding"}:
        role_ref = body.get("roleRef")
        name = str(role_ref.get("name", "")) if isinstance(role_ref, dict) else ""
        if name == "cluster-admin":
            return FactorValue.resolved(
                "privilege", 5, f"{identity} binds cluster-admin: unbounded cluster authority"
            )
        return FactorValue.unresolved(
            "privilege",
            f"{identity} binds role {name!r}, whose rules are a separate resource this "
            f"bounded extractor does not aggregate",
        )

    if kind not in {"Role", "ClusterRole"}:
        return FactorValue.resolved(
            "privilege", 0, f"{identity} kind {kind!r} grants no RBAC permission"
        )

    rules = body.get("rules")
    if not isinstance(rules, list):
        return FactorValue.unresolved("privilege", f"{identity} has no readable rules block")

    level = 0
    reasons: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = {str(v).lower() for v in _as_list(rule.get("verbs"))}
        resources = {str(r).lower() for r in _as_list(rule.get("resources"))}
        if "*" in verbs and "*" in resources:
            level = max(level, 5)
            reasons.append("wildcard verbs and resources")
        elif verbs & _ESCALATION_VERBS and resources & _RBAC_SENSITIVE_RESOURCES:
            level = max(level, 4)
            reasons.append(f"{sorted(verbs & _ESCALATION_VERBS)} on {sorted(resources)}")
        elif resources & _RBAC_SENSITIVE_RESOURCES:
            level = max(level, 4)
            reasons.append(f"access to {sorted(resources & _RBAC_SENSITIVE_RESOURCES)}")
        elif verbs - {"get", "list", "watch"}:
            level = max(level, 2)
            reasons.append(f"mutating verbs {sorted(verbs)}")
        else:
            level = max(level, 1)
            reasons.append(f"read-only verbs {sorted(verbs)}")
    if not reasons:
        return FactorValue.unresolved(
            "privilege", f"{identity} rules block yielded no readable verb"
        )
    return FactorValue.resolved("privilege", level, f"{identity}: {'; '.join(reasons)}")


def extract(
    finding: NormalizedFinding,
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> FactorValue:
    """Resolve the privilege factor for one finding, or mark it unresolved."""
    identity = finding.resource_identity
    if k8s_index is not None:
        body = k8s_lookup(k8s_index, identity)
        if body is not None:
            return _kubernetes(identity, body)

    resource = tf_index.get(identity)
    if resource is None:
        return FactorValue.unresolved("privilege", f"no resource body indexed for {identity}")

    managed = _managed_attachment(resource)
    if managed is not None:
        return FactorValue.unresolved(
            "privilege",
            f"attaches AWS-managed policy {managed}, whose contents are not in this "
            f"repository and cannot be read without a live account",
        )

    for attr in _PERMISSION_ATTRS:
        raw = attribute(resource, attr)
        if raw is None:
            continue
        document = parse_policy_document(raw)
        if document is None:
            return FactorValue.unresolved(
                "privilege", f"{identity}.{attr} is not a literal policy document"
            )
        levels = _statement_levels(document)
        if not levels:
            return FactorValue.unresolved(
                "privilege",
                f"{identity}.{attr} parsed but yielded no Allow permission statement "
                f"(a trust or resource policy grants no permission to its principal)",
            )
        level = max(levels)
        return FactorValue.resolved(
            "privilege", level, f"{identity}.{attr}: highest Allow statement scores {level}"
        )

    if attribute(resource, "assume_role_policy") is not None:
        # Decision 12. The trust policy is readable but grants nothing; the role's actual
        # permissions live in separate attached policy resources this bounded extractor
        # does not aggregate. Resolving 0 here would falsely reassure.
        return FactorValue.unresolved(
            "privilege",
            f"{identity} carries only a trust policy; its permissions come from attached "
            f"policy resources, which a bounded per-finding read does not aggregate",
        )

    if resource.type.startswith("aws_iam_"):
        return FactorValue.unresolved(
            "privilege", f"{identity} is an IAM resource with no readable policy document"
        )

    return FactorValue.resolved(
        "privilege", 0, f"{resource.type} touches no identity, policy, role or RBAC binding"
    )
