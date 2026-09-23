"""The checkov adapter (design spec §5): reads a polymorphic `resource` field.

Checkov's `resource` string does not announce what it names - across corpus v0's
489 failed checks it is a Terraform address (`aws_db_instance.default`), a
Dockerfile path (`/resources\\Dockerfile.`), a provider block
(`aws.plain_text_access_keys_provider`), a bare 40-hex secret hash (spec §1
measured fact 3, §2.1), or a Kubernetes `Kind.namespace.name` triple, sometimes
with a fourth dot-component. `classify_resource` reads that shape; nothing else
in this module second-guesses it once classified.

The fourth Kubernetes component deserves its own warning, because an earlier
draft of the spec got it wrong and this module exists to not repeat that
mistake: it is the pod template's label rendered `key-value`, not a container
name, in 10 of 10 measured cases (spec §4's erratum). `_resolve_kubernetes`
never passes it to `ResourceIndex.by_address(container=...)`. Every one of the
form's occurrences in corpus v0 is `CKV2_K8S_6`, a pod-level check, and every
one of checkov's `Pod.*` findings - four-component or plain three-component
alike - synthesizes `Pod` as the kind regardless of the workload's real kind
(`Deployment`, `DaemonSet`, `Job`...), so a direct kind/namespace/name lookup
never matches for any of them (measured: 0 of 12 in corpus v0). The fallback
below - resolving by the finding's own file and start line, the same mechanism
`ResourceIndex.by_line` gives trivy - is what actually resolves all 12, because
a pod-level check's start line sits in the workload's own span, outside every
container's narrower one, and `by_line` returns the innermost match containing
it (spec §4).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from iacrisk import identity, rubric, taxonomy
from iacrisk.finding import NormalizedFinding
from iacrisk.resources import ResourceIndex
from iacrisk.scanners.base import AdapterResult, ScannerAdapter, rebase_to_scan_root

_SECRET_HASH_RE = re.compile(r"^[0-9a-fA-F]{40}$")
"""A bare secret hash, e.g. `25910f981e85ca04baf359199dd0bd4a3ae738b6` (§2.1).

Checked before every other pattern: a hash is 40 hex characters with no dot, so
it could not accidentally satisfy the terraform or kubernetes address patterns
below, but checking it first keeps the order in this module matching the order
stated in the task brief, rather than relying on that non-overlap to hold
forever.
"""

_TERRAFORM_ADDRESS_RE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+\.[^.]+$")
"""A Terraform resource address: `<type>.<name>`, `type` containing an underscore.

The underscore is doing real work, not decoration. Corpus v0's one provider
block, `aws.plain_text_access_keys_provider`, is *also* exactly `<lower>.<lower>`
- a bare "does it look like `word.word`" test would misclassify it as a
resource. What actually distinguishes it, measured across all 47 distinct
terraform-platform values in corpus v0: every one of the 42 real resource
addresses has a `<provider>_<resource>` type (`aws_db_instance`, `aws_s3_bucket`,
...), and the one provider block does not - its "type" is bare `aws`. This
regex encodes that measured distinction rather than checkov's `check_class`
field (`checkov.terraform.checks.provider.aws.credentials` for that finding),
which `classify_resource` cannot see: its signature is `(value, rule_id,
platform)`, not the full check record. That makes the underscore test
coincidental rather than principled, and it fails in two directions this
corpus does not happen to exercise: a provider block whose name itself
contains an underscore would misclassify as terraform, and a resource type
with no underscore in it (neither occurs among corpus v0's 47 distinct
terraform-platform values) would misclassify as a provider.
"""

_KUBERNETES_ADDRESS_RE = re.compile(r"^[A-Z][A-Za-z0-9]*\.[^.]+\.[^.]+(?:\.[^.]+)?$")
"""A Kubernetes `Kind.namespace.name` triple, or the four-component label form.

`Kind` is required to start uppercase, which is how Kubernetes spells every kind
it has; corpus v0's 266 kubernetes-address resource values (268 minus the 2
`CKV_SECRET_6` hashes) are all three or four dot-components with an uppercase
first one. No cluster-scoped, two-component form (`Kind.name`, no namespace) is
observed in corpus v0's checkov output, so this pattern does not recognize one;
see the module docstring's measured-fact citations for what is and is not
exercised.
"""

_META_KEY = "resource_type"
"""checkov's own housekeeping entry in `evaluated_keys`. Names no attribute at
all (spec §6) and is discarded from every fingerprint, including one that would
otherwise be empty - `["resource_type"]` fingerprints as unresolved, not as the
string `"resource_type"`.
"""


def classify_resource(value: str, rule_id: str, platform: str) -> tuple[str, str, bool]:
    """Read checkov's `resource` string and say what shape it is.

    Order is load-bearing (task brief): secret hash, then Dockerfile/path, then
    the platform-appropriate address pattern, then the `provider` catch-all. A
    hash must be caught before an address pattern could claim it, and a path
    before the terraform pattern could - though corpus v0 never in fact produces
    an ambiguous value between those two, checking secret first costs nothing
    and removes a fragile assumption.

    The returned `resource_identity` is the *final* value for `terraform`,
    `secret` and `provider`: a terraform address round-trips through `identity.
    terraform_identity` (S1's single spelling authority), and `secret`/
    `provider` have no S1 formatter at all, so the value is returned verbatim.
    `kubernetes` and `file` both come back as placeholders instead, because
    each needs something this pure, index-free classifier does not have access
    to. For `kubernetes`, this function returns `identity.UNRESOLVED`
    deliberately: the canonical form needs `apiVersion`, which is not in
    checkov's field at all (spec §4), and needs the resource index's
    by-address/by-line resolution (`_resolve_kubernetes`, below). For `file`,
    it returns `identity.normalize_path(value)` - the raw `resource` string,
    backslash-normalized - but that string carries decoration checkov's own
    `file_path` field does not (a trailing `.` on a Dockerfile finding,
    measured in corpus v0; see `_build_finding`'s docstring), so
    `_build_finding` substitutes the rebased `file_path` for it, which this
    classifier also cannot reach. `CheckovAdapter.parse` overwrites both
    placeholders; nothing downstream should read either as final from this
    function alone.

    Only `terraform` and `kubernetes` are `context_eligible` (spec §2.1): the
    other three kinds have no cloud or cluster resource for S3b to attach
    context to, and marking them eligible would let the five context defaults
    float them to a "High" that reflects nothing having resolved rather than
    any actual severity (the washout spec §3.5(2) describes).
    """
    if _SECRET_HASH_RE.fullmatch(value):
        return value, "secret", False

    if rule_id.startswith("CKV_DOCKER_") or "/" in value or "\\" in value:
        return identity.normalize_path(value), "file", False

    if platform == "terraform" and _TERRAFORM_ADDRESS_RE.fullmatch(value):
        resource_type, _, resource_name = value.partition(".")
        return identity.terraform_identity(resource_type, resource_name), "terraform", True

    if platform == "kubernetes" and _KUBERNETES_ADDRESS_RE.fullmatch(value):
        return identity.UNRESOLVED, "kubernetes", True

    return value, "provider", False


def fingerprint_from(evaluated_keys: Sequence[str]) -> str | None:
    """The Q8 violation fingerprint from checkov's `check_result.evaluated_keys` (spec §6).

    Discards `_META_KEY`, preserves case (attribute paths are case-significant -
    `logging` and `Logging` are not the same key), sorts what remains
    lexicographically so scanner key order cannot change the fingerprint, and
    joins with `,`. An empty list, or a list containing only the meta-key, both
    collapse to `None` - the explicit unresolved state, never a sentinel string
    that a real single-key fingerprint could collide with.
    """
    keys = sorted(key for key in evaluated_keys if key != _META_KEY)
    return ",".join(keys) if keys else None


def _optional_str(value: object) -> str | None:
    """`None` stays `None`; anything else is coerced to `str`.

    checkov's `severity` and `guideline` fields are `str | None` in every
    fixture row this module has seen: `severity` is `None` on all 489 failed
    checks (the count is spec §1's Findings column, 221 + 268; the null fact
    itself is measured - CLAUDE.md, "Severity in corpus v0, measured"), and
    `guideline` measures the same on this pin - null on every one of the same
    489, not just the ones this adapter drops. This is a narrow defensive
    coercion, not a modeled state: nothing in corpus v0 exercises a
    non-string, non-null value for either field.
    """
    return None if value is None else str(value)


def _line_range(raw: object) -> tuple[int, int] | None:
    """checkov's `file_line_range` as `(start, end)`, or `None` if it is not that shape.

    Present on every one of corpus v0's 489 failed checks (spec §1), so this is
    a defensive fallback rather than a modeled corpus state - a malformed or
    absent range is carried as `None` (first-class, per the explicit-state
    discipline) rather than raised.
    """
    if not isinstance(raw, list) or len(raw) != 2:
        return None
    start, end = raw
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return start, end


def _resolve_kubernetes(
    value: str, file_path: str, line_range: tuple[int, int] | None, index: ResourceIndex
) -> str:
    """The index-dependent half of Kubernetes identity: kind/namespace/name first, by-line second.

    Only the first three dot-components of `value` are ever used for addressing
    - a fourth component, where present, is discarded unconditionally rather
    than risked as `by_address(container=...)`, per the module docstring's
    erratum. `by_address` is tried first because it is exact where it applies
    (spec §5.1's "by kind/namespace/name for checkov"); the by-line fallback
    exists because checkov's own `Kind` is wrong for every `Pod.*` value in
    corpus v0 (measured: `by_address` fails for all 12), so falling back to the
    finding's own file and start line - the same mechanism trivy relies on
    entirely - is what actually resolves them, landing on the workload because
    a pod-level check's start line sits outside every container's span.

    Returns `identity.UNRESOLVED` if neither lookup succeeds - an unparseable
    file or a line matching no span (spec §4). Unobserved in corpus v0: no
    checkov kubernetes finding in the fixtures points at the four unparseable
    Helm templates, so this branch is stated as defensive, not measured.
    """
    kind, namespace, name = value.split(".")[:3]
    entry = index.by_address(kind, namespace, name, container=None)
    if entry is None and line_range is not None and file_path:
        entry = index.by_line(file_path, line_range[0])
    return entry.to_identity() if entry is not None else identity.UNRESOLVED


def _platform_of(documents: Sequence[Any]) -> str:
    """Which scan root produced this run, read off checkov's own `check_type`.

    checkov emits one JSON array per scan-root invocation - three blocks
    (`terraform`, `dockerfile`, `secrets`) on the terraform root, two
    (`kubernetes`, `secrets`) on the kubernetes root (spec §1 measured fact 3).
    `check_type` varies *within* one array (a `secrets` block sits alongside
    `terraform` or alongside `kubernetes`) but never carries findings from both
    scan roots in one array, so a `kubernetes` block anywhere in `documents` is
    conclusive for every finding in the run. Its absence defaults to
    `terraform`, the only other platform S3a supports (`finding.PLATFORMS`).
    """
    for document in documents:
        if isinstance(document, dict) and document.get("check_type") == "kubernetes":
            return "kubernetes"
    return "terraform"


_CONTEXT_ELIGIBLE_KINDS = frozenset({"terraform", "kubernetes"})
"""The only two `identity_kind` values `context_eligible` may be `True` for (spec §2.1).

Stated once and re-read wherever a kind can change after `classify_resource`
returns, rather than re-derived in each such place: `_build_finding` downgrades
a `kubernetes` kind to `unresolved` when `_resolve_kubernetes` falls through,
and re-reads this set to settle `context_eligible` for that downgraded kind -
one flag, one meaning, sourced from the kind alone.
"""


def _build_finding(
    check: dict[str, Any], platform: str, scan_root: Path, index: ResourceIndex | None
) -> tuple[NormalizedFinding | None, str | None]:
    """One `failed_checks` entry turned into a finding, or the reason it could not be.

    `resource` is present on every one of corpus v0's 489 failed checks (spec
    §1's identity-present column), and `check_id` measures the same on this pin
    though spec §1 does not itself tabulate it. Both guards are therefore
    defensive rather than modeled; they exist so a future capture missing
    either is counted as `dropped` (`in == out + dropped`, spec §0.1) instead
    of crashing the adapter run or, worse, silently vanishing.

    A `kubernetes`-shaped identity that still resolves to `identity.UNRESOLVED`
    after `_resolve_kubernetes` runs - both lookups missed, or no index was
    available to try them - is downgraded to `identity_kind = "unresolved"`
    here, and `context_eligible` is re-settled from that downgraded kind
    (`_CONTEXT_ELIGIBLE_KINDS`) rather than left at the `True` `classify_resource`
    assigned before resolution had a chance to fail. `classify_resource` cannot
    make this call itself - resolution has not happened yet when it runs.

    A `file`-shaped identity is replaced with the rebased `file_path`, for the
    same reason `classify_resource`'s own docstring flags it as a placeholder:
    checkov's `resource` string for a Dockerfile finding carries decoration its
    `file_path` field does not (a trailing `.` in `/resources\\Dockerfile.`,
    measured on corpus v0's two `CKV_DOCKER_*` findings), and that decoration
    would put this adapter's identity for the file one character off trivy's
    identity for the same file - silently defeating the Task 8 cross-scanner
    join `CKV_DOCKER_2`/`DS-0002` and `CKV_DOCKER_3`/`DS-0026` are exactly the
    kind of pair it exists to report.
    """
    raw_rule_id = check.get("check_id")
    if not raw_rule_id:
        return None, "check_id missing or empty"
    rule_id = str(raw_rule_id)

    raw_resource = check.get("resource")
    if not raw_resource:
        return None, "resource missing or empty"
    resource_value = str(raw_resource)

    resource_identity, identity_kind, context_eligible = classify_resource(
        resource_value, rule_id, platform
    )

    raw_file_path = str(check.get("file_path") or "")
    file_path = rebase_to_scan_root(raw_file_path, scan_root) if raw_file_path else ""
    line_range = _line_range(check.get("file_line_range"))

    if identity_kind == "file":
        resource_identity = file_path

    if identity_kind == "kubernetes":
        if index is not None:
            resource_identity = _resolve_kubernetes(resource_value, file_path, line_range, index)
        if resource_identity == identity.UNRESOLVED:
            identity_kind = "unresolved"
            context_eligible = identity_kind in _CONTEXT_ELIGIBLE_KINDS

    check_result = check.get("check_result") or {}
    fingerprint = fingerprint_from(check_result.get("evaluated_keys") or [])

    native_severity = _optional_str(check.get("severity"))

    finding = NormalizedFinding(
        scanner="checkov",
        rule_id=rule_id,
        canonical_rule_id=taxonomy.canonical_rule_id(rule_id),
        issue_class=taxonomy.class_for("checkov", rule_id),
        title=str(check.get("check_name") or ""),
        remediation=_optional_str(check.get("guideline")),
        native_severity=native_severity,
        severity_level=rubric.normalize_severity("checkov", native_severity),
        platform=platform,
        resource_identity=resource_identity,
        identity_kind=identity_kind,
        file_path=file_path,
        line_range=line_range,
        fingerprint=fingerprint,
        context_eligible=context_eligible,
    )
    return finding, None


class CheckovAdapter:
    """Turns one checkov run's JSON into `NormalizedFinding` values (spec §5).

    `parse` reads the whole array in one call because platform is a property of
    the *run*, not of any one block within it (`_platform_of`'s docstring) - so
    this adapter, unlike a per-finding transform, has to see every block before
    it can classify the first check. Only `failed_checks` are findings;
    `passed_checks` (1111 across corpus v0's two fixtures) and `skipped_checks`
    are not read at all, matching `tools/harvest/walkers.py::walk_checkov`'s own
    reading of the same shape - re-derived here rather than imported, per the
    "harvest is not reusable" constraint (spec §0.1).
    """

    name = "checkov"

    def parse(self, raw: object, scan_root: Path, index: ResourceIndex | None) -> AdapterResult:
        documents: list[Any] = list(raw) if isinstance(raw, list) else [raw]
        platform = _platform_of(documents)

        findings: list[NormalizedFinding] = []
        dropped: list[tuple[str, str]] = []

        for document in documents:
            if not isinstance(document, dict):
                continue
            results = document.get("results") or {}
            for check in results.get("failed_checks") or []:
                if not isinstance(check, dict):
                    dropped.append(("", "failed_checks entry is not an object"))
                    continue
                finding, reason = _build_finding(check, platform, scan_root, index)
                if finding is None:
                    dropped.append((str(check.get("check_id") or ""), reason or "unknown"))
                else:
                    findings.append(finding)

        return AdapterResult(findings=tuple(findings), dropped=tuple(dropped))


_conforms: ScannerAdapter = CheckovAdapter()
"""Never executed - a mypy-checked assertion that `CheckovAdapter` satisfies
`ScannerAdapter` structurally. Without it, conformance rests on a reviewer
reading both signatures side by side, which is exactly the kind of check that
stops happening once nobody is looking; this makes a future drift in either
signature a type error instead of a silent one.
"""
