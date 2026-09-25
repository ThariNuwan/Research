"""Trivy: the scanner whose resource identity comes from anywhere but the obvious field.

Terraform is close to checkov's easy case: `CauseMetadata.Resource` is present
on 113 of 115 corpus v0 findings and is always a clean `<type>.<name>` pair -
no polymorphism to read apart, unlike checkov's `resource` field (spec §2.1).
The 2 without it (`resources/Dockerfile`'s `DS-0002` and `DS-0026`, run
alongside the terraform scan root per trivy's own block-level `Type` field)
take `identity_kind="file"` with the rebased `Target` as their identity, not
`<unresolved>` - checkov flags the same file (`CKV_DOCKER_2`/`CKV_DOCKER_3`)
and gives it the same kind, and `<unresolved>` is reserved for identity that
is genuinely undeterminable, which this is not (`_resolve_terraform`'s
docstring has the full correction history).

Kubernetes has no such field to read at all - measured 0 of 332 findings carry
`CauseMetadata.Resource`; trivy states the resource only in the `Message`
string (`Container 'batch-check' of Job 'batch-check-job' should set...`),
which this module deliberately does not parse. Every Kubernetes identity
instead comes from `ResourceIndex.by_line(target, CauseMetadata.StartLine)` -
the same by-line mechanism checkov's adapter falls back to only for its
`Pod.*` label erratum, but here it is the *only* mechanism there is.

`fingerprint` is `None` unconditionally (spec §6) - not because trivy's
`Resolution` field lacks an extractable attribute (185 of 332, 55.7%, carry a
cleanly quoted token such as `containers[].securityContext.runAsNonRoot`), but
because that extracted vocabulary shares zero exact spellings with checkov's
`evaluated_keys` (18 distinct trivy tokens, 23 distinct checkov keys, 0
overlap). Extracting it would add a field that never matches anything and
produce no additional Tier-1 dedupe collapse, so this module does not attempt
it.
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

_TERRAFORM_RESOURCE_RE = re.compile(r"^[^.]+\.[^.]+$")
"""A `<type>.<name>` pair with exactly one dot.

Looser than checkov's `_TERRAFORM_ADDRESS_RE`, which has to tell a real
resource address apart from a provider block that looks almost identical
(`aws.plain_text_access_keys_provider`). Trivy's `CauseMetadata.Resource` never
carries that ambiguity - measured across all 113 corpus v0 values that carry
one at all, every one matches this shape, with no module path, no `count` or
`for_each` index, and no provider block. This regex exists as a guard against
a future trivy version reporting a different shape, not to disambiguate
anything corpus v0 actually contains.
"""

_CONTEXT_ELIGIBLE_KINDS = frozenset({"terraform", "kubernetes"})
"""The only two `identity_kind` values `context_eligible` may be `True` for (spec §2.1).

Restated here rather than imported from `checkov.py`, which does not export
it - each adapter module owns its own copy of this one-line policy rather than
reaching into a sibling adapter for it.
"""


def _optional_str(value: object) -> str | None:
    """`None` stays `None`; anything else is coerced to `str`."""
    return None if value is None else str(value)


def _line_range(cause_metadata: dict[str, Any]) -> tuple[int, int] | None:
    """trivy's `CauseMetadata.StartLine`/`EndLine`, or `None` if either is not an int.

    Measured on both fixtures: the two fields are always present together or
    absent together (113/115 terraform, 328/332 kubernetes carry both; the
    remainder carry neither) - never one without the other - so this checks
    them as a pair rather than independently, and a malformed range is carried
    as `None` (explicit-state discipline) rather than raised.
    """
    start = cause_metadata.get("StartLine")
    end = cause_metadata.get("EndLine")
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return start, end


def _file_path_from_target(target: str, scan_root: Path) -> str:
    """trivy's `Target`, rebased to the scan-root-relative join key (spec §5.1).

    trivy already reports `Target` scan-root-relative, so `rebase_to_scan_root`
    only has normalization to do here, never a root-prefix strip - unlike
    tfsec's absolute paths (Task 7). One block in corpus v0's terraform fixture
    has `Target == "."`: trivy's own directory-level summary for the scan root
    itself (`MisconfSummary` only, no `Misconfigurations` key), which names no
    file. It carries no misconfiguration in corpus v0, so this is a defensive
    rule rather than one a real finding exercises - but a `"."` reaching
    `rebase_to_scan_root` would round-trip to the literal string `"."`, a
    bogus non-empty file_path, so it is special-cased to the empty string
    before rebasing runs at all.
    """
    if not target or target == ".":
        return ""
    return rebase_to_scan_root(target, scan_root)


def _platform_of(results: Sequence[Any]) -> str:
    """Which scan root produced this run, read off trivy's own block-level `Type`.

    Measured: the terraform-root fixture's blocks carry `Type` values
    `{"terraform", "dockerfile"}` only; the kubernetes-root fixture's carry
    `{"kubernetes", "helm"}` only (the one Helm chart's two blocks). Neither
    value set appears in the other fixture, so either `kubernetes` or `helm`
    anywhere in `results` is conclusive for the whole run, mirroring
    `checkov._platform_of`'s reasoning for its own `check_type` field. Absence
    of both defaults to `terraform`, the only other platform S3a supports
    (`finding.PLATFORMS`).
    """
    for block in results:
        if isinstance(block, dict) and block.get("Type") in ("kubernetes", "helm"):
            return "kubernetes"
    return "terraform"


def _resolve_terraform(resource: object, file_path: str) -> tuple[str, str]:
    """`CauseMetadata.Resource` read as a terraform identity, a file identity, or `<unresolved>`.

    `resource` is missing on 2 of 115 corpus v0 findings and is always a clean
    `<type>.<name>` pair when present, measured against `_TERRAFORM_RESOURCE_RE`.
    A present-but-unrecognized shape falls through toward the file/unresolved
    branch below alongside the missing case - defensive, since corpus v0 has
    no such value.

    **Correction, recorded during Task 6's fix round.** The task brief
    originally said the 2 resource-less findings should take `<unresolved>`.
    That was wrong: both are `DS-*` Dockerfile checks (`Type: "dockerfile"`,
    `Target: "resources/Dockerfile"`) - trivy tells us exactly which file is
    at fault, it simply is not a terraform *resource*. `<unresolved>` means
    "we could not determine it"; here we can, from `Target` alone. Checkov
    flags the same file with `CKV_DOCKER_2`/`CKV_DOCKER_3` and gives it
    `identity_kind="file"` (`checkov.classify_resource`) - without this
    fallback, one Dockerfile would carry two different identity kinds
    depending only on which scanner found it, breaking Task 9's retention
    grouping and Task 8's dedupe key for no principled reason. So: no
    terraform-shaped `Resource` but a real `Target` (a non-empty, non-`"."`
    `file_path`) resolves to the `file` kind instead, mirroring checkov's own
    treatment of the same file. Only when there is truly no file to point at
    (`file_path` empty, e.g. a `Target == "."` summary block) does this fall
    through to `<unresolved>`.
    """
    if isinstance(resource, str) and _TERRAFORM_RESOURCE_RE.fullmatch(resource):
        resource_type, _, resource_name = resource.partition(".")
        return identity.terraform_identity(resource_type, resource_name), "terraform"
    if file_path:
        return identity.normalize_path(file_path), "file"
    return identity.UNRESOLVED, "unresolved"


def _resolve_kubernetes(
    file_path: str, line_range: tuple[int, int] | None, index: ResourceIndex | None
) -> tuple[str, str]:
    """The index-only Kubernetes identity: by line, and nothing else (spec §4).

    trivy supplies no `resource`-shaped field for Kubernetes at all (0 of 332
    measured), so there is no by-address path to try first the way checkov's
    adapter does - `ResourceIndex.by_line` against `CauseMetadata.StartLine`
    is the entire mechanism. Returns `<unresolved>` when there is no index, no
    line, or the line matches no span - the same three failure causes §4
    documents for the index itself.

    A matched entry can still be only *partially* resolved - a quoted,
    templated Helm name renders `apps/v1/Deployment/<unresolved>/<unresolved>`
    (`identity.kubernetes_identity` substitutes the sentinel per component),
    which is not equal to `identity.UNRESOLVED` but is not usable either
    (whole-branch review Finding 1). `identity.is_unusable` is the one place
    that judgment is made; a matched-but-unusable entry's identity kind comes
    back `"unresolved"` too, and the informative partial string is returned
    as-is rather than collapsed to the bare sentinel - `identity_kind` alone
    carries the explicit state.
    """
    if index is not None and line_range is not None and file_path:
        entry = index.by_line(file_path, line_range[0])
        if entry is not None:
            rendered = entry.to_identity()
            if not identity.is_unusable(rendered):
                return rendered, "kubernetes"
            return rendered, "unresolved"
    return identity.UNRESOLVED, "unresolved"


def _build_finding(
    misconfiguration: dict[str, Any],
    platform: str,
    scan_root: Path,
    target: str,
    index: ResourceIndex | None,
) -> tuple[NormalizedFinding | None, str | None]:
    """One `Misconfigurations` entry turned into a finding, or the reason it could not be.

    `ID` is present on every one of corpus v0's 447 misconfigurations
    (measured), so the guard below is defensive rather than modeled - it
    exists so a future capture missing it is counted as `dropped`
    (`in == out + dropped`, spec §10 acceptance gate 6) instead of crashing
    the adapter run.
    """
    raw_id = misconfiguration.get("ID")
    if not raw_id:
        return None, "ID missing or empty"
    rule_id = str(raw_id)

    cause_metadata = misconfiguration.get("CauseMetadata") or {}
    file_path = _file_path_from_target(target, scan_root)
    line_range = _line_range(cause_metadata)

    if platform == "terraform":
        resource_identity, identity_kind = _resolve_terraform(
            cause_metadata.get("Resource"), file_path
        )
    else:
        resource_identity, identity_kind = _resolve_kubernetes(file_path, line_range, index)
    # `context_eligible` is derived from the kind alone, never from resolution
    # success directly - the same rule checkov's adapter follows (spec §2.1),
    # so that one flag carries one meaning rather than a conjunction of two.
    context_eligible = identity_kind in _CONTEXT_ELIGIBLE_KINDS

    native_severity = _optional_str(misconfiguration.get("Severity"))

    finding = NormalizedFinding(
        scanner="trivy",
        rule_id=rule_id,
        canonical_rule_id=taxonomy.canonical_rule_id(rule_id),
        issue_class=taxonomy.class_for("trivy", rule_id),
        title=str(misconfiguration.get("Title") or ""),
        remediation=_optional_str(misconfiguration.get("Resolution")),
        native_severity=native_severity,
        severity_level=rubric.normalize_severity("trivy", native_severity),
        platform=platform,
        resource_identity=resource_identity,
        identity_kind=identity_kind,
        file_path=file_path,
        line_range=line_range,
        fingerprint=None,
        context_eligible=context_eligible,
    )
    return finding, None


class TrivyAdapter:
    """Turns one trivy run's JSON into `NormalizedFinding` values (spec §5).

    `parse` reads the whole `Results` array in one call because platform is a
    property of the *run*, not of any one block within it (`_platform_of`'s
    docstring) - the same reason `CheckovAdapter.parse` reads its whole array
    before classifying the first check.
    """

    name = "trivy"

    def parse(self, raw: object, scan_root: Path, index: ResourceIndex | None) -> AdapterResult:
        document = raw if isinstance(raw, dict) else {}
        results = document.get("Results") or []
        platform = _platform_of(results)

        findings: list[NormalizedFinding] = []
        dropped: list[tuple[str, str]] = []

        for block in results:
            if not isinstance(block, dict):
                continue
            target = str(block.get("Target") or "")
            for misconfiguration in block.get("Misconfigurations") or []:
                if not isinstance(misconfiguration, dict):
                    dropped.append(("", "Misconfigurations entry is not an object"))
                    continue
                finding, reason = _build_finding(
                    misconfiguration, platform, scan_root, target, index
                )
                if finding is None:
                    dropped.append((str(misconfiguration.get("ID") or ""), reason or "unknown"))
                else:
                    findings.append(finding)

        return AdapterResult(findings=tuple(findings), dropped=tuple(dropped))


_conforms: ScannerAdapter = TrivyAdapter()
"""Never executed - a mypy-checked assertion that `TrivyAdapter` satisfies
`ScannerAdapter` structurally, matching `checkov.py`'s own guard.
"""
