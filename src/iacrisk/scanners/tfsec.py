"""tfsec: the scanner whose paths are absolute and whose resource is sometimes attribute-suffixed.

tfsec is the simplest of the three adapters to write and the hardest to get
the path handling right for. `resource` is present on all 119 corpus v0
findings and is a clean `<type>.<name>` Terraform address on 118 of them
(measured), occasionally with a third component naming the specific
attribute that failed - `aws_db_instance.default.publicly_accessible` on the
fixture's one such row, `AVD-AWS-0180`. That trailing component is split off
and becomes the Q8 violation fingerprint (spec §6); the identity itself is
the bare `<type>.<name>` pair, so a suffixed and an unsuffixed finding on the
same resource resolve to the identical identity string. A `data.<type>.
<name>` data-source address (S1 §5.1) is the one other shape this module
recognizes, unobserved in corpus v0's 119 rows but not hypothetical: checkov
already flags the exact data source a `data.` value would name
(`aws_iam_policy_document.policy`, four `CKV_AWS_*` findings in the
terraform fixture) and renders it without the `data.` prefix, so tfsec's
identity for the same resource must match that rendering exactly or the two
scanners' findings on it can never join. Unlike checkov's `resource`,
tfsec's never carries a Dockerfile path, a provider block or a secret hash in
corpus v0 - tfsec only ever flags real Terraform resources or their data
sources, so there are two recognized shapes and one fallback
(`<unresolved>`), not checkov's five-way classifier.

`location.filename` is where the real work is: tfsec reports it as an
**absolute** Windows path on all 119 findings
(`D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\db-app.tf`), where
checkov emits `/ec2.tf` and trivy emits `ec2.tf` for the same file (spec §1
consequence 1). `rebase_to_scan_root` (`scanners/base.py`) is what makes it
join checkov's and trivy's spelling of the same file - without it, the join
key is wrong for all 119 findings, not a handful. Acceptance gate 3 (spec
§10) is exactly this: every one of the 119 rebased paths must be string-equal
to what checkov and trivy report for the same files.

tfsec is Terraform-only - `tools/scanners.lock.json` declares its platform
matrix as `["terraform"]` alone - so `platform` is a constant here, not a
per-run detection the way `checkov._platform_of`/`trivy._platform_of` have to
be: those two scanners run against both scan roots and have to tell which one
produced a given array, tfsec never does. `index` is accepted only because
`ScannerAdapter.parse` is one signature for every platform; tfsec never
resolves a Kubernetes identity and so never reads it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from iacrisk import identity, rubric, taxonomy
from iacrisk.finding import NormalizedFinding
from iacrisk.resources import ResourceIndex
from iacrisk.scanners.base import AdapterResult, ScannerAdapter, rebase_to_scan_root

_TFSEC_RESOURCE_RE = re.compile(r"^(?P<type>[^.]+)\.(?P<name>[^.]+)(?:\.(?P<attribute>[^.]+))?$")
"""A Terraform `<type>.<name>` pair, with an optional third `.<attribute>` component.

Applied to the value **after** `_DATA_SOURCE_PREFIX` has already been
stripped by `_resolve_terraform`, so this pattern itself does not need to
know about `data.` at all - it only ever sees the managed-resource-shaped
remainder. Measured: 118 of 119 corpus v0 `resource` values are exactly
`<type>.<name>` (one dot), and the 119th, `AVD-AWS-0180`'s
`aws_db_instance.default.publicly_accessible`, is the only one carrying a
second dot. This pattern recognizes both shapes and nothing else - a value
with two or more trailing dots after the optional `data.` strip (never
observed in corpus v0) does not match and falls through to the unresolved
branch below rather than guessing which trailing component is the real
attribute. tfsec's own resource-address values never carry checkov's
ambiguity against a provider block (`aws.plain_text_access_keys_provider`):
tfsec does not flag provider blocks at all, so no disambiguating type/name
underscore check is needed here the way `checkov._TERRAFORM_ADDRESS_RE`
needs one.
"""

_DATA_SOURCE_PREFIX = "data."
"""tfsec's own spelling of a Terraform data-source address: `data.<type>.<name>`.

S1 §5.1: data sources stay outside the managed-resource scheme unless a
scanner flags one, in which case they render as `type.name` with no instance
key - the same bare form a managed resource takes, and deliberately without
a `data` marker of any kind. Corpus v0's tfsec fixture contains 0 `data.`
values (measured across all 119 `resource` strings), but the shape is not
speculative: checkov already flags `aws_iam_policy_document.policy`, a real
Terraform `data` block in the vendored corpus, and renders it exactly as
S1 §5.1 prescribes - no `data` component anywhere in the string. Stripping
this prefix before `_TFSEC_RESOURCE_RE` runs is what makes a future tfsec
finding on that same data source resolve to `aws_iam_policy_document.policy`
too, matching checkov's rendering rather than colliding every data source of
one type into `data.<type>` (which is also not `S1 §5.1`-shaped at all - it
discards the instance name entirely). A future reader must not "tidy" this
prefix back into the identity: dropping it is what makes tfsec's and
checkov's identities for one data source equal, not an oversight to restore.
"""

_CONTEXT_ELIGIBLE_KINDS = frozenset({"terraform", "kubernetes"})
"""The only two `identity_kind` values `context_eligible` may be `True` for (spec §2.1).

Restated here rather than imported from `checkov.py` or `trivy.py`, neither of
which exports it - each adapter module owns its own copy of this one-line
policy, matching the precedent both existing adapters already set.
"""


def _optional_str(value: object) -> str | None:
    """`None` stays `None`; anything else is coerced to `str`."""
    return None if value is None else str(value)


def _line_range(location: dict[str, Any]) -> tuple[int, int] | None:
    """tfsec's `location.start_line`/`end_line` as `(start, end)`, or `None`.

    Present as a pair on all 119 corpus v0 findings (measured), so this is a
    defensive fallback rather than a modeled corpus state - a malformed or
    absent range is carried as `None` (explicit-state discipline) rather than
    raised, matching `trivy._line_range`'s own reasoning for its equivalent
    pair of fields.
    """
    start = location.get("start_line")
    end = location.get("end_line")
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    return start, end


def _resolve_terraform(resource: object) -> tuple[str, str, str | None]:
    """tfsec's `resource` read as a terraform identity plus an optional fingerprint.

    Returns `(resource_identity, identity_kind, fingerprint)`. A leading
    `data.` is stripped first (S1 §5.1) - fixed round, corrected from an
    earlier version of this function that ran `_TFSEC_RESOURCE_RE` directly
    against the raw value. That version silently mis-parsed a data-source
    address: `data.aws_iam_policy_document.policy` has two dots, the exact
    shape `_TFSEC_RESOURCE_RE` already recognizes for the attribute-suffixed
    managed-resource case, so it matched with `type="data"`,
    `name="aws_iam_policy_document"`, `attribute="policy"` - a wrong identity
    that collides every data source of one type together, and a bogus
    fingerprint that is really the data source's own name. Stripping the
    prefix first, then running the same pattern against the remainder, is
    what turns that into the correct `type="aws_iam_policy_document"`,
    `name="policy"`, matching checkov's own rendering of the identical data
    source exactly.

    A value that is missing, not a string, or does not match
    `_TFSEC_RESOURCE_RE` after the optional strip resolves to
    `(identity.UNRESOLVED, "unresolved", None)` - tfsec has no file/provider/
    secret fallback the way trivy's Dockerfile case or checkov's five-way
    classifier do, because corpus v0 shows tfsec only ever naming a real
    Terraform resource or data source. A present-but-unrecognized shape is
    therefore stated as defensive rather than modeled: corpus v0 has no such
    value.
    """
    if not isinstance(resource, str) or not resource:
        return identity.UNRESOLVED, "unresolved", None
    value = resource.removeprefix(_DATA_SOURCE_PREFIX)
    match = _TFSEC_RESOURCE_RE.fullmatch(value)
    if match is None:
        return identity.UNRESOLVED, "unresolved", None
    resource_identity = identity.terraform_identity(match.group("type"), match.group("name"))
    return resource_identity, "terraform", match.group("attribute")


def _build_finding(
    result: dict[str, Any], scan_root: Path
) -> tuple[NormalizedFinding | None, str | None]:
    """One `results` entry turned into a finding, or the reason it could not be.

    `rule_id` is present and non-empty on every one of corpus v0's 119 results
    (measured), so the guard below is defensive rather than modeled - it exists
    so a future capture missing it is counted as `dropped` (`in == out +
    dropped`, spec §10 acceptance gate 6) instead of crashing the adapter run.
    """
    raw_rule_id = result.get("rule_id")
    if not raw_rule_id:
        return None, "rule_id missing or empty"
    rule_id = str(raw_rule_id)

    location = result.get("location") or {}
    raw_filename = str(location.get("filename") or "")
    file_path = rebase_to_scan_root(raw_filename, scan_root) if raw_filename else ""
    line_range = _line_range(location)

    resource_identity, identity_kind, fingerprint = _resolve_terraform(result.get("resource"))
    # `context_eligible` is derived from the kind alone, once resolution has
    # settled it - never from a provisional shape-only guess later downgraded,
    # matching trivy's shape rather than checkov's (task 7 brief).
    context_eligible = identity_kind in _CONTEXT_ELIGIBLE_KINDS

    native_severity = _optional_str(result.get("severity"))

    finding = NormalizedFinding(
        scanner="tfsec",
        rule_id=rule_id,
        canonical_rule_id=taxonomy.canonical_rule_id(rule_id),
        issue_class=taxonomy.class_for("tfsec", rule_id),
        title=str(result.get("rule_description") or ""),
        remediation=_optional_str(result.get("resolution")),
        native_severity=native_severity,
        severity_level=rubric.normalize_severity("tfsec", native_severity),
        platform="terraform",
        resource_identity=resource_identity,
        identity_kind=identity_kind,
        file_path=file_path,
        line_range=line_range,
        fingerprint=fingerprint,
        context_eligible=context_eligible,
    )
    return finding, None


class TfsecAdapter:
    """Turns one tfsec run's JSON into `NormalizedFinding` values (spec §5).

    `parse` reads `raw["results"]` directly rather than pre-classifying a
    platform the way `checkov.parse`/`trivy.parse` do, because tfsec's own
    platform matrix (`tools/scanners.lock.json`) is `["terraform"]` alone -
    there is no second platform's block that could appear in this array to
    detect. `index` is accepted to satisfy `ScannerAdapter` and never read.
    """

    name = "tfsec"

    def parse(self, raw: object, scan_root: Path, index: ResourceIndex | None) -> AdapterResult:
        document = raw if isinstance(raw, dict) else {}
        results = document.get("results") or []

        findings: list[NormalizedFinding] = []
        dropped: list[tuple[str, str]] = []

        for result in results:
            if not isinstance(result, dict):
                dropped.append(("", "results entry is not an object"))
                continue
            finding, reason = _build_finding(result, scan_root)
            if finding is None:
                dropped.append((str(result.get("rule_id") or ""), reason or "unknown"))
            else:
                findings.append(finding)

        return AdapterResult(findings=tuple(findings), dropped=tuple(dropped))


_conforms: ScannerAdapter = TfsecAdapter()
"""Never executed - a mypy-checked assertion that `TfsecAdapter` satisfies
`ScannerAdapter` structurally, matching `checkov.py`'s and `trivy.py`'s own
guards.
"""
