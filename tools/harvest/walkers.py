"""One walker per scanner JSON schema. Pure functions - no I/O, no subprocess.

Every field path here was read off the six fixtures in `tests/harvest/fixtures/`
rather than off documentation, and `tests/harvest/test_walkers.py` holds each
walker to the exact row count those bytes produce at the versions pinned in
`tools/scanners.lock.json`. That is the drift tripwire PLAN.md names for scanner
schema change: a renamed or moved field changes a count, and a changed count
fails.

`target` is recorded **verbatim** - whatever string the scanner put in its path
field, byte for byte. No `Path()` round-trip, no separator folding, no stripping
of a leading separator. The three scanners disagree with each other, and checkov
disagrees with itself: measured on `checkov-terraform.json`, its `terraform`
block spells one file `\\ec2.tf` while the `secrets` block of the *same run*
spells it `/ec2.tf`; trivy reports scan-root-relative forward slashes
(`resources/Dockerfile`); tfsec reports an absolute native path
(`D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\db-app.tf`). A walker
that normalized would destroy the evidence that they disagree. Canonical
identity is S1's spec to write with these fixtures in hand, not a decision to
make here by accident.

Deliberately absent: any reading of an exit code, and any status filter. trivy
exits 0 carrying 447 findings while checkov and tfsec exit 1 on findings, and
tfsec exits 0 with zero findings off-platform - so exit status is a findings
signal for no scanner here. No function in this module sees a process at all;
that is Task 8's runner, and nothing below should be read as an opinion about
one.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from tools.harvest.model import InventoryRow

Walker = Callable[[Any, str], list[InventoryRow]]


def _clean(value: Any) -> str | None:
    """Absent-or-blank severity becomes None; every other string is kept verbatim.

    None means the scanner said *nothing*: a missing key, JSON null, `""`, or
    whitespace. It never means "the scanner said something unhelpful". A level is
    never substituted for an absent one (PLAN.md R3-#4) - the rate of None is a
    reported S0 metric, and checkov's is 100% at this pin, so a default would not
    be a small distortion, it would be the entire checkov column.

    `"UNKNOWN"` is therefore preserved, not folded into None. It is a real value
    in trivy's own severity vocabulary, and collapsing it would make *the scanner
    said UNKNOWN* indistinguishable from *the scanner said nothing* - two facts
    S3's normalization spec has to tell apart, since that spec does not exist yet
    and will be written from the distribution S0 records. The literal strings
    `"NONE"` and `"NULL"` are preserved for the same reason.

    Unobserved-but-permitted: no fixture contains `"UNKNOWN"`, `"NONE"` or
    `"NULL"` in a severity field, and no fixture omits a severity key. The
    vocabulary measured across all 1600 checkov checks and 447 trivy
    misconfigurations is null / CRITICAL / HIGH / MEDIUM / LOW and nothing else.
    `test_walkers.py` unit-tests all four inputs against this function's
    contract; nothing here claims a scanner in this corpus emitted one.
    """
    if value is None:
        return None
    # str(): unobserved coercion. Severity is a JSON string or null in all six
    # fixtures; nothing in the corpus reaches this with a number or a bool.
    return str(value).strip() or None


def walk_checkov(doc: Any, case_id: str) -> list[InventoryRow]:
    """checkov: an array of per-framework blocks, each `{"results": {"failed_checks": [...]}}`.

    Measured: the terraform root produced three blocks - `terraform`,
    `dockerfile`, `secrets` - and the kubernetes root two - `kubernetes`,
    `secrets`. The array is therefore one block per framework checkov *detected
    inside one scan root*, not one per platform and not one per run. Every block
    is walked and `check_type` is never filtered on: dropping `dockerfile` and
    `secrets` would silently discard 8 of the 489 failed checks.

    Only `failed_checks` are findings. `passed_checks` (1111 across the two
    fixtures) and `skipped_checks` (0) are not; reading them would inflate the
    inventory more than threefold.

    `severity` is null on all 489 failed and all 1111 passed checks at this pin,
    which is what `_clean` may never paper over with a default level.
    """
    # Unobserved: `stdout_top_level` is "array" for both checkov captures in
    # artifacts/scanner-behavior.json, so the single-object branch is defensive.
    documents: Iterable[Any] = doc if isinstance(doc, list) else [doc]
    rows: list[InventoryRow] = []
    for document in documents:
        # Unobserved: every element of both arrays is a JSON object.
        if not isinstance(document, dict):
            continue
        results = document.get("results") or {}
        for check in results.get("failed_checks") or []:
            rule_id = check.get("check_id")
            # Unobserved: `check_id` is present and non-empty on all 489 failed
            # checks. Kept as a skip rather than an error because Task 6 invents
            # no error policy; the golden row-count assertions are what stop a
            # skip here from being silent.
            if not rule_id:
                continue
            rows.append(
                InventoryRow(
                    scanner="checkov",
                    rule_id=str(rule_id),
                    native_severity=_clean(check.get("severity")),
                    # Verbatim. `file_path` is scan-root-relative with a leading
                    # separator, and mixes separators - `/batch-check\job.yaml`
                    # on 1262 of 1262 kubernetes checks. See the module docstring.
                    target=str(check.get("file_path") or ""),
                    case_id=case_id,
                )
            )
    return rows


def walk_trivy(doc: Any, case_id: str) -> list[InventoryRow]:
    """trivy: `{"Results": [{"Target": ..., "Misconfigurations": [...]}]}`.

    Measured: `Results` is a list of 14 entries (terraform) and 18 (kubernetes),
    carrying 115 + 332 = 447 misconfigurations, every one of them
    `"Status": "FAIL"`. The captured argv did not ask for passing checks, so no
    status filter is applied here - one would be untested policy over a field
    whose other values this corpus has never seen.

    One terraform entry and two kubernetes entries carry **no
    `Misconfigurations` key at all**; the terraform one is `"Target": "."`, a
    per-directory summary. `.get(...) or []` covers an absent key and a null
    alike.

    The rule id is `Misconfigurations[].ID`, and at this pin it is *not*
    AVD-prefixed: `AWS-0028`, `KSV-0001`. Measured, the literal `AVD-` appears
    zero times in either trivy fixture and no record carries an `AVDID` key. A
    fallback to `AVDID` was deliberately **not** kept: it would absorb a future
    rename of `ID` without moving the row count, which is precisely the drift the
    golden test exists to catch.
    """
    rows: list[InventoryRow] = []
    # Unobserved: both trivy fixtures parse to an object (`stdout_top_level`).
    if not isinstance(doc, dict):
        return rows
    # Unobserved: `Results` is a non-empty list in both fixtures. `or []` also
    # covers the null shape, which this corpus never produced - so nothing here
    # claims to know what trivy emits when it finds nothing scannable.
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        # Verbatim: scan-root-relative, forward slashes only, no leading
        # separator - `db-app.tf`, `resources/Dockerfile`.
        target = str(result.get("Target") or "")
        for misconf in result.get("Misconfigurations") or []:
            rule_id = misconf.get("ID")
            # Unobserved: `ID` is present and non-empty on all 447 records.
            if not rule_id:
                continue
            rows.append(
                InventoryRow(
                    scanner="trivy",
                    rule_id=str(rule_id),
                    native_severity=_clean(misconf.get("Severity")),
                    target=target,
                    case_id=case_id,
                )
            )
    return rows


def walk_tfsec(doc: Any, case_id: str) -> list[InventoryRow]:
    """tfsec: `{"results": [{"rule_id": ..., "severity": ..., "location": {...}}]}`.

    Measured: 119 results on the terraform root, and `{"results": []}` - an
    **empty array**, not null - on the off-matrix kubernetes root, at exit 0 and
    with the same 365 stderr bytes as the successful run. Nothing in that document
    distinguishes "scanned and found nothing" from "cannot read this platform",
    which is why `tools/scanners.lock.json` pins tfsec terraform-only and why the
    registry test reads that lockfile instead of restating the matrix.

    `rule_id` is the AVD id - `AVD-AWS-0099` - present on all 119. `long_id` is a
    *different* identifier in a *different* namespace
    (`aws-ec2-add-description-to-security-group`), also present on all 119, and it
    is deliberately not a fallback: an `or long_id` would put two kinds of
    identifier in one column without moving the row count, so no golden assertion
    could see it happen.

    `location.filename` is an absolute native path on all 119, unlike checkov's
    scan-root-relative `file_path` and trivy's forward-slash `Target`. Recorded
    as-is; see the module docstring.
    """
    rows: list[InventoryRow] = []
    # Unobserved: both tfsec fixtures parse to an object.
    if not isinstance(doc, dict):
        return rows
    # `or []` also covers `"results": null`, a shape this corpus never produced -
    # the kubernetes capture emitted an empty array. Defensive, and not evidence
    # of anything about how tfsec reports a clean or unreadable target.
    for result in doc.get("results") or []:
        if not isinstance(result, dict):
            continue
        rule_id = result.get("rule_id")
        # Unobserved: `rule_id` is present and non-empty on all 119 results.
        if not rule_id:
            continue
        location = result.get("location") or {}
        rows.append(
            InventoryRow(
                scanner="tfsec",
                rule_id=str(rule_id),
                native_severity=_clean(result.get("severity")),
                target=str(location.get("filename") or ""),
                case_id=case_id,
            )
        )
    return rows


WALKERS: dict[str, Walker] = {
    "checkov": walk_checkov,
    "trivy": walk_trivy,
    "tfsec": walk_tfsec,
}


def walk(scanner: str, doc: Any, case_id: str) -> list[InventoryRow]:
    """Dispatch to the walker for `scanner`. Raises KeyError if unregistered.

    `case_id` is stamped onto every row this call produces, unconditionally and
    without interpretation. `walk()` does not read `tools/corpus.lock.json`, does
    not parse `target` to guess a case, and does not implement the `attribution`
    rule that `InventoryRow.case_id`'s docstring describes. It could not: one
    document routinely spans several cases, because the four Terraform cases share
    a single `scan_root` and are scanned once between them.

    **Rows out of here are not attributed rows.** Deciding what to pass -
    including the explicit `unattributed` state the lockfile's `attribution` rule
    defines - belongs to the later task that walks the corpus, and that task has
    real work to do: checkov's kubernetes `file_path` values carry no corpus
    prefix at all, so matching them to a case by prefix against
    `corpus/vendor/...` matches none of the 1262.

    The KeyError is raised explicitly rather than left to `WALKERS[scanner]`,
    whose message is the bare key and says nothing about what would have worked.
    """
    try:
        walker = WALKERS[scanner]
    except KeyError:
        raise KeyError(
            f"no walker registered for scanner {scanner!r}; registered: {sorted(WALKERS)}"
        ) from None
    return walker(doc, case_id)
