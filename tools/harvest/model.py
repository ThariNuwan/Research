"""The only record type harvest produces."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InventoryRow:
    """One scanner rule firing, recorded verbatim.

    Deliberately shallow: no issue-class, no context, no score. Those belong
    to S3/S4 and depend on specs that do not exist yet.

    `frozen=True` is load-bearing rather than stylistic. It gives the class a
    value-based `__hash__` alongside the generated `__eq__`, and every field
    participates in both - which is what lets a later task put rows in a set to
    count how many distinct rule firings a scan produced. Adding a field with
    `field(compare=False)` would silently collapse rows that differ only in that
    field; `tests/harvest/test_model.py` asserts per-field that this has not
    happened.
    """

    scanner: str
    """Which scanner produced this: "checkov" | "trivy" | "tfsec"."""

    rule_id: str
    """The scanner's own rule identifier, unmodified."""

    native_severity: str | None
    """The scanner's own severity string, or None when it emitted none.

    None is a first-class state, never coerced to a default level
    (PLAN.md R3-#4). The rate of None is a reported metric.

    The annotation is the whole contract here. Nothing in this module can
    enforce the policy, because a walker that defaulted an absent severity to
    "LOW" would still be passing a `str`. The guard belongs to the walkers in
    Task 6, fed scanner JSON with the severity key absent.
    """

    target: str
    """File path exactly as the scanner reported it - separators unmodified.

    Preserved raw so S1's canonical-identity spec can be written against
    real observed path formats, including Windows backslashes.
    """

    case_id: str
    """The corpus.lock.json case that produced this row.

    Assigned by the `attribution` rule in tools/corpus.lock.json, not by which
    directory was scanned: the four Terraform cases share one `scan_root`, so a
    row's case is decided by matching the scanner's reported file against each
    case's `path`. A row under a scan root that no case `path` claims carries the
    explicit `unattributed` state that rule defines.
    """
