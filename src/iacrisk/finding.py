"""The normalized finding record (design spec section 2).

S0 deliberately refused to define this record because it depends on the
issue-class taxonomy, and that taxonomy did not exist until S1. Every adapter
in this sub-project (checkov, trivy, tfsec) converges on this one shape, so
it is where S1's explicit-state discipline either survives into the pipeline
or gets quietly lost: an unmapped rule, an unknown severity, an unresolved
identity or fingerprint must each stay a first-class, inspectable value here
rather than collapse into a default that reads as more certain than the
scan actually was. S3b's contextual attributes are deliberately absent -
this record only carries what layers 1-2 and dedupe produce.
"""

from __future__ import annotations

from dataclasses import dataclass

IDENTITY_KINDS = ("terraform", "kubernetes", "file", "provider", "secret", "unresolved")
"""The closed vocabulary for `NormalizedFinding.identity_kind`.

Closed rather than a free-form string so a new kind is a deliberate edit to
this tuple (and to whatever consumes it), never an accidental new spelling
drifting in from an adapter.
"""

PLATFORMS = ("terraform", "kubernetes")
"""The closed vocabulary for `NormalizedFinding.platform` (spec §2's field table)."""

UNMAPPED_PREFIX = "unmapped:"
"""Mirrors `taxonomy.UNMAPPED_PREFIX`. Restated here, not imported, so this module's
`is_unmapped` reads the same string the taxonomy writes without pulling that module's
I/O and caching machinery into a record type that has none of its own.
"""


@dataclass(frozen=True)
class NormalizedFinding:
    """One scanner finding, reshaped into the common record every later stage consumes.

    Frozen for value equality and hashing, and every field listed here
    participates in `__eq__` and `__hash__` by dataclass default - none is
    excluded as incidental. That matters for bookkeeping over whole records,
    such as Task 8's accounting check that every input finding ends up in
    exactly one dedupe group or standing alone.

    It is deliberately NOT what performs deduplication. Tier 1 groups on the
    derived key `(resource_identity, issue_class, fingerprint)` (spec §7),
    and two findings that must collapse are by definition reported by
    different scanners - so they differ in `scanner` and usually `rule_id`,
    `title`, `native_severity` and `remediation` too, and remain two distinct
    records under this dataclass's own equality however equal their dedupe
    key. A `set()` of raw records cannot perform that collapse; Task 8 groups
    by the derived key, not by record identity.

    `native_severity` is the scanner's own string (or `None` where the scanner
    supplied none, per corpus v0's measured Checkov gap); `severity_level` is
    the normalized value derived from it, `int` when a mapping exists and the
    literal string `"unknown"` when it does not (PLAN Q9) - never a number
    standing in for "we don't know".

    `resource_identity` is the canonical string from `identity.py`, including
    its own `UNRESOLVED` sentinel for a component that could not be resolved;
    `identity_kind` says what shape that identity is, and `secret` /
    `unresolved` mark the cases with no addressable cloud resource at all.

    `fingerprint` is the Q8 dedupe key's third component (`identity.dedupe_key`;
    spec §7). `fingerprint is None` is a distinct, explicit state - unresolved,
    not merely absent - and is exactly what `has_resolved_fingerprint` and
    Task 8's tier-1 dedupe test for; nothing here coerces it to a placeholder
    string, which would silently pull unrelated findings together.
    """

    scanner: str
    rule_id: str
    canonical_rule_id: str
    issue_class: str
    title: str
    remediation: str | None
    native_severity: str | None
    severity_level: int | str
    platform: str
    resource_identity: str
    identity_kind: str
    file_path: str
    line_range: tuple[int, int] | None
    fingerprint: str | None
    context_eligible: bool

    @property
    def is_unmapped(self) -> bool:
        """Whether `issue_class` is the `unmapped:` fallback rather than a taxonomy class.

        Reads `issue_class` itself instead of a separately-stored flag, so the
        two cannot be constructed to disagree (mirrors `taxonomy.is_unmapped`,
        whose `unmapped:` fallback contract is S1 spec §2.4).
        """
        return self.issue_class.startswith(UNMAPPED_PREFIX)

    @property
    def has_resolved_fingerprint(self) -> bool:
        """Whether `fingerprint` is a resolved value rather than the `None` unresolved state.

        This is what Task 8's dedupe tier turns on: only findings with a
        resolved fingerprint are eligible to collapse into the reported count.
        """
        return self.fingerprint is not None
