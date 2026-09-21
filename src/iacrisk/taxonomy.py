"""The issue-class taxonomy and the scanner-rule-ID mapping (design spec sections 1-2).

The taxonomy is the cross-cutting single source of truth: the mapping keys on it,
the rubric anchors against it, the evaluation test design is drawn over it, and
the dedupe key (spec section 5.4) carries it as one of three components.

This module is deliberately thin. taxonomy.json is the artifact; everything here
exists because a behaviour in the spec needs a function to carry it - chiefly the
`unmapped:` fallback of section 2.4, which is the PLAN Q9 explicit-state rule at
the taxonomy seam.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "taxonomy.json"

CATEGORIES = ("storage", "networking", "iam", "compute", "containers")
"""The five tested domains, in the order the spec presents them."""

UNMAPPED_PREFIX = "unmapped:"


@dataclass(frozen=True)
class IssueClass:
    """One issue class: an id, its category, a title, and a one-sentence definition."""

    id: str
    category: str
    title: str
    definition: str


@dataclass(frozen=True)
class MappingRow:
    """One observed `(scanner, rule_id)` and the class it maps to.

    Keyed on the raw rule id exactly as the scanner emitted it, never a
    pre-normalized key, so every row stays independently verifiable against the
    S0 fixtures (spec section 2.1). `canonical_id` is the cross-scanner form.
    """

    scanner: str
    rule_id: str
    canonical_id: str
    class_id: str
    title: str


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return parsed


@lru_cache(maxsize=1)
def classes() -> MappingProxyType[str, IssueClass]:
    """Every issue class, keyed by id. Read-only: one parse shared by all callers."""
    return MappingProxyType(
        {
            entry["id"]: IssueClass(
                id=entry["id"],
                category=entry["category"],
                title=entry["title"],
                definition=entry["definition"],
            )
            for entry in _document()["classes"]
        }
    )


@lru_cache(maxsize=1)
def mapping() -> MappingProxyType[tuple[str, str], MappingRow]:
    """Every observed rule, keyed by `(scanner, rule_id)`. Read-only."""
    return MappingProxyType(
        {
            (entry["scanner"], entry["rule_id"]): MappingRow(
                scanner=entry["scanner"],
                rule_id=entry["rule_id"],
                canonical_id=entry["canonical_id"],
                class_id=entry["class_id"],
                title=entry["title"],
            )
            for entry in _document()["mapping"]
        }
    )


def fallback_contract() -> MappingProxyType[str, Any]:
    """The `unmapped:` policy, as data (spec section 2.4).

    Shipped in the artifact rather than restated in S3 so the runtime cannot
    quietly adopt a different policy from the one the dissertation reports.
    """
    return MappingProxyType(dict(_document()["unmapped_fallback"]))


def canonical_rule_id(rule_id: str) -> str:
    """The cross-scanner form of a rule id: one leading ``AVD-`` removed.

    trivy emits ``AWS-0026`` and tfsec emits ``AVD-AWS-0026`` for the same Aqua
    rule (spec section 2.2), and corpus v0 holds 45 such twin pairs. Not every
    ``AVD-`` id has a trivy counterpart - ``AVD-AWS-0057``, ``AVD-AWS-0082`` and
    ``AVD-AWS-0088`` are tfsec-only - so canonicalization is a normalization, not
    evidence that a twin exists. Checkov ids carry no such prefix and are returned
    unchanged. `removeprefix` strips exactly one occurrence, which is why
    ``AVD-AVD-1`` becomes ``AVD-1`` rather than ``1``.
    """
    return rule_id.removeprefix("AVD-")


def class_for(scanner: str, rule_id: str) -> str:
    """The class id for an observed rule, or an explicit `unmapped:` id.

    A rule the table has never seen - a newer scanner version, an unseen rule -
    is named, counted, and surfaced as baseline-only informational. It is never
    dropped and never assigned a real class by guesswork (spec section 2.4).
    """
    row = mapping().get((scanner, rule_id))
    if row is None:
        return f"{UNMAPPED_PREFIX}{scanner}:{rule_id}"
    return row.class_id


def is_unmapped(class_id: str) -> bool:
    """Whether a class id is the explicit fallback state rather than a real class."""
    return class_id.startswith(UNMAPPED_PREFIX)
