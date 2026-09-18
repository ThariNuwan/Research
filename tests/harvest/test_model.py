"""InventoryRow is deliberately minimal - it is not S3's normalized finding.

Every assertion here is labelled shape or content in the task report. The one
that is neither a guard nor content - `test_missing_severity_is_none_...` - says
so in its own docstring rather than letting its name imply a guard it is not.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from tools.harvest.model import InventoryRow

# One complete row, as a dict so a test can vary exactly one field and leave the
# other four byte-identical. A field renamed on the dataclass makes
# `InventoryRow(**BASE_FIELDS)` raise TypeError, so these dicts cannot drift
# silently out of step with the model.
BASE_FIELDS: dict[str, Any] = {
    "scanner": "trivy",
    "rule_id": "AVD-AWS-0001",
    "native_severity": "HIGH",
    "target": "s3.tf",
    "case_id": "tg-aws-s3",
}

# What each field becomes in the one-field-different variant. Every value differs
# from its BASE_FIELDS counterpart, and `native_severity` varies to None rather
# than to another string so the None state is inside the discrimination check too.
VARIED_FIELDS: dict[str, Any] = {
    "scanner": "checkov",
    "rule_id": "CKV_AWS_18",
    "native_severity": None,
    "target": "ec2.tf",
    "case_id": "tg-aws-compute",
}


def test_row_is_frozen_and_hashable() -> None:
    """Immutability, and hashing by value rather than by identity.

    `len({row, row}) == 1` cannot distinguish a correct `__hash__` from a
    degenerate one - a set holding the same object twice has one element by
    identity alone. Two separately constructed instances carrying equal field
    values test the property a later task actually relies on when it puts rows in
    a set to count distinct rule firings.
    """
    row = InventoryRow(**BASE_FIELDS)
    twin = InventoryRow(**BASE_FIELDS)
    assert dataclasses.is_dataclass(row)
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.scanner = "checkov"  # type: ignore[misc]
    # Asserted before the set, or the set collapsing would prove nothing.
    assert row is not twin, "the two rows must be distinct for the set below to mean anything"
    assert row == twin, "equal field values must compare equal"
    assert hash(row) == hash(twin), "equal rows must hash equal"
    assert len({row, twin}) == 1


@pytest.mark.parametrize("field_name", sorted(BASE_FIELDS))
def test_every_field_participates_in_equality_and_hashing(field_name: str) -> None:
    """Content: the other half of hashing - that it discriminates, not just agrees.

    `test_row_is_frozen_and_hashable` is satisfied by a degenerate
    `__eq__`/`__hash__` pair that treats every row as equal to every other. This
    is what refuses that: for each of the five fields in turn, two rows differing
    in that field alone must stay two rows. It fails on `field(compare=False)`, on
    a hand-written `__eq__` that forgets a field, and on `eq=False`.
    """
    base = InventoryRow(**BASE_FIELDS)
    variant = InventoryRow(**{**BASE_FIELDS, field_name: VARIED_FIELDS[field_name]})
    # The variation landed, asserted before its consequence.
    assert getattr(base, field_name) != getattr(variant, field_name), (
        f"{field_name} is identical in both rows; the assertions below would hold "
        "for a reason that has nothing to do with equality"
    )
    assert base != variant, f"rows differing only in {field_name} compare equal"
    assert len({base, variant}) == 2, f"rows differing only in {field_name} hash together"


def test_missing_severity_is_none_never_a_default_level() -> None:
    """PLAN.md R3-#4: absent severity is an explicit state, never silently low.

    A documentation assertion, NOT a guard, and named here as such. It pins the
    annotation as `str | None` and records the intent, but the body only checks
    that a dataclass returns the value it was constructed with - true of every
    dataclass ever written. Nothing in this module can enforce the policy: a
    walker that defaulted an absent severity to "LOW" would pass a `str` and this
    test would never see it. The real guard is Task 6's, over a walker fed scanner
    JSON with the severity key absent.
    """
    row = InventoryRow(
        scanner="checkov",
        rule_id="CKV_AWS_1",
        native_severity=None,
        target="s3.tf",
        case_id="tg-aws-s3",
    )
    assert row.native_severity is None


def test_row_has_no_scored_or_normalized_fields() -> None:
    """Guards the S0/S3 boundary: no context, no score, no issue-class here.

    Content. Set equality, not a subset test, so it fails on an added field and on
    a removed one alike - the model of what a content assertion looks like.
    """
    fields = {f.name for f in dataclasses.fields(InventoryRow)}
    assert fields == {"scanner", "rule_id", "native_severity", "target", "case_id"}
