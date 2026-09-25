"""The record S0 refused to define, because it depends on a taxonomy that did not exist.

Every explicit state S1 established has to survive into this record: unmapped
classes, unknown severity, unresolved identity. S3a adds one more - an unresolved
violation fingerprint - and the tests below are what stop any of them being
collapsed into a convenient default.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from iacrisk import taxonomy
from iacrisk.finding import IDENTITY_KINDS, PLATFORMS, UNMAPPED_PREFIX, NormalizedFinding

BASE: dict[str, Any] = {
    "scanner": "checkov",
    "rule_id": "CKV_AWS_133",
    "canonical_rule_id": "CKV_AWS_133",
    "issue_class": "storage-data-recoverability",
    "title": "Ensure that RDS instances has backup policy",
    "remediation": None,
    "native_severity": None,
    "severity_level": "unknown",
    "platform": "terraform",
    "resource_identity": "aws_db_instance.default",
    "identity_kind": "terraform",
    "file_path": "db-app.tf",
    "line_range": (1, 42),
    "fingerprint": "backup_retention_period",
    "context_eligible": True,
}


def test_the_record_is_frozen_and_hashes_by_value() -> None:
    """Later tasks put findings in sets to count distinct ones, so value hashing is load-bearing."""
    a = NormalizedFinding(**BASE)
    b = NormalizedFinding(**BASE)

    assert a == b
    assert len({a, b}) == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.scanner = "trivy"  # type: ignore[misc]


@pytest.mark.parametrize("field", list(BASE))
def test_every_field_discriminates(field: str) -> None:
    """No field may be excluded from equality - that would silently merge distinct findings."""
    varied = dict(BASE)
    current = varied[field]
    varied[field] = (
        "varied" if isinstance(current, str) else (None if current is not None else "was-none")
    )
    if field == "context_eligible":
        varied[field] = False
    if field == "line_range":
        varied[field] = (9, 9)

    assert NormalizedFinding(**BASE) != NormalizedFinding(**varied), (
        f"{field} does not participate in equality"
    )


def test_unknown_severity_is_the_literal_string_not_a_number() -> None:
    """PLAN Q9: an undetermined severity is a state, not a low score."""
    finding = NormalizedFinding(**BASE)

    assert finding.severity_level == "unknown"
    assert not isinstance(finding.severity_level, int)


def test_a_numeric_severity_is_allowed_too() -> None:
    finding = NormalizedFinding(**{**BASE, "severity_level": 4})

    assert finding.severity_level == 4


def test_is_unmapped_reads_the_class_not_a_separate_flag() -> None:
    """One source of truth: the class id carries the state, so the two cannot disagree."""
    mapped = NormalizedFinding(**BASE)
    unmapped = NormalizedFinding(**{**BASE, "issue_class": "unmapped:checkov:CKV_AWS_9999"})

    assert not mapped.is_unmapped
    assert unmapped.is_unmapped


def test_an_unresolved_fingerprint_is_none_and_is_reported_as_such() -> None:
    """Dedupe tier 1 turns on this property; a sentinel string would collapse wrongly."""
    resolved = NormalizedFinding(**BASE)
    unresolved = NormalizedFinding(**{**BASE, "fingerprint": None})

    assert resolved.has_resolved_fingerprint
    assert not unresolved.has_resolved_fingerprint
    assert unresolved.fingerprint is None


def test_the_vocabularies_are_closed() -> None:
    """A new identity kind or platform should be a deliberate edit, not an accident."""
    assert IDENTITY_KINDS == ("terraform", "kubernetes", "file", "provider", "secret", "unresolved")
    assert PLATFORMS == ("terraform", "kubernetes")


def test_the_unmapped_prefix_agrees_with_the_taxonomy_module() -> None:
    """finding.py restates the prefix rather than importing taxonomy's I/O machinery.

    That is a reasonable trade, but an unguarded duplicate is one edit away from
    `is_unmapped` silently returning False for every unmapped finding. This is
    the cheap guard that makes the duplication safe.
    """
    assert UNMAPPED_PREFIX == taxonomy.UNMAPPED_PREFIX


def test_a_non_resource_finding_is_marked_context_ineligible() -> None:
    """Spec 2.1: no resource means nothing for S3b to contextualize.

    Without the flag these findings would reach S4 with all five context factors
    defaulted, and the defaults sum to 16 - landing every one of them at 17-21,
    always High, for structural reasons rather than on merit.
    """
    secret = NormalizedFinding(
        **{
            **BASE,
            "issue_class": "iam-hardcoded-secrets",
            "resource_identity": "fc3f784491eba6121c3bfcc1652a2c57d27b16cb",
            "identity_kind": "secret",
            "context_eligible": False,
        }
    )

    assert secret.identity_kind == "secret"
    assert secret.context_eligible is False
