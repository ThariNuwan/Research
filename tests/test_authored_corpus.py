"""S2 Task 2: the hand-crafted privilege and severity cases (task brief step 5).

`corpus/authored/` holds the two factors corpus v0 cannot isolate - IAM
privilege breadth and same-class severity spread - because it is authored
against the taxonomy rather than vendored. This module scans it through the
same adapters the rest of the pipeline uses (`CheckovAdapter`, `TfsecAdapter`,
`TrivyAdapter`), against the raw JSON captured under
`tests/harvest/fixtures/authored/`, and asserts against what that scan
actually produced - never a literal restating what one particular run
happened to find, per the dispatch's own warning about a class-specific test
passing for the wrong reason.

R4 (task dispatch ruling): the fixture-integrity assertion for corpus v0's six
*existing* fixtures is deliberately not written here. It is a controller-side
check made once, after this task's commits land, against a HEAD that this
task's own commits move - not a property of the code under test.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

from iacrisk.finding import NormalizedFinding
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures" / "authored"
SCAN_ROOT = REPO_ROOT / "corpus" / "authored"

IAM_POLICY_RESOURCES = (
    "aws_iam_policy.narrow_scope",
    "aws_iam_policy.moderate_scope",
    "aws_iam_policy.broad_scope",
)


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _all_findings() -> tuple[NormalizedFinding, ...]:
    """Every finding the three adapters produce over the authored fixtures.

    `index=None` for all three: identity for terraform comes from the
    scanner's own field (`iacrisk.scanners.base.ScannerAdapter`'s own
    docstring), so no `ResourceIndex` is needed for a terraform-only root -
    the same call shape `tests/scanners/test_checkov.py` and its siblings use
    against the corpus v0 terraform fixtures.
    """
    checkov_result = CheckovAdapter().parse(
        _load_fixture("checkov-terraform.json"), SCAN_ROOT, None
    )
    tfsec_result = TfsecAdapter().parse(_load_fixture("tfsec-terraform.json"), SCAN_ROOT, None)
    trivy_result = TrivyAdapter().parse(_load_fixture("trivy-terraform.json"), SCAN_ROOT, None)
    return checkov_result.findings + tfsec_result.findings + trivy_result.findings


# --------------------------------------------------------------------------
# Every authored aws_iam_policy resource was actually scanned.
# --------------------------------------------------------------------------


def test_every_iam_policy_resource_has_at_least_one_finding() -> None:
    """No privilege case is silently unscanned (task brief step 5, bullet 1).

    Measured while authoring this fixture: a policy granting one S3 read
    action on one specific object-prefix ARN - the brief's own first draft of
    `narrow_scope` - drew zero findings from all three scanners. That is a
    correct scanner outcome, not a defect (a correctly-scoped policy is a true
    negative), but it left `narrow_scope` silently unscanned, which is exactly
    what this assertion exists to catch. `narrow_scope` now grants
    `sts:GetSessionToken`, an action AWS itself only ever permits with
    `Resource: "*"` - not a breadth choice on our part, an IAM constraint on
    that action - which checkov's credentials-exposure check still flags.
    """
    identities = {finding.resource_identity for finding in _all_findings()}
    for resource in IAM_POLICY_RESOURCES:
        assert resource in identities, f"{resource} drew no finding from any of the three scanners"


# --------------------------------------------------------------------------
# The three privilege cases are distinguishable from one another.
# --------------------------------------------------------------------------


def test_privilege_cases_are_distinguishable() -> None:
    """narrow_scope, moderate_scope and broad_scope each look different to the pipeline.

    Task brief step 5, bullet 2: "the set of issue classes or the count of
    findings differs across narrow_scope, moderate_scope, broad_scope."
    Computes both signatures per resource and asserts all three are pairwise
    distinct - not just that some pair differs, which a two-resource collision
    could still satisfy by accident.
    """
    findings = _all_findings()
    signatures: dict[str, tuple[int, frozenset[str]]] = {}
    for resource in IAM_POLICY_RESOURCES:
        matching = [f for f in findings if f.resource_identity == resource]
        signatures[resource] = (len(matching), frozenset(f.issue_class for f in matching))

    distinct_signatures = set(signatures.values())
    assert len(distinct_signatures) == len(IAM_POLICY_RESOURCES), (
        f"privilege cases are not pairwise distinguishable: {signatures}"
    )


# --------------------------------------------------------------------------
# The severity-pair property: two findings, one issue_class, different levels.
# --------------------------------------------------------------------------


def test_two_findings_share_an_issue_class_at_different_severity_levels() -> None:
    """The property the authored severity pair rests on (task brief step 5, bullet 3).

    Asserts the property itself - two findings sharing one `issue_class` with
    two different *integer* `severity_level`s - rather than a specific class
    name. A test naming `storage-key-management-cmk` directly would pass for
    the wrong reason the moment a re-scan (a scanner upgrade, say) picked a
    different class, which is exactly the failure mode the task dispatch
    warns against. `severity_level` is `int | str` (`"unknown"` for checkov,
    which never carries a native severity in this corpus - CLAUDE.md); only
    the `int` values are comparable at all, so the `"unknown"` string values
    are excluded from the search rather than silently coerced.
    """
    findings = _all_findings()
    with_known_severity = [f for f in findings if isinstance(f.severity_level, int)]

    found_pair = any(
        left.issue_class == right.issue_class and left.severity_level != right.severity_level
        for left, right in itertools.combinations(with_known_severity, 2)
    )
    assert found_pair, (
        "no two findings share one issue_class at two different integer severity_levels: "
        f"{[(f.issue_class, f.severity_level) for f in with_known_severity]}"
    )
