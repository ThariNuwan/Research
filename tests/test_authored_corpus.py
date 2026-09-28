"""S2 Task 2: the hand-crafted authored-root cases (task brief step 5, as revised by fix round 1).

`corpus/authored/` holds the two factors corpus v0 cannot isolate at all:
IAM privilege breadth (`iam_privilege.tf`, this module's main subject) and
the second Exposure pair (`storage_public_exposure.tf`, design spec section
4's "why buckets rather than security groups"). (A severity-spread case was
authored alongside the privilege one and then removed - R9 - once
measurement showed no same-type resource pair in this corpus or v0 can
differ in severity within an identical issue-class set without the class
set itself changing; that reasoning lives in the S2 design spec, not here.)
This module scans the whole authored root through the same adapters the
rest of the pipeline uses (`CheckovAdapter`, `TfsecAdapter`, `TrivyAdapter`),
against the raw JSON captured under `tests/harvest/fixtures/authored/`, and
asserts against what that scan actually produced - never a literal restating
what one particular run happened to find, per the dispatch's own warning
about a class-specific test passing for the wrong reason.

R4 (task dispatch ruling): the fixture-integrity assertion for corpus v0's six
*existing* fixtures is deliberately not written here. It is a controller-side
check made once, after this task's commits land, against a HEAD that this
task's own commits move - not a property of the code under test.

R8 (fix round 1): the first draft of the three IAM policies varied *action
family* across the three resources (a specific S3 read, then `s3:*`, then
`*`) to guarantee each one drew a finding. That broke the breadth-only
premise the pair rests on: the narrowest and middle resources shared no
issue class at all, and the narrowest's class was arguably the more severe
of the two - a difference in *kind*, not degree. All three resources now stay
in one action family (`s3:*`, escalating only in `Resource` breadth, then
`*` on `*` as the ceiling), so breadth is the only variable and their
issue-class sets nest.
"""

from __future__ import annotations

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

# Ordered narrowest to broadest, matching the resource shapes in
# corpus/authored/iam_privilege.tf: same action family (`s3:*`, then `*` as
# the ceiling), escalating only in `Resource` breadth.
ORDERED_IAM_POLICIES = (
    "aws_iam_policy.s3_bucket_scope",
    "aws_iam_policy.s3_account_scope",
    "aws_iam_policy.unrestricted_scope",
)

# The two authored S3 buckets (corpus/authored/storage_public_exposure.tf) -
# the second Exposure pair's hand-crafted cases.
AUTHORED_STORAGE_BUCKETS = (
    "aws_s3_bucket.private_baseline",
    "aws_s3_bucket.public_exposed",
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


def _issue_classes(findings: tuple[NormalizedFinding, ...], resource: str) -> frozenset[str]:
    return frozenset(f.issue_class for f in findings if f.resource_identity == resource)


# --------------------------------------------------------------------------
# Every authored aws_iam_policy resource was actually scanned.
# --------------------------------------------------------------------------


def test_every_iam_policy_resource_has_at_least_one_finding() -> None:
    """No privilege case is silently unscanned (task brief step 5, bullet 1).

    Measured while first authoring this fixture: a policy granting one S3
    read action on one specific object-prefix ARN drew zero findings from
    all three scanners. That is a correct scanner outcome, not a defect (a
    correctly-scoped policy is a true negative), but it would leave a case
    silently unscanned, which is exactly what this assertion exists to
    catch. Each of the three resources below carries at least one measured
    finding (2, 7 and 11 respectively at authoring time).
    """
    identities = {finding.resource_identity for finding in _all_findings()}
    for resource in ORDERED_IAM_POLICIES:
        assert resource in identities, f"{resource} drew no finding from any of the three scanners"


def test_every_authored_storage_bucket_has_at_least_one_finding() -> None:
    """No storage-exposure case is silently unscanned, mirroring the IAM guard above.

    `s3-private-baseline-not-public`'s own notes record that its
    public-access-block sibling (`aws_s3_bucket_public_access_block.private_baseline`)
    draws zero findings from any of the three scanners - a genuine absence,
    not a defect. That is a property of the sibling resource, not of the
    bucket itself: both `aws_s3_bucket.private_baseline` and
    `aws_s3_bucket.public_exposed` must still draw at least one finding each,
    or the pair's low side would be a case with no findings at all - the
    "cannot enter a contrastive pair" constraint design spec section 4
    records.
    """
    identities = {finding.resource_identity for finding in _all_findings()}
    for resource in AUTHORED_STORAGE_BUCKETS:
        assert resource in identities, f"{resource} drew no finding from any of the three scanners"


# --------------------------------------------------------------------------
# The three privilege cases nest: each broader policy's issue classes are a
# strict superset of the narrower one's.
# --------------------------------------------------------------------------


def test_privilege_classes_strictly_nest_with_increasing_breadth() -> None:
    """Each broader resource's issue-class set is a strict superset of the narrower one's (R8).

    This is the property the authored pair rests on, not a specific class
    name: `s3_bucket_scope`'s classes must be a proper subset of
    `s3_account_scope`'s, and `s3_account_scope`'s a proper subset of
    `unrestricted_scope`'s. A proper-subset relation implies the two sets
    differ (so a broader resource is never merely a relabeling of a
    narrower one) and orders that difference in the one direction breadth
    is supposed to move - a same-size or shrinking class set as breadth
    increases would fail this even if the sets were merely unequal.
    """
    findings = _all_findings()
    class_sets = [_issue_classes(findings, resource) for resource in ORDERED_IAM_POLICIES]

    for narrower_resource, broader_resource, narrower_classes, broader_classes in zip(
        ORDERED_IAM_POLICIES, ORDERED_IAM_POLICIES[1:], class_sets, class_sets[1:], strict=False
    ):
        assert narrower_classes < broader_classes, (
            f"{narrower_resource}'s issue classes {sorted(narrower_classes)} are not a "
            f"proper subset of {broader_resource}'s {sorted(broader_classes)}"
        )
