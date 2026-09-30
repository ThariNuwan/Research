"""S3b acceptance gates (design spec section 10).

Every figure these gates assert is derived from the committed golden fixtures
(`tests/harvest/fixtures/`) and the vendored corpus, never restated from a document.
The five real adapter runs come from `tests/_corpus.py`, the same source S3a's gates use.

Judge this file by pytest's EXIT CODE. Under `addopts = -q --strict-markers -rs` a failing
test prints `F` and a traceback and emits no line beginning with `FAILED`, so grepping for
one returns 0 on a red suite.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from _corpus import KUBERNETES_SCAN_ROOT as K8S_ROOT
from _corpus import TERRAFORM_SCAN_ROOT as TF_ROOT
from _corpus import all_real_findings as _all_real_findings
from iacrisk import taxonomy
from iacrisk.context.coverage import build as build_coverage
from iacrisk.context.extract import (
    CONTEXT_FACTOR_KEYS,
    LOW_CONFIDENCE_THRESHOLD,
    ContextualizedFinding,
    contextualize,
)
from iacrisk.context.kubernetes import build_body_index
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.terraform import build_index as build_tf_index
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding


def _tf_index() -> dict[str, TerraformResource]:
    return build_tf_index(sorted(TF_ROOT.rglob("*.tf")), TF_ROOT)


def _k8s_index() -> dict[str, dict[str, Any]]:
    files: list[Path] = sorted(K8S_ROOT.rglob("*.yaml")) + sorted(K8S_ROOT.rglob("*.yml"))
    return build_body_index(files)


def _contextualized() -> list[ContextualizedFinding]:
    return contextualize(_all_real_findings(), {}, _tf_index(), _k8s_index())


def _other_class_in_same_category(class_id: str) -> str:
    """A DIFFERENT taxonomy class in the same category.

    Asserts the substitution is real. A helper that silently returned the same class
    would make gate 5 pass unconditionally, which is the vacuous-test failure mode this
    project has hit before (S2's exclusion test).
    """
    classes = taxonomy.classes()
    entry = classes.get(class_id)
    if entry is None:
        # An `unmapped:` class has no category. Substitute any real class - the point of
        # the mutation is that the class changes, not which category it belongs to.
        substitute = sorted(classes)[0]
    else:
        siblings = sorted(
            other
            for other, e in classes.items()
            if e.category == entry.category and other != class_id
        )
        assert siblings, (
            f"category {entry.category!r} has only one class; mutation would be vacuous"
        )
        substitute = siblings[0]
    assert substitute != class_id, "mutation must change the class or the gate is vacuous"
    return substitute


def test_gate_1_every_context_eligible_finding_carries_five_defined_factors() -> None:
    """No factor is ever absent, and no level exists that the rubric does not define."""
    from iacrisk import rubric

    factors = rubric.factors()
    results = _contextualized()
    eligible = [r for r in results if r.finding.context_eligible]
    assert eligible, "expected at least one context-eligible finding over the corpus"

    for result in eligible:
        assert len(result.factors) == 5, result.finding.resource_identity
        assert {v.key for v in result.factors} == set(CONTEXT_FACTOR_KEYS)
        for value in result.factors:
            if value.level is None:
                continue
            factor = factors[value.key]
            assert factor.minimum <= value.level <= factor.maximum
            assert any(level.score == value.level for level in factor.levels)


def test_gate_2_context_ineligible_findings_carry_no_context_block_at_all() -> None:
    """Not defaults, not unresolved markers. Silently defaulting them re-opens the
    all-defaulted washout S3a closed with `context_eligible`.
    """
    results = _contextualized()
    ineligible = [r for r in results if not r.finding.context_eligible]
    assert ineligible, (
        "corpus v0 carries 30 context-ineligible findings (9 checkov non-resource, "
        "21 trivy); expected some here"
    )

    for result in ineligible:
        assert result.exposure is None
        assert result.privilege is None
        assert result.sensitivity is None
        assert result.criticality is None
        assert result.encryption is None
        assert result.factors == ()
        assert result.defaulted_factors == ()
        assert result.unresolved_factors == ()
        assert result.low_confidence is False


def test_gate_3_defaulted_and_unresolved_are_disjoint_over_the_whole_corpus() -> None:
    """And their union is exactly the set of factors not resolved from evidence."""
    for result in _contextualized():
        defaulted = set(result.defaulted_factors)
        unresolved = set(result.unresolved_factors)
        assert not defaulted & unresolved, result.finding.resource_identity
        assert defaulted <= {"sensitivity", "criticality"}
        assert unresolved <= {"exposure", "privilege", "encryption"}
        not_resolved = {v.key for v in result.factors if v.state is not FactorState.RESOLVED}
        assert defaulted | unresolved == not_resolved


def test_gate_4_the_exposure_precedence_rule_holds_as_data() -> None:
    """For every finding whose evidence records an any-source opening, exposure >= 4.

    The rule text is read from `rubric.json` so the gate cannot drift from the artifact,
    and the assertion is over the corpus rather than a constructed example.
    """
    from iacrisk import rubric

    precedence = rubric.factors()["exposure"].precedence_rule
    assert precedence is not None and "0.0.0.0/0" in precedence

    checked = 0
    for result in _contextualized():
        value = result.exposure
        if value is None or "any-source ingress opening" not in value.evidence:
            continue
        checked += 1
        assert value.level is not None and value.level >= 4, value.evidence
    assert checked > 0, "expected at least one any-source ingress opening in the corpus"


def test_gate_5_no_resolved_factor_level_depends_on_the_issue_class() -> None:
    """severity_context_fencing, by mutation rather than assertion.

    The constraint is that a change *cannot* have an effect, which a positive assertion
    cannot demonstrate. Substituting each finding's issue_class for a different class in
    the same category must leave every resolved factor level untouched. A difference means
    the extractor read the class rather than the resource.
    """
    findings = _all_real_findings()
    tf_index = _tf_index()
    k8s_index = _k8s_index()

    baseline = contextualize(findings, {}, tf_index, k8s_index)
    mutated_findings: list[NormalizedFinding] = [
        replace(f, issue_class=_other_class_in_same_category(f.issue_class)) for f in findings
    ]
    assert all(
        a.issue_class != b.issue_class for a, b in zip(findings, mutated_findings, strict=True)
    ), "every finding's class must actually change or this gate is vacuous"

    mutated = contextualize(mutated_findings, {}, tf_index, k8s_index)
    assert len(baseline) == len(mutated)

    for before, after in zip(baseline, mutated, strict=True):
        for key in CONTEXT_FACTOR_KEYS:
            b = getattr(before, key)
            a = getattr(after, key)
            if b is None or a is None:
                assert b is None and a is None
                continue
            assert b.level == a.level, (
                f"{before.finding.resource_identity} {key}: {b.level} -> {a.level} after "
                f"class mutation - the extractor read the class, not the resource"
            )


def test_gate_6_the_resolution_rate_distribution_is_measured_and_reported() -> None:
    """Spec section 8.3. This is the number that says whether the framework can rank at
    all: the five context defaults sum to 16, so an all-defaulted finding always lands in
    High, and a corpus resolving nothing would collapse into one band.

    The gate asserts the report is well-formed and internally consistent. It deliberately
    does NOT assert a resolution threshold - the measured rate is a finding to report,
    not a target to pass, and pinning one here would turn an empirical result into a
    test that has to be kept green.
    """
    results = _contextualized()
    coverage = build_coverage(results)

    assert sorted(coverage.resolution_distribution) == [0, 1, 2, 3, 4, 5]
    assert sum(coverage.resolution_distribution.values()) == coverage.eligible
    assert coverage.eligible + coverage.ineligible == len(results)

    assert set(coverage.per_factor_defaulted) == {"sensitivity", "criticality"}
    assert set(coverage.per_factor_unresolved) == {"exposure", "privilege", "encryption"}

    # The low-confidence population is exactly the tail at or above the frozen threshold.
    expected_low = sum(
        total
        for missing, total in coverage.resolution_distribution.items()
        if missing >= LOW_CONFIDENCE_THRESHOLD
    )
    assert coverage.low_confidence_count == expected_low

    assert len(coverage.per_class_coverage) >= 28
    assert set(taxonomy.classes()) <= set(coverage.per_class_coverage)
    assert sum(e.findings for e in coverage.per_class_coverage.values()) == coverage.eligible


def test_gate_7_the_privilege_mapping_holds_on_every_corpus_iam_case() -> None:
    """Spec section 5.4. Asserted as four explicit expectations, because the pair
    privilege-iam-bucket-to-account stops isolating its factor if the first two collapse
    to one level - and it would still pass on rank, for a reason fencing forbids.
    """
    from iacrisk.context.privilege import extract as extract_privilege

    authored_root = Path(__file__).resolve().parent.parent / "corpus" / "authored"
    authored = build_tf_index(sorted(authored_root.glob("*.tf")), authored_root)
    vendored = _tf_index()

    def _level(identity: str, index: dict[str, TerraformResource]) -> int | None:
        finding = NormalizedFinding(
            scanner="checkov",
            rule_id="R1",
            canonical_rule_id="R1",
            issue_class="iam-overpermissive-policy",
            title="t",
            remediation=None,
            native_severity=None,
            severity_level=3,
            platform="terraform",
            resource_identity=identity,
            identity_kind="terraform",
            file_path="x.tf",
            line_range=None,
            fingerprint=None,
            context_eligible=True,
        )
        return extract_privilege(finding, index).level

    assert _level("aws_iam_policy.s3_bucket_scope", authored) == 2
    assert _level("aws_iam_policy.s3_account_scope", authored) == 3
    assert _level("aws_iam_policy.unrestricted_scope", authored) == 5
    assert _level("aws_iam_role_policy.ec2policy", vendored) == 4
