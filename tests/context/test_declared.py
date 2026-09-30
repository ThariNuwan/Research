import json
from pathlib import Path

import pytest

from iacrisk.context.declared import governed_target, join, load_declared
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.value import FactorState

DECLARED = {"aws_s3_bucket.data": {"sensitivity": 5, "criticality": 4}}


def _res(rtype: str, name: str, **body: object) -> TerraformResource:
    return TerraformResource(
        identity=f"{rtype}.{name}", type=rtype, name=name, body=dict(body), file_path="x.tf"
    )


def test_an_exact_identity_match_takes_the_declared_values() -> None:
    sensitivity, criticality = join("aws_s3_bucket.data", DECLARED, {})
    assert (sensitivity.state, sensitivity.level) == (FactorState.RESOLVED, 5)
    assert (criticality.state, criticality.level) == (FactorState.RESOLVED, 4)


def test_no_match_defaults_both_and_never_resolves() -> None:
    sensitivity, criticality = join("aws_s3_bucket.other", DECLARED, {})
    assert sensitivity.state is FactorState.DEFAULTED
    assert criticality.state is FactorState.DEFAULTED
    assert sensitivity.scored_level == 3
    assert criticality.scored_level == 4


def test_a_near_match_is_not_a_match() -> None:
    """No fuzzy matching and no fallback to a shorter key: a near-match join would
    attach one resource's business context to a different resource.
    """
    sensitivity, _ = join("aws_s3_bucket.data_2", DECLARED, {})
    assert sensitivity.state is FactorState.DEFAULTED


def test_a_declared_value_outside_the_rubric_range_is_a_hard_error() -> None:
    with pytest.raises(ValueError):
        join("aws_s3_bucket.x", {"aws_s3_bucket.x": {"sensitivity": 9, "criticality": 1}}, {})


def test_a_resource_attached_iam_finding_inherits_from_the_governed_resource() -> None:
    """The rubric's iam_governed_resource_inheritance rule. A bucket policy carries no
    business sensitivity of its own; the bucket it governs does.
    """
    tf = {"aws_s3_bucket_policy.p": _res("aws_s3_bucket_policy", "p", bucket='"data"')}
    sensitivity, criticality = join("aws_s3_bucket_policy.p", DECLARED, tf)
    assert (sensitivity.state, sensitivity.level) == (FactorState.RESOLVED, 5)
    assert (criticality.state, criticality.level) == (FactorState.RESOLVED, 4)
    assert "aws_s3_bucket.data" in sensitivity.evidence


def test_a_pure_account_level_policy_does_not_inherit_and_defaults() -> None:
    """Spec section 3.1: it keeps the band cap and is a stated limitation of the
    additive model. It gets no special value - it defaults like any unmatched resource.
    """
    tf = {"aws_iam_policy.admin": _res("aws_iam_policy", "admin", policy='"{}"')}
    sensitivity, _ = join("aws_iam_policy.admin", DECLARED, tf)
    assert sensitivity.state is FactorState.DEFAULTED


def test_an_interpolated_attachment_does_not_resolve() -> None:
    tf = {"aws_s3_bucket_policy.p": _res("aws_s3_bucket_policy", "p", bucket='"${var.b}"')}
    assert governed_target(tf["aws_s3_bucket_policy.p"]) is None
    sensitivity, _ = join("aws_s3_bucket_policy.p", DECLARED, tf)
    assert sensitivity.state is FactorState.DEFAULTED


def test_governed_target_builds_a_canonical_identity_not_a_bare_name() -> None:
    assert governed_target(_res("aws_s3_bucket_policy", "p", bucket='"data"')) == (
        "aws_s3_bucket.data"
    )
    assert governed_target(_res("aws_iam_role_policy", "rp", role='"ec2role"')) == (
        "aws_iam_role.ec2role"
    )
    assert governed_target(_res("aws_s3_bucket", "b")) is None


def test_a_single_element_list_attachment_resolves_because_hcl2_wraps_scalars() -> None:
    """python-hcl2 returns some scalar attributes wrapped in a one-element list, so the
    accessor unwraps exactly that shape. A longer list names more than one target and
    must not resolve to the first.
    """
    assert governed_target(_res("aws_s3_bucket_policy", "p", bucket=['"data"'])) == (
        "aws_s3_bucket.data"
    )
    assert governed_target(_res("aws_s3_bucket_policy", "q", bucket=['"a"', '"b"'])) is None


def test_load_declared_reads_the_corpus_shape(tmp_path: Path) -> None:
    """corpus-v1.json carries declared_context as identity -> {sensitivity, criticality}."""
    path = tmp_path / "declared.json"
    path.write_text(json.dumps(DECLARED), encoding="utf-8")
    assert load_declared(path) == DECLARED
