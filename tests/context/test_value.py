import pytest

from iacrisk.context.value import FactorState, FactorValue


def test_a_resolved_value_scores_its_own_level() -> None:
    v = FactorValue.resolved("exposure", 4, "cidr_blocks=0.0.0.0/0 at ec2.tf:77")
    assert v.state is FactorState.RESOLVED
    assert v.level == 4
    assert v.scored_level == 4


def test_an_unresolved_value_scores_the_rubric_default_and_keeps_level_none() -> None:
    """The rubric's exposure unresolved_default is 3. `level` stays None because no
    level was read; `scored_level` is what S4 does arithmetic on. Keeping them
    distinct is what lets the coverage report count unresolved factors without
    re-deriving them from a magic number.
    """
    v = FactorValue.unresolved("exposure", "cidr_blocks is ${aws_vpc.web_vpc.cidr_block}")
    assert v.state is FactorState.UNRESOLVED
    assert v.level is None
    assert v.scored_level == 3


def test_a_defaulted_value_scores_the_rubric_default() -> None:
    v = FactorValue.defaulted("criticality", "no declared-context match")
    assert v.state is FactorState.DEFAULTED
    assert v.level is None
    assert v.scored_level == 4


def test_every_factor_default_comes_from_the_rubric_not_a_literal() -> None:
    """Guards against a future hand-typed constant drifting from rubric.json. The
    five context defaults sum to 16, which is the washout spec section 1.1 measures.
    """
    keys = ("exposure", "privilege", "sensitivity", "criticality", "encryption")
    totals = sum(FactorValue.unresolved(k, "x").scored_level for k in keys)
    assert totals == 16


def test_a_level_outside_the_rubric_range_is_a_hard_error() -> None:
    with pytest.raises(ValueError, match="outside"):
        FactorValue.resolved("encryption", 4, "x")  # encryption maximum is 3


def test_an_unknown_factor_key_is_a_hard_error() -> None:
    with pytest.raises(KeyError):
        FactorValue.unresolved("not_a_factor", "x")


def test_evidence_is_required_and_non_empty() -> None:
    """Every factor value must say what it read and from where. An empty evidence
    string is how an unexplained level reaches the output JSON.
    """
    with pytest.raises(ValueError, match="evidence"):
        FactorValue.resolved("exposure", 4, "   ")
