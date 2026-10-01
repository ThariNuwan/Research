from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.engine import ScoredFinding, score
from iacrisk.scoring.rank import rank_all


def _scored(
    *,
    target: int,
    identity: str = "aws_s3_bucket.b",
    issue_class: str = "storage-encryption-at-rest",
    scanner: str = "checkov",
) -> ScoredFinding:
    """A real ScoredFinding whose total is `target`, built through score().

    Going through the engine rather than constructing ScoredFinding directly keeps these
    ranking tests honest about what the engine actually produces.
    """
    # Fill the six factors greedily within their ranges. severity must take at least 1 (its
    # floor), and the attainable total is therefore 1..28 - the frozen bounds.
    assert 1 <= target <= 28, f"{target} is outside the frozen 1-28 bounds"
    remainder = target - 1
    caps = {"exposure": 5, "privilege": 5, "sensitivity": 5, "criticality": 5, "encryption": 3}
    severity_extra = min(4, remainder)
    remainder -= severity_extra
    levels: dict[str, int] = {}
    for key, cap in caps.items():
        take = min(cap, remainder)
        levels[key] = take
        remainder -= take
    assert remainder == 0, f"cannot build a score of {target} within the factor ranges"

    finding = NormalizedFinding(
        scanner=scanner,
        rule_id="R1",
        canonical_rule_id="R1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=1 + severity_extra,
        platform="terraform",
        resource_identity=identity,
        identity_kind="terraform",
        file_path="x.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=True,
    )
    ctx = ContextualizedFinding(
        finding=finding,
        exposure=FactorValue.resolved("exposure", levels["exposure"], "t"),
        privilege=FactorValue.resolved("privilege", levels["privilege"], "t"),
        sensitivity=FactorValue.resolved("sensitivity", levels["sensitivity"], "t"),
        criticality=FactorValue.resolved("criticality", levels["criticality"], "t"),
        encryption=FactorValue.resolved("encryption", levels["encryption"], "t"),
    )
    result = score(ctx)
    assert result.score == target, (result.score, target)
    return result


def _scored_with_scores(targets: list[int]) -> list[ScoredFinding]:
    return [_scored(target=t, identity=f"aws_s3_bucket.r{i}") for i, t in enumerate(targets)]


def test_equal_scores_share_a_rank_and_the_next_rank_skips() -> None:
    """Competition ranking. corpus-v1's containers scenario contains a deliberate tie, so
    collapsing ties into distinct ranks would misreport the framework as discriminating
    where it does not.
    """
    ranked = rank_all(_scored_with_scores([20, 20, 20, 15]))
    assert [r.rank for r in ranked] == [1, 1, 1, 4]


def test_findings_sort_by_descending_score() -> None:
    ranked = rank_all(_scored_with_scores([5, 25, 15]))
    assert [r.scored.score for r in ranked] == [25, 15, 5]
    assert [r.rank for r in ranked] == [1, 2, 3]


def test_the_sub_order_within_a_tie_is_stable_and_does_not_change_ranks() -> None:
    a = _scored(target=20, identity="aws_s3_bucket.z")
    b = _scored(target=20, identity="aws_s3_bucket.a")
    ranked = rank_all([a, b])
    assert [r.scored.finding.resource_identity for r in ranked] == [
        "aws_s3_bucket.a",
        "aws_s3_bucket.z",
    ]
    assert [r.rank for r in ranked] == [1, 1]


def test_the_sub_order_falls_through_identity_then_class_then_scanner() -> None:
    """Presentational only, and documented as such - it exists so output is reproducible
    across runs, never to break a tie into an ordering the score does not support.
    """
    first = _scored(target=20, identity="aws_s3_bucket.a", issue_class="storage-logging-audit")
    second = _scored(
        target=20, identity="aws_s3_bucket.a", issue_class="storage-encryption-at-rest"
    )
    ranked = rank_all([first, second])
    assert [r.scored.finding.issue_class for r in ranked] == [
        "storage-encryption-at-rest",
        "storage-logging-audit",
    ]
    assert [r.rank for r in ranked] == [1, 1]


def test_ranking_is_deterministic_across_input_order() -> None:
    forward = rank_all(_scored_with_scores([10, 20, 15]))
    backward = rank_all(list(reversed(_scored_with_scores([10, 20, 15]))))
    assert [r.scored.score for r in forward] == [r.scored.score for r in backward]


def test_an_empty_input_ranks_to_an_empty_list() -> None:
    assert rank_all([]) == []


def test_a_single_finding_ranks_first() -> None:
    (ranked,) = rank_all(_scored_with_scores([12]))
    assert ranked.rank == 1
