import json

import pytest

from iacrisk.context.extract import ContextualizedFinding
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding
from iacrisk.scoring.emit import render_markdown, to_json
from iacrisk.scoring.engine import ScoredFinding, score
from iacrisk.scoring.rank import rank_all
from iacrisk.scoring.report import build


def _scored(
    *,
    target: int = 20,
    identity: str = "aws_s3_bucket.b",
    issue_class: str = "storage-encryption-at-rest",
    unresolved: tuple[str, ...] = (),
    eligible: bool = True,
    weights: dict[str, int] | None = None,
) -> ScoredFinding:
    assert 1 <= target <= 28
    remainder = target - 1
    severity_extra = min(4, remainder)
    remainder -= severity_extra
    caps = {"exposure": 5, "privilege": 5, "sensitivity": 5, "criticality": 5, "encryption": 3}
    levels: dict[str, int] = {}
    for key, cap in caps.items():
        take = min(cap, remainder)
        levels[key] = take
        remainder -= take

    finding = NormalizedFinding(
        scanner="checkov",
        rule_id="CKV_AWS_1",
        canonical_rule_id="CKV_AWS_1",
        issue_class=issue_class,
        title="t",
        remediation=None,
        native_severity=None,
        severity_level=1 + severity_extra,
        platform="terraform",
        resource_identity=identity,
        identity_kind="terraform",
        file_path="main.tf",
        line_range=None,
        fingerprint=None,
        context_eligible=eligible,
    )

    def fv(key: str) -> FactorValue:
        if key in unresolved:
            return FactorValue.unresolved(key, "t")
        return FactorValue.resolved(key, levels[key], "t")

    if not eligible:
        ctx = ContextualizedFinding(
            finding=finding,
            exposure=None,
            privilege=None,
            sensitivity=None,
            criticality=None,
            encryption=None,
        )
    else:
        ctx = ContextualizedFinding(
            finding=finding,
            exposure=fv("exposure"),
            privilege=fv("privilege"),
            sensitivity=fv("sensitivity"),
            criticality=fv("criticality"),
            encryption=fv("encryption"),
        )
    return score(ctx, weights)


def _payload(*scored: ScoredFinding) -> dict[str, object]:
    items = list(scored) or [_scored()]
    return to_json(rank_all(items), build(items))


def test_the_payload_round_trips_through_json() -> None:
    json.dumps(_payload())


def test_every_finding_carries_its_states_and_decomposition() -> None:
    payload = _payload()
    entry = payload["findings"][0]  # type: ignore[index]
    for key in (
        "rank",
        "resource_identity",
        "issue_class",
        "scanner",
        "score",
        "band",
        "action",
        "contributions",
        "factor_states",
        "explanation",
        "baseline_band",
        "low_confidence",
        "factor_gap",
        "unmapped",
        "baseline_only_informational",
    ):
        assert key in entry, key
    assert len(entry["contributions"]) == 6
    assert len(entry["explanation"]) == len(entry["contributions"])
    assert sum(entry["contributions"].values()) == entry["score"]


def test_per_factor_state_survives_into_the_payload() -> None:
    """A consumer must be able to tell a resolved 3 from an unresolved one, because every
    S5 report depends on the difference.
    """
    payload = _payload(_scored(unresolved=("exposure",)))
    states = payload["findings"][0]["factor_states"]  # type: ignore[index]
    assert states["exposure"] == "unresolved"
    assert states["privilege"] == "resolved"


def test_a_context_ineligible_finding_carries_one_contribution_and_its_flag() -> None:
    payload = _payload(_scored(eligible=False))
    entry = payload["findings"][0]  # type: ignore[index]
    assert entry["contributions"] == {"severity": entry["score"]}
    assert entry["baseline_only_informational"] is True
    assert len(entry["explanation"]) == 1
    assert set(entry["factor_states"]) == {"severity"}


def test_emitting_a_weighted_score_is_refused() -> None:
    """Spec section 4.4: the frozen primary model is unweighted, and a report path that
    accepted a weighted score would let the analysed model silently become the reported one.
    """
    weighted = _scored(weights={"exposure": 2})
    with pytest.raises(ValueError, match="weighted"):
        to_json(rank_all([weighted]), build([weighted]))


def test_the_renderer_reads_the_payload_and_nothing_else() -> None:
    """The human report is a view, never a second source. Passing it the payload is what
    guarantees it cannot disagree with the JSON.
    """
    payload = _payload()
    text = render_markdown(payload)
    entry = payload["findings"][0]  # type: ignore[index]
    assert str(entry["score"]) in text
    assert entry["resource_identity"] in text
    assert entry["band"] in text


def test_the_renderer_groups_critical_first() -> None:
    payload = _payload(
        _scored(target=24, identity="aws_s3_bucket.crit"),
        _scored(target=18, identity="aws_s3_bucket.high"),
        _scored(target=12, identity="aws_s3_bucket.med"),
    )
    text = render_markdown(payload)
    assert text.index("## Critical") < text.index("## High") < text.index("## Medium")


def test_the_renderer_omits_a_band_with_no_findings() -> None:
    text = render_markdown(_payload(_scored(target=20)))
    assert "## High" in text
    assert "## Critical" not in text


def test_the_renderer_shows_the_score_decomposition_and_the_flags() -> None:
    """The decomposition is asserted against the payload's own score rather than a literal.

    An earlier version asserted "= 20" after requesting target=20 with exposure unresolved -
    but an unresolved factor contributes the rubric default (3) instead of the resolved level
    (5), so the real total is 18. The helper does not honour `target` once a factor is
    unresolved, which is a property of the model rather than a bug: that substitution is
    exactly what the unresolved default does.
    """
    payload = _payload(
        _scored(target=20, issue_class="containers-image-supply-chain", unresolved=("exposure",))
    )
    entry = payload["findings"][0]  # type: ignore[index]
    text = render_markdown(payload)
    assert "factor-gap" in text
    assert f"= {entry['score']}" in text
    assert sum(entry["contributions"].values()) == entry["score"]
    assert entry["contributions"]["exposure"] == 3
    assert "exposure" in text
