import pytest

from iacrisk import rubric, taxonomy
from iacrisk.scoring.factor_map import (
    GAP_CANDIDATE_FACTORS,
    bearing_factors,
    is_factor_gap,
    rule,
    table,
)

# The 14 classes the systematic sweep found, measured against each class DEFINITION.
# CLAUDE.md names five candidates and says the set "is not established as complete"; it was
# right to doubt them - those were the ones someone had noticed. Spec section 1.4 carries the
# full table and the two-number split.
GAP_CLASSES = {
    # self-declared lower-severity or no-direct-impact (4 classes, 178 findings)
    "containers-workload-reliability",
    "storage-data-lifecycle-hygiene",
    "networking-config-hygiene",
    "compute-reliability-observability",
    # substantive gap (10 classes, 256 findings)
    "storage-data-recoverability",
    "containers-image-supply-chain",
    "containers-host-isolation-breakout",
    "storage-logging-audit",
    "iam-authentication-controls",
    "compute-instance-metadata-hardening",
    "networking-egress-exposure",
    "iam-hardcoded-secrets",
    "networking-flow-logging",
    "containers-image-vulnerability-scanning",
}

ALWAYS_BEARING = {"severity", "sensitivity", "criticality"}


def test_the_table_covers_every_taxonomy_class_with_no_unmapped_cell() -> None:
    """Gate 7's core. The S2 handoff records that no class-to-factor mapping existed
    anywhere in the data, which is why the gap set was never shown to be complete. A
    table missing a class leaves that class's gap status undecided rather than decided.
    """
    assert set(table()) == set(taxonomy.classes())
    assert len(table()) == 28


def test_every_named_factor_is_a_real_rubric_factor() -> None:
    valid = set(rubric.factors())
    for class_id, factors in table().items():
        assert factors <= valid, f"{class_id} names a factor the rubric does not define"


def test_the_three_always_bearing_factors_bear_on_every_class() -> None:
    """severity, sensitivity and criticality describe the rule, the asset and the
    environment rather than the risk mechanism, so they modulate any finding.
    """
    for class_id, factors in table().items():
        assert factors >= ALWAYS_BEARING, class_id


def test_gap_candidates_are_exactly_the_three_parsed_factors() -> None:
    """The other three bear on everything, so they can never distinguish a gap."""
    assert frozenset({"exposure", "privilege", "encryption"}) == GAP_CANDIDATE_FACTORS


def test_the_fourteen_swept_gap_classes_are_gaps() -> None:
    for class_id in GAP_CLASSES:
        assert is_factor_gap(class_id), class_id
        assert not (bearing_factors(class_id) & GAP_CANDIDATE_FACTORS)


def test_no_other_class_is_a_gap() -> None:
    """Pins the gap set at exactly the fourteen the sweep found. A fifteenth must be argued
    and added to spec section 1.4's table, not absorbed silently here.
    """
    gaps = {c for c in taxonomy.classes() if is_factor_gap(c)}
    assert gaps == GAP_CLASSES


def test_the_non_gap_classes_split_three_five_six_across_the_parsed_factors() -> None:
    """Spec section 1.4's closing figure, asserted so the table cannot drift from it."""
    counts = {
        factor: sum(1 for f in table().values() if factor in f) for factor in GAP_CANDIDATE_FACTORS
    }
    assert counts == {"exposure": 3, "privilege": 5, "encryption": 6}
    assert len(table()) - len(GAP_CLASSES) == 14


def test_an_unknown_class_is_a_hard_error_not_a_silent_gap() -> None:
    """An `unmapped:` class has no entry. Returning "gap" for it would conflate two
    different exclusions that PLAN Q7 and spec section 2.3 report separately.
    """
    with pytest.raises(KeyError):
        bearing_factors("unmapped:checkov:CKV_AWS_62")
    with pytest.raises(KeyError):
        is_factor_gap("not-a-class")


def test_an_exposure_bearing_class_names_exposure() -> None:
    """A spot check that the table is not uniformly 'no' on the parsed factors, which
    would make every class a gap and the marker meaningless.
    """
    assert "exposure" in bearing_factors("networking-ingress-exposure")
    assert "exposure" in bearing_factors("storage-public-accessibility")
    assert "encryption" in bearing_factors("storage-encryption-at-rest")
    assert "privilege" in bearing_factors("iam-overpermissive-policy")


def test_every_class_carries_a_rationale_naming_its_parsed_factor_decision() -> None:
    """The rationale is what lets a reader check the judgement rather than accept it. A
    gap entry must say so explicitly, because a silent gap is indistinguishable from an
    unconsidered one.
    """
    import json

    from iacrisk.scoring.factor_map import PATH

    document = json.loads(PATH.read_text(encoding="utf-8"))
    for class_id, entry in document["classes"].items():
        assert entry["rationale"].strip(), class_id
        if class_id in GAP_CLASSES:
            assert "GAP" in entry["rationale"], f"{class_id} is a gap and must say so"


def test_the_authoring_rule_travels_with_the_table() -> None:
    """Carried as data so the table and the rule it was built from cannot drift apart."""
    text = rule()
    assert "inbound network reachability" in text
    assert "granted IAM/RBAC permission" in text
    assert "not evidence of that factor" in text
