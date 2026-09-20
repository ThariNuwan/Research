"""The taxonomy is the single source of truth for mapping, rubric anchoring, and dedupe.

Every count asserted here is a corpus v0 observation measured on this host, not a
scanner contract (spec section 0). The gate these tests enforce is spec section 1.4:
every rule ID the pinned scanners emit maps to a class or an explicit `unmapped:`
entry, and all five tested categories are populated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iacrisk import taxonomy

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "artifacts" / "rule-inventory.json"

# Per-category class counts from spec section 1.2. Asserted as a whole dict rather
# than a bare total so a class silently moving between categories still fails.
EXPECTED_CLASS_COUNTS = {
    "storage": 7,
    "networking": 6,
    "iam": 4,
    "compute": 4,
    "containers": 7,
}


def _inventory_rule_ids() -> set[tuple[str, str]]:
    """Every (scanner, rule_id) the S0 harvest actually observed."""
    document = json.loads(INVENTORY.read_text(encoding="utf-8"))
    return {
        (scanner, rule_id)
        for scanner, block in document["by_scanner"].items()
        for rule_id in block["rule_ids"]
    }


def test_taxonomy_has_28_classes_across_five_categories() -> None:
    """Spec section 1.2: 28 classes, category-first, over the five tested domains."""
    classes = taxonomy.classes()
    assert len(classes) == 28

    counts: dict[str, int] = {}
    for issue_class in classes.values():
        counts[issue_class.category] = counts.get(issue_class.category, 0) + 1
    assert counts == EXPECTED_CLASS_COUNTS


def test_every_class_carries_a_definition() -> None:
    """A class with no definition cannot anchor a rubric score or a test case."""
    undefined = [
        issue_class.id
        for issue_class in taxonomy.classes().values()
        if not issue_class.definition.strip()
    ]
    assert undefined == [], f"classes with an empty definition: {undefined}"


def test_every_observed_rule_id_maps_to_a_real_class() -> None:
    """The section 1.4 gate: 255/255 mapped, 0 unmapped in corpus v0.

    Driven from artifacts/rule-inventory.json rather than from taxonomy.json's own
    row list, so the assertion is against what the scanners emitted, not against
    the artifact restating itself.
    """
    observed = _inventory_rule_ids()
    assert len(observed) == 255

    class_ids = set(taxonomy.classes())
    unmapped = [
        (scanner, rule_id)
        for scanner, rule_id in sorted(observed)
        if taxonomy.class_for(scanner, rule_id) not in class_ids
    ]
    assert unmapped == [], f"{len(unmapped)} observed rule ids do not map: {unmapped[:10]}"


def test_mapping_contains_no_row_the_inventory_never_observed() -> None:
    """The other direction: no invented rows padding the coverage number."""
    observed = _inventory_rule_ids()
    invented = sorted(set(taxonomy.mapping()) - observed)
    assert invented == [], f"mapping rows absent from the S0 inventory: {invented[:10]}"


def test_no_class_is_empty() -> None:
    """An empty class is a taxonomy defect: it can never be exercised or evaluated."""
    used = {row.class_id for row in taxonomy.mapping().values()}
    empty = sorted(set(taxonomy.classes()) - used)
    assert empty == [], f"classes with no rule assigned: {empty}"


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("AVD-AWS-0026", "AWS-0026"),  # tfsec form
        ("AWS-0026", "AWS-0026"),  # trivy form of the same Aqua rule - already canonical
        ("CKV_AWS_3", "CKV_AWS_3"),  # checkov ids are their own canonical form
        ("CKV2_AWS_8", "CKV2_AWS_8"),
        ("AVD-AVD-1", "AVD-1"),  # strips exactly one leading prefix, not all of them
    ],
)
def test_canonical_rule_id_strips_one_leading_avd(rule_id: str, expected: str) -> None:
    """Spec section 2.2: trivy AWS-#### and tfsec AVD-AWS-#### are the same Aqua rule."""
    assert taxonomy.canonical_rule_id(rule_id) == expected


def test_trivy_and_tfsec_twins_share_one_class() -> None:
    """Spec section 2.2 co-location, locked so no future edit can split a twin.

    True by construction for the 45 twin pairs (trivy took tfsec's class during
    derivation). This test is what keeps it true.
    """
    by_canonical: dict[str, dict[str, str]] = {}
    for row in taxonomy.mapping().values():
        by_canonical.setdefault(row.canonical_id, {})[row.scanner] = row.class_id

    twins = {
        canonical: per_scanner
        for canonical, per_scanner in by_canonical.items()
        if "trivy" in per_scanner and "tfsec" in per_scanner
    }
    assert len(twins) == 45, f"expected 45 trivy/tfsec twin pairs, found {len(twins)}"

    split = {
        canonical: per_scanner
        for canonical, per_scanner in twins.items()
        if per_scanner["trivy"] != per_scanner["tfsec"]
    }
    assert split == {}, f"twins split across classes: {split}"


def test_unknown_rule_id_falls_back_to_an_explicit_unmapped_class() -> None:
    """Spec section 2.4: a rule the table has never seen is named, never dropped.

    This is the PLAN Q9 explicit-state rule at the taxonomy seam: an unseen rule
    must not quietly acquire a real class, and must not vanish.
    """
    class_id = taxonomy.class_for("trivy", "AWS-9999")

    assert class_id == "unmapped:trivy:AWS-9999"
    assert taxonomy.is_unmapped(class_id)
    assert class_id not in taxonomy.classes()


def test_real_class_ids_are_not_reported_as_unmapped() -> None:
    """Guard the guard: is_unmapped must be precise, not merely wide."""
    assert not taxonomy.is_unmapped("storage-encryption-at-rest")


def test_unmapped_fallback_contract_is_recorded_in_the_artifact() -> None:
    """The Q7 #9 / Q8 #6 policy ships as data, so S3 cannot reinvent it differently."""
    fallback = taxonomy.fallback_contract()

    assert fallback["class_id_format"] == "unmapped:<scanner>:<rule_id>"
    assert fallback["counted_once"] is True
    assert fallback["dropped"] is False
    assert fallback["excluded_from_prioritization_quality_claims"] is True
