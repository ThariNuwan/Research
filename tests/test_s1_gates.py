"""The five S1 acceptance gates, as tests rather than as a claim in a report.

Each gate's docstring quotes PLAN.md verbatim where PLAN states one. A gate
asserted here is one the artifacts actually support; a gate PLAN states that S1
cannot yet meet is recorded in `test_deferred_gate_items_are_named` rather than
quietly counted as met (the section G3 defect class).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.ground_truth import GroundTruthError, load_and_validate, validate
from iacrisk import identity, rubric, taxonomy

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_gate_1_every_emitted_rule_id_maps_and_all_five_categories_are_covered() -> None:
    """The PLAN.md gate, verbatim:

    "Every rule ID emitted by the pinned scanner versions across the corpus maps
    to an issue-class or an explicit `unmapped:` entry (measured mapping
    completeness); taxonomy covers all five tested categories."
    """
    inventory = json.loads(
        (REPO_ROOT / "artifacts" / "rule-inventory.json").read_text(encoding="utf-8")
    )
    observed = [
        (scanner, rule_id)
        for scanner, block in inventory["by_scanner"].items()
        for rule_id in block["rule_ids"]
    ]
    class_ids = set(taxonomy.classes())

    resolved = [taxonomy.class_for(scanner, rule_id) for scanner, rule_id in observed]
    assert len(resolved) == 255
    assert all(class_id in class_ids for class_id in resolved)
    assert not any(taxonomy.is_unmapped(class_id) for class_id in resolved)

    covered = {issue_class.category for issue_class in taxonomy.classes().values()}
    assert covered == set(taxonomy.CATEGORIES)


def test_gate_2_every_rubric_score_point_is_anchored_and_the_model_is_additive() -> None:
    """Spec section 3.6: anchors cite CVSS/NIST/NSA-CISA/OWASP, each score point
    justifiable; the equal-weighted additive sum is the primary model; weighting
    is a tunable framed as sensitivity analysis.
    """
    anchors = ("CVSS", "NIST", "NSA", "OWASP", "FIPS")
    for factor in rubric.factors().values():
        for level in factor.levels:
            assert any(anchor in level.source for anchor in anchors)
            assert level.justification.strip()

    assert rubric.model()["formula"] == (
        "Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk"
    )
    assert rubric.model()["equal_weighted"] is True
    assert "sensitivity analysis" in rubric.model()["weighting"]


def test_gate_3_severity_normalizes_per_scanner_with_explicit_unknown_routing() -> None:
    """Spec section 3.3, which is what makes the raw-severity baseline comparable."""
    table = rubric.severity_normalization()

    assert set(table["per_scanner"]) == {"checkov", "trivy", "tfsec"}
    assert rubric.normalize_severity("trivy", "CRITICAL") == 5
    assert rubric.normalize_severity("trivy", "UNKNOWN") == rubric.UNKNOWN
    assert rubric.normalize_severity("checkov", None) == rubric.UNKNOWN
    assert table["unknown_resolves_to"] == rubric.unresolved_default("severity")


def test_gate_4_the_schema_validates_good_records_and_rejects_bad_ones() -> None:
    """The PLAN.md gate, verbatim:

    "Schema validates on all corpus cases; harness rejects a case with
    missing/ill-formed expected outputs rather than skipping it."

    The reject half is asserted here in full. The "all corpus cases" half is
    asserted against the committed exemplar, because the corpus ground truth
    itself is authored in S2 against this schema - see
    `test_deferred_gate_items_are_named`.
    """
    document = load_and_validate(REPO_ROOT / "eval" / "ground_truth" / "example.json")
    assert document["cases"]

    broken = json.loads(json.dumps(document))
    del broken["cases"][0]["expected"]
    with pytest.raises(GroundTruthError):
        validate(broken)


def test_gate_5_every_corpus_resource_shape_has_a_defined_identity() -> None:
    """The PLAN.md gate, verbatim:

    "Identity is defined for every resource/instance shape present in the
    corpus (module, `for_each`/`count`, namespace/kind)."

    One assertion per shape the spec section 5.5 inventory enumerates.
    """
    shapes = {
        # Terraform: the bare form, and the one static count index in the corpus.
        "tf-bare": identity.terraform_identity("aws_s3_bucket", "data"),
        "tf-count": identity.terraform_identity(
            "aws_neptune_cluster_instance", "default", instance_key=0
        ),
        "tf-module": identity.terraform_identity(
            "aws_s3_bucket", "data", module_path="module.storage"
        ),
        "tf-for-each": identity.terraform_identity("aws_s3_bucket", "b", instance_key="alpha"),
        "tf-unresolved": identity.terraform_identity(
            "aws_instance", "web", instance_key=identity.UNRESOLVED
        ),
        # Kubernetes: namespaced, cluster-scoped, container-scoped, and templated.
        "k8s-namespaced": identity.kubernetes_identity(
            "apps/v1", "Deployment", "api", namespace="prod"
        ),
        "k8s-cluster-scoped": identity.kubernetes_identity("v1", "Namespace", "big-monolith"),
        "k8s-container": identity.kubernetes_identity(
            "apps/v1", "Deployment", "internal-proxy", namespace="default", container="nginx"
        ),
        "k8s-helm": identity.kubernetes_identity(
            "apps/v1", "Deployment", "{{ .Release.Name }}-db", namespace="{{ .Release.Namespace }}"
        ),
    }

    assert all(rendered for rendered in shapes.values())
    assert len(set(shapes.values())) == len(shapes), "two distinct shapes rendered identically"
    assert shapes["k8s-helm"].count(identity.UNRESOLVED) == 2


def test_the_model_and_bands_are_frozen_at_the_end_of_s1() -> None:
    """Spec section 0: ranges and bands freeze here, before any scoring output."""
    assert rubric.score_bounds() == (1, 28)
    assert [band.name for band in rubric.bands()] == ["Critical", "High", "Medium", "Low"]
    assert (rubric.band_for(22), rubric.band_for(21)) == ("Critical", "High")
    assert (rubric.band_for(16), rubric.band_for(15)) == ("High", "Medium")
    assert (rubric.band_for(9), rubric.band_for(8)) == ("Medium", "Low")


def test_deferred_gate_items_are_named() -> None:
    """What S1 ships as a contract and S3/S4 ship as enforcement.

    Naming these keeps the gate report honest: each item below is a spec
    requirement that needs a scoring engine S1 does not build, so S1 carries the
    rule as data and the later sub-project enforces it. A gate claimed without
    its enforcement would be a claim the artifact does not support.
    """
    rules = rubric.coherence_rules()

    assert "iam_governed_resource_inheritance" in rules  # spec 3.5(1), enforced in S3
    assert "unresolved_default_reporting" in rules  # spec 3.5(2), enforced in S4
    assert "severity_context_fencing" in rules  # spec 3.5(3), enforced in S3

    # Spec 2.4: the unmapped: scoring behaviour ships as a contract here.
    fallback = taxonomy.fallback_contract()
    assert fallback["scoring"] == "severity-only, default context"
    assert fallback["excluded_from_prioritization_quality_claims"] is True
