"""A malformed ground-truth record is a hard reject, never a skip (spec section 4.5).

A harness that skips a bad case silently shrinks its own denominator and reports
a better number than it earned. Every test here is about the reject path being
loud.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from eval.ground_truth import GroundTruthError, load_and_validate, validate

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "eval" / "ground_truth" / "example.json"


def _document() -> dict[str, Any]:
    """A minimal document that exercises all three record types and validates."""
    return {
        "schema_version": 1,
        "cases": [
            {
                "case_id": "tg-aws-s3",
                "platform": "terraform",
                "domain": "storage",
                "source": {
                    "repo": "bridgecrewio/terragoat",
                    "commit": "729f8da6",
                    "path": "terraform/aws/s3.tf",
                },
                "declared_context": {
                    "aws_s3_bucket.data": {"sensitivity": 4, "criticality": 4},
                    "aws_s3_bucket.financials": {"sensitivity": None, "criticality": None},
                },
                "expected": {
                    "findings": [
                        {
                            "resource_identity": "aws_s3_bucket.data",
                            "issue_class": "storage-encryption-at-rest",
                            "expected_band": "High",
                        },
                        {
                            "resource_identity": "aws_s3_bucket.financials",
                            "issue_class": "unmapped:trivy:AWS-9999",
                            "excluded_from_quality_claims": True,
                        },
                    ]
                },
            },
            {
                "case_id": "tg-aws-s3-locked",
                "platform": "terraform",
                "domain": "storage",
                "source": "hand-crafted",
                "declared_context": {"aws_s3_bucket.data": {"sensitivity": 4, "criticality": 4}},
                "expected": {"findings": []},
            },
        ],
        "contrastive_pairs": [
            {
                "pair_id": "exposure-public-vs-private-bucket",
                "factor_under_test": "exposure",
                "case_high": "tg-aws-s3",
                "case_low": "tg-aws-s3-locked",
                "expected_rank_order": "high_above_low",
                "expected_score_delta_sign": "positive",
                "rationale": "The two cases differ only in the public-access-block setting.",
            }
        ],
        "scenarios": [
            {
                "scenario_id": "storage-triage-order",
                "domain": "storage",
                "expected_ordering": [["tg-aws-s3"], ["tg-aws-s3-locked"]],
                "rationale": (
                    "A world-readable bucket holding regulated data outranks a locked one."
                ),
                "oracle": {
                    "author": "258243J",
                    "reviewer": "supervisor",
                    "registered_at": "2026-09-19T00:00:00Z",
                    "reviewer_verdict": "agree",
                },
            }
        ],
    }


def test_a_well_formed_document_validates() -> None:
    validate(_document())


def test_the_committed_example_validates() -> None:
    """The shipped exemplar has to be an example of something that actually passes."""
    assert load_and_validate(EXAMPLE)["schema_version"] == 1


def test_a_case_with_no_expected_block_is_rejected() -> None:
    """The spec section 4.5 gate, stated exactly: missing expected is a hard reject."""
    document = _document()
    del document["cases"][0]["expected"]

    with pytest.raises(GroundTruthError, match="expected"):
        validate(document)


def test_a_case_with_an_ill_formed_expected_block_is_rejected() -> None:
    document = _document()
    document["cases"][0]["expected"] = {"findings": "not-a-list"}

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_null_declared_context_value_is_allowed() -> None:
    """Null is how a case deliberately exercises the default-fallback path (4.1)."""
    document = _document()
    document["cases"][0]["declared_context"]["aws_s3_bucket.data"] = {
        "sensitivity": None,
        "criticality": None,
    }

    validate(document)


@pytest.mark.parametrize("value", [-1, 6, 2.5, "3"])
def test_a_declared_context_value_outside_0_to_5_is_rejected(value: object) -> None:
    """Declared context feeds two 0-5 factors; anything else is ill-formed."""
    document = _document()
    document["cases"][0]["declared_context"]["aws_s3_bucket.data"]["sensitivity"] = value

    with pytest.raises(GroundTruthError):
        validate(document)


def test_expected_band_is_optional() -> None:
    """Spec section 4.4: ordering is primary, absolute band is secondary."""
    document = _document()
    del document["cases"][0]["expected"]["findings"][0]["expected_band"]

    validate(document)


def test_an_unmapped_issue_class_is_a_first_class_expected_value() -> None:
    """The harness has to be able to hold an unmapped finding to the Q7 #9 exclusion."""
    document = _document()
    finding = document["cases"][0]["expected"]["findings"][1]

    assert finding["issue_class"].startswith("unmapped:")
    validate(document)


def test_a_duplicate_case_id_is_rejected() -> None:
    document = _document()
    document["cases"].append(copy.deepcopy(document["cases"][0]))

    with pytest.raises(GroundTruthError, match="duplicate case_id"):
        validate(document)


def test_a_pair_referencing_an_unknown_case_is_rejected() -> None:
    """A dangling reference means the pair tests nothing - it must not pass quietly."""
    document = _document()
    document["contrastive_pairs"][0]["case_low"] = "no-such-case"

    with pytest.raises(GroundTruthError, match="unknown case"):
        validate(document)


def test_a_pair_whose_two_cases_are_the_same_is_rejected() -> None:
    """A pair with one case cannot differ in exactly one factor (spec 4.2)."""
    document = _document()
    document["contrastive_pairs"][0]["case_low"] = "tg-aws-s3"

    with pytest.raises(GroundTruthError, match="same case"):
        validate(document)


def test_a_pair_with_an_unknown_factor_under_test_is_rejected() -> None:
    document = _document()
    document["contrastive_pairs"][0]["factor_under_test"] = "vibes"

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_scenario_tier_referencing_an_unknown_case_is_rejected() -> None:
    document = _document()
    document["scenarios"][0]["expected_ordering"] = [["tg-aws-s3"], ["ghost-case"]]

    with pytest.raises(GroundTruthError, match="unknown case"):
        validate(document)


def test_an_oracle_authored_and_reviewed_by_one_person_is_rejected() -> None:
    """Spec section 4.3: author != reviewer, or the oracle reviews itself.

    JSON Schema cannot express a field inequality, so this is the validator's
    own check - and it is the reason the validator exists rather than a bare
    jsonschema call at the harness entry point.
    """
    document = _document()
    document["scenarios"][0]["oracle"]["reviewer"] = "258243J"

    with pytest.raises(GroundTruthError, match="author and reviewer"):
        validate(document)


def test_a_disagreeing_oracle_must_record_the_disagreement() -> None:
    """Disagreement is reported as oracle uncertainty, never resolved away (4.3)."""
    document = _document()
    document["scenarios"][0]["oracle"]["reviewer_verdict"] = "disagree"

    with pytest.raises(GroundTruthError):
        validate(document)

    document["scenarios"][0]["oracle"]["disagreement_note"] = "Reviewer ranks IAM above storage."
    validate(document)


def test_an_unknown_top_level_key_is_rejected() -> None:
    """Three record types, never merged - and never quietly extended either."""
    document = _document()
    document["findings"] = []

    with pytest.raises(GroundTruthError):
        validate(document)


def test_a_non_object_document_is_rejected() -> None:
    with pytest.raises(GroundTruthError, match="schema validation"):
        validate([1, 2, 3])


def test_load_and_validate_rejects_malformed_json(tmp_path: Path) -> None:
    """A truncated file must not read as an empty-but-valid document."""
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema_version": 1, "cases": [', encoding="utf-8")

    with pytest.raises(GroundTruthError, match="not valid JSON"):
        load_and_validate(broken)


def test_the_schema_file_is_itself_valid_json() -> None:
    path = REPO_ROOT / "eval" / "ground_truth.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
