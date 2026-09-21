"""Validation at the harness entry point (design spec section 4.5).

The gate is exact: a case with a missing or ill-formed `expected` block is a hard
reject, not a skip. A harness that skips a bad case shrinks its own denominator
and reports a better number than it earned.

Two layers, because one is not enough:

1. JSON Schema, for shape.
2. Cross-record semantics, for the things JSON Schema structurally cannot say -
   uniqueness of ids across a list, references from pairs and scenarios resolving
   to real cases, and `author != reviewer` on an oracle. That last one is a field
   inequality, which no JSON Schema keyword expresses, and it is the reason this
   module exists rather than a bare `jsonschema.validate` call at the call site.

This module deliberately imports nothing from `iacrisk`: the harness may not share
code with what it grades (PLAN Q7), a boundary
`tests/test_architecture.py::test_eval_does_not_import_scoring` enforces.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]  # no py.typed marker; stub package not added

SCHEMA_PATH: Path = Path(__file__).resolve().parent / "ground_truth.schema.json"


class GroundTruthError(ValueError):
    """A ground-truth document the harness must reject rather than skip."""


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """The JSON Schema for the three record types."""
    parsed: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return parsed


def _check_shape(document: Any) -> None:
    schema = load_schema()
    validator_class = jsonschema.validators.validator_for(schema)
    validator = validator_class(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    rendered = "; ".join(
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors[:5]
    )
    suffix = f" (and {len(errors) - 5} more)" if len(errors) > 5 else ""
    raise GroundTruthError(f"ground truth failed schema validation - {rendered}{suffix}")


def _unique_ids(records: list[dict[str, Any]], key: str) -> set[str]:
    seen: set[str] = set()
    for record in records:
        identifier = record[key]
        if identifier in seen:
            raise GroundTruthError(f"duplicate {key}: {identifier!r}")
        seen.add(identifier)
    return seen


def _check_semantics(document: dict[str, Any]) -> None:
    case_ids = _unique_ids(document["cases"], "case_id")
    _unique_ids(document["contrastive_pairs"], "pair_id")
    _unique_ids(document["scenarios"], "scenario_id")

    for pair in document["contrastive_pairs"]:
        for side in ("case_high", "case_low"):
            if pair[side] not in case_ids:
                raise GroundTruthError(
                    f"contrastive pair {pair['pair_id']!r} {side} names unknown case {pair[side]!r}"
                )
        if pair["case_high"] == pair["case_low"]:
            raise GroundTruthError(
                f"contrastive pair {pair['pair_id']!r} names the same case on both sides; "
                "a pair cannot differ in exactly one factor from itself"
            )

    for scenario in document["scenarios"]:
        for tier in scenario["expected_ordering"]:
            for case_id in tier:
                if case_id not in case_ids:
                    raise GroundTruthError(
                        f"scenario {scenario['scenario_id']!r} orders unknown case {case_id!r}"
                    )
        oracle = scenario["oracle"]
        if oracle["author"] == oracle["reviewer"]:
            raise GroundTruthError(
                f"scenario {scenario['scenario_id']!r} oracle author and reviewer are the "
                f"same person ({oracle['author']!r}); the oracle would be reviewing itself"
            )


def validate(document: Any) -> None:
    """Validate a ground-truth document, raising `GroundTruthError` on any defect."""
    _check_shape(document)
    _check_semantics(document)


def load_and_validate(path: Path) -> dict[str, Any]:
    """Read, parse and validate a ground-truth file.

    A truncated or malformed file raises rather than reading as an empty-but-valid
    document - the same reject-do-not-skip discipline applied one layer earlier.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GroundTruthError(f"{path} is not valid JSON: {exc}") from exc
    validate(document)
    parsed: dict[str, Any] = document
    return parsed
