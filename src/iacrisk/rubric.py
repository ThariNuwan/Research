"""The frozen six-factor scoring rubric (design spec section 3).

Risk = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk.
Equal-weighted, additive, explainable - not machine learning. Every level carries
the standard it is anchored to, because the rubric is mirrored verbatim in the
dissertation and each score point has to be defensible on its own.

Ranges and bands freeze at the end of S1. `band_for` raises rather than clamping
an out-of-range total: a score outside 1..28 means a caller has broken the frozen
model, and silently banding it would hide that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "rubric.json"

FACTOR_KEYS = ("severity", "exposure", "privilege", "sensitivity", "criticality", "encryption")
"""The six model terms, in formula order. A seventh would move the score ceiling."""


@dataclass(frozen=True)
class Level:
    """One score point: what it means, why that number, and the standard behind it."""

    score: int
    meaning: str
    justification: str
    source: str


@dataclass(frozen=True)
class Factor:
    """One model term, its range, its levels, and its unresolved-state policy.

    `unresolved_default` is the value an unresolvable instance takes. Every one of
    the six sits above the midpoint of its own range - PLAN Q9 forbids an
    unresolved state ever reading as low. `sensitivity_sweep` is set only for
    exposure, the factor Q9 names as the one a fixed numeric default distorts.
    """

    key: str
    name: str
    minimum: int
    maximum: int
    levels: tuple[Level, ...]
    unresolved_default: int
    unresolved_policy: str
    unresolved_rationale: str
    sensitivity_sweep: tuple[int, int] | None


@dataclass(frozen=True)
class Band:
    """One priority band and the remediation action it prescribes."""

    name: str
    minimum: int
    maximum: int
    action: str


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return parsed


@lru_cache(maxsize=1)
def factors() -> MappingProxyType[str, Factor]:
    """The six factors, keyed by their model-term key. Read-only."""
    built: dict[str, Factor] = {}
    for entry in _document()["factors"]:
        sweep = entry["sensitivity_sweep"]
        built[entry["key"]] = Factor(
            key=entry["key"],
            name=entry["name"],
            minimum=entry["minimum"],
            maximum=entry["maximum"],
            levels=tuple(
                Level(
                    score=level["score"],
                    meaning=level["meaning"],
                    justification=level["justification"],
                    source=level["source"],
                )
                for level in entry["levels"]
            ),
            unresolved_default=entry["unresolved_default"],
            unresolved_policy=entry["unresolved_policy"],
            unresolved_rationale=entry["unresolved_rationale"],
            sensitivity_sweep=None if sweep is None else (sweep[0], sweep[1]),
        )
    return MappingProxyType(built)


@lru_cache(maxsize=1)
def bands() -> tuple[Band, ...]:
    """The four priority bands, highest first."""
    return tuple(
        Band(
            name=entry["name"],
            minimum=entry["minimum"],
            maximum=entry["maximum"],
            action=entry["action"],
        )
        for entry in _document()["bands"]
    )


def model() -> MappingProxyType[str, Any]:
    """The frozen model block: formula, equal weighting, and score bounds."""
    return MappingProxyType(dict(_document()["model"]))


def coherence_rules() -> MappingProxyType[str, str]:
    """The four structural rules from spec section 3.5, carried as data for S3."""
    return MappingProxyType(dict(_document()["coherence_rules"]))


def score_bounds() -> tuple[int, int]:
    """The reachable total-score range: (1, 28) under the frozen ranges."""
    block = _document()["model"]
    return (int(block["minimum_score"]), int(block["maximum_score"]))


def unresolved_default(factor_key: str) -> int:
    """The value an unresolved instance of `factor_key` takes (spec section 3.2)."""
    return factors()[factor_key].unresolved_default


def band_for(score: int) -> str:
    """The priority band a total score falls in.

    Raises `ValueError` outside 1..28. An out-of-range total is a caller that has
    broken the frozen model, and a clamped band would bury that rather than
    surface it.
    """
    minimum, maximum = score_bounds()
    if not minimum <= score <= maximum:
        raise ValueError(f"score {score} is outside the frozen model range {minimum}..{maximum}")
    for band in bands():
        if band.minimum <= score <= band.maximum:
            return band.name
    raise ValueError(f"score {score} matched no band; rubric.json bands do not tile the range")
