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

UNKNOWN = "unknown"
"""The explicit severity-undetermined state. Never coerced to a numeric level."""


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
    precedence_rule: str | None
    """A constraint that overrides level selection, or None where the factor has one.

    Only exposure carries one (spec section 3.4): a `0.0.0.0/0` network-layer
    opening forces the factor to at least 4, and identity-gating may modulate
    only within a network-openness tier, never across it. Carried here rather
    than left in spec prose so S3 cannot reinvent it - the same discipline that
    puts the section 3.5 coherence rules in the artifact.
    """


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
            precedence_rule=entry.get("precedence_rule"),
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
    """Spec section 3.5's three structural resolutions plus its orthogonality note.

    Carried as data so S3 enforces the rules S1 decided rather than reinventing
    them. Four entries, not four resolutions: section 3.5 approves three
    structural decisions, and `encryption_sensitivity_orthogonality` is its
    closing secondary fix - already baked into the authored encryption levels,
    recorded here so the reasoning survives alongside them.
    """
    return MappingProxyType(dict(_document()["coherence_rules"]))


def structure_frozen() -> bool:
    """Whether the six factors, their ranges, the bounds and the bands are frozen.

    True from the end of S1. This is the claim the freeze actually earns: those
    values were fixed before any scoring output existed, were computed rather
    than asserted, and are pinned by tests.
    """
    return bool(_document()["structure_frozen"])


def citations_audited() -> bool:
    """Whether the per-level `source` strings have been independently re-verified.

    Deliberately separate from `structure_frozen`, because conflating the two is
    how a real defect survived: the corrections from the verification pass
    (design spec section 3.4) were written into the spec prose and never reached
    this artifact, and every check asserted the artifact matched its design
    input - which carried the same uncorrected text. A byte-comparison cannot
    tell a sound citation from a fabricated one, and neither can the anchor test,
    which only looks for a standard's name in the string.

    False until an audit of all 33 levels against the primary sources is
    committed. Treat a quoted `source` as unwarranted while this is False.
    """
    return bool(_document()["citations_audited"])


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


def severity_normalization() -> MappingProxyType[str, Any]:
    """The per-scanner raw-token to 1-5 table (design spec section 3.3)."""
    return MappingProxyType(dict(_document()["severity_normalization"]))


def normalize_severity(scanner: str, token: str | None) -> int | str:
    """Map a scanner's raw severity token to a 1-5 level, or to `UNKNOWN`.

    This is what makes the raw-scanner baseline comparable across scanners
    (PLAN Q7 #5). Four routes end in `UNKNOWN`, and none of them ends in a low
    number, which is the whole point:

    - `None`: the scanner emitted no severity at all. Every one of corpus v0's
      489 such rows is Checkov.
    - A token in `unknown_tokens`: trivy's `UNKNOWN` is severity-undetermined,
      not a benign informational band. Scoring it 1 was the defect the
      verification pass caught (spec section 3.4).
    - A token the table does not know: named, not guessed at.
    - A scanner outside the pinned three: no verified token vocabulary exists
      for it, so its tokens cannot be trusted to mean what they look like.

    The caller resolves `UNKNOWN` through `unresolved_default("severity")`, which
    the table's own `unknown_resolves_to` is asserted to agree with.
    """
    table = _document()["severity_normalization"]
    if scanner not in table["per_scanner"]:
        return UNKNOWN
    if token is None:
        return UNKNOWN
    normalized = token.strip().upper()
    if not normalized or normalized in table["unknown_tokens"]:
        return UNKNOWN
    scale: dict[str, int] = table["token_scale"]
    level = scale.get(normalized)
    return UNKNOWN if level is None else level
