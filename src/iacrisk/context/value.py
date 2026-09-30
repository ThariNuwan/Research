"""The one type every factor resolution returns.

S1 handoff item 5 and S3a handoff item 2 both record the same trap: `normalize_severity`
returns `int | str`, so every call site must branch before arithmetic or a single
unguarded `+` concatenates or raises at runtime. S3b has five such factors, so the trap
is five times larger. This module is the boundary conversion both handoffs recommended:
callers read `scored_level` for arithmetic and `state` for reporting, and no call site
can accidentally add a string.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from iacrisk import rubric

__all__ = ["FactorState", "FactorValue"]


class FactorState(StrEnum):
    """Why a factor holds the value it holds.

    DEFAULTED and UNRESOLVED are deliberately distinct: PLAN Q4's missing declared
    value and PLAN Q9's extractor failure are reported as separate rates, and the
    ground-truth schema carries them as separate fields. Merging them makes that
    report impossible to reconstruct afterwards.
    """

    RESOLVED = "resolved"
    DEFAULTED = "defaulted"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class FactorValue:
    key: str
    level: int | None
    state: FactorState
    evidence: str

    @property
    def scored_level(self) -> int:
        """What S4 does arithmetic on: the read level, or the rubric's documented default.

        Never raises and never returns None, so an unguarded `+` at a scoring call site
        is impossible by construction rather than by discipline.
        """
        if self.level is not None:
            return self.level
        return int(rubric.factors()[self.key].unresolved_default)

    @staticmethod
    def _check(key: str, evidence: str) -> None:
        rubric.factors()[key]  # KeyError on an unknown factor key
        if not evidence.strip():
            raise ValueError(f"evidence is required for factor {key!r}")

    @classmethod
    def resolved(cls, key: str, level: int, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        factor = rubric.factors()[key]
        if not factor.minimum <= level <= factor.maximum:
            raise ValueError(
                f"level {level} is outside {key} range {factor.minimum}-{factor.maximum}"
            )
        return cls(key=key, level=level, state=FactorState.RESOLVED, evidence=evidence)

    @classmethod
    def defaulted(cls, key: str, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        return cls(key=key, level=None, state=FactorState.DEFAULTED, evidence=evidence)

    @classmethod
    def unresolved(cls, key: str, evidence: str) -> FactorValue:
        cls._check(key, evidence)
        return cls(key=key, level=None, state=FactorState.UNRESOLVED, evidence=evidence)
