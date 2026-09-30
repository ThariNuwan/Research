"""Context-coverage reporting: the numbers layer 3 exists to make measurable.

Spec section 1.1 is why this module matters more than its size suggests. The five context
defaults sum to 16, so an all-defaulted finding scores 17-21 - always High - and a checkov
finding with nothing resolved lands on exactly 20. **If layer 3 resolves little, the
ranking collapses into one band and the framework's claim evaporates.** The resolution
rate is therefore not a quality metric to report afterwards; it is the condition under
which the framework works at all.

Three reporting rules are structural rather than stylistic:

* **Per-factor rates are never aggregated into one number** (spec 8.2). PLAN Q4's
  missing-declared-value and PLAN Q9's extractor-failure are separate reports.
* **`resolution_distribution` always carries all six keys 0-5**, even at zero, because an
  absent key is indistinguishable from an unmeasured one.
* **`per_class_coverage` covers all 28 taxonomy classes**, including those with no
  findings, because section 8.4's purpose is to let S4 rule on the three classes that map
  to no rubric factor - and a class missing from the report reads as a class with no
  findings.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from iacrisk import taxonomy
from iacrisk.context.extract import CONTEXT_FACTOR_KEYS, ContextualizedFinding
from iacrisk.context.value import FactorState

__all__ = ["ClassCoverage", "ContextCoverage", "build", "to_json"]

_DECLARED_KEYS = ("sensitivity", "criticality")
_PARSED_KEYS = ("exposure", "privilege", "encryption")


@dataclass(frozen=True, slots=True)
class ClassCoverage:
    findings: int
    resolved_factors: int
    possible_factors: int


@dataclass(frozen=True, slots=True)
class ContextCoverage:
    eligible: int
    ineligible: int
    per_factor_defaulted: dict[str, int]
    per_factor_unresolved: dict[str, int]
    resolution_distribution: dict[int, int]
    low_confidence_count: int
    per_class_coverage: dict[str, ClassCoverage]

    @property
    def fully_resolved(self) -> int:
        """Eligible findings with zero defaulted or unresolved factors."""
        return self.resolution_distribution[0]


def build(results: Sequence[ContextualizedFinding]) -> ContextCoverage:
    per_factor_defaulted = {key: 0 for key in _DECLARED_KEYS}
    per_factor_unresolved = {key: 0 for key in _PARSED_KEYS}
    # All six keys present from the outset: an absent key would be indistinguishable
    # from an unmeasured one.
    distribution = {count: 0 for count in range(len(CONTEXT_FACTOR_KEYS) + 1)}
    per_class = {
        class_id: ClassCoverage(findings=0, resolved_factors=0, possible_factors=0)
        for class_id in taxonomy.classes()
    }

    eligible = 0
    ineligible = 0
    low_confidence = 0

    for result in results:
        if not result.factors:
            ineligible += 1
            continue
        eligible += 1

        for value in result.factors:
            if value.state is FactorState.DEFAULTED:
                if value.key not in per_factor_defaulted:
                    # A defaulted exposure, privilege or encryption is a state error, not a
                    # datum: it would be counted in `resolution_distribution` while missing
                    # from every per-factor report, so the two would disagree with nothing
                    # raised. This module's own contract is that it never silently loses a
                    # finding, so it raises instead of dropping.
                    raise ValueError(
                        f"factor {value.key!r} reported DEFAULTED, which only the two "
                        f"declared factors may be"
                    )
                per_factor_defaulted[value.key] += 1
            elif value.state is FactorState.UNRESOLVED:
                if value.key not in per_factor_unresolved:
                    raise ValueError(
                        f"factor {value.key!r} reported UNRESOLVED, which only the three "
                        f"parsed factors may be"
                    )
                per_factor_unresolved[value.key] += 1

        missing = len(result.defaulted_factors) + len(result.unresolved_factors)
        distribution[missing] = distribution.get(missing, 0) + 1
        if result.low_confidence:
            low_confidence += 1

        class_id = result.finding.issue_class
        resolved = sum(1 for v in result.factors if v.state is FactorState.RESOLVED)
        existing = per_class.get(class_id)
        if existing is None:
            # An `unmapped:<scanner>:<rule_id>` class is not in the taxonomy by design.
            # It is counted under its own key rather than dropped, so the report never
            # silently loses a finding.
            existing = ClassCoverage(findings=0, resolved_factors=0, possible_factors=0)
        per_class[class_id] = ClassCoverage(
            findings=existing.findings + 1,
            resolved_factors=existing.resolved_factors + resolved,
            possible_factors=existing.possible_factors + len(result.factors),
        )

    return ContextCoverage(
        eligible=eligible,
        ineligible=ineligible,
        per_factor_defaulted=per_factor_defaulted,
        per_factor_unresolved=per_factor_unresolved,
        resolution_distribution=distribution,
        low_confidence_count=low_confidence,
        per_class_coverage=per_class,
    )


def to_json(coverage: ContextCoverage) -> dict[str, Any]:
    """A JSON-serialisable form. Distribution keys become strings, as JSON requires."""
    return {
        "eligible": coverage.eligible,
        "ineligible": coverage.ineligible,
        "per_factor_defaulted": dict(coverage.per_factor_defaulted),
        "per_factor_unresolved": dict(coverage.per_factor_unresolved),
        "resolution_distribution": {
            str(count): total for count, total in sorted(coverage.resolution_distribution.items())
        },
        "low_confidence_count": coverage.low_confidence_count,
        "fully_resolved": coverage.fully_resolved,
        "per_class_coverage": {
            class_id: {
                "findings": entry.findings,
                "resolved_factors": entry.resolved_factors,
                "possible_factors": entry.possible_factors,
            }
            for class_id, entry in sorted(coverage.per_class_coverage.items())
        },
    }
