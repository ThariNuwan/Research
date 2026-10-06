"""Layer 3's orchestrator: attach five factors to a finding, or skip it entirely.

`context_eligible = False` findings get **no context block at all** - not defaults, not
unresolved markers, nothing. S3a introduced that flag precisely so the all-defaulted
washout cannot float a finding with no resource into High for structural reasons, and
defaulting them here would re-open it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from iacrisk.context import encryption as encryption_extractor
from iacrisk.context import exposure as exposure_extractor
from iacrisk.context import privilege as privilege_extractor
from iacrisk.context.declared import join
from iacrisk.context.inferred import Inference, join_inferred
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.value import FactorState, FactorValue
from iacrisk.finding import NormalizedFinding

__all__ = [
    "CONTEXT_FACTOR_KEYS",
    "LOW_CONFIDENCE_THRESHOLD",
    "ContextualizedFinding",
    "contextualize",
]

CONTEXT_FACTOR_KEYS = ("exposure", "privilege", "sensitivity", "criticality", "encryption")

LOW_CONFIDENCE_THRESHOLD = 3
"""Frozen 2026-09-30, before any scoring output existed (spec section 8.1).

A finding is low-confidence when 3 or more of its 5 contextual factors are defaulted or
unresolved - a majority of the contextual evidence absent. The primary argument is about
evidence rather than arithmetic, and a count is the form the rubric's
`unresolved_default_reporting` coherence rule asks for.

The arithmetic supports it without determining it: the mean default is 16/5 = 3.2 and the
bands span 8, 7, 6 and 7 points, so three defaults contribute about 9.6 - more than any
single band's width - and the defaults alone can therefore decide the band. Two defaults
(about 6.4) already exceed the narrowest band, so the arithmetic does not single out three
on its own.

Later movement is reported as sensitivity analysis (PLAN Q10), never tuned to fit.
"""


@dataclass(frozen=True, slots=True)
class ContextualizedFinding:
    finding: NormalizedFinding
    exposure: FactorValue | None
    privilege: FactorValue | None
    sensitivity: FactorValue | None
    criticality: FactorValue | None
    encryption: FactorValue | None

    @property
    def factors(self) -> tuple[FactorValue, ...]:
        """The present factors, empty for a context-ineligible finding."""
        return tuple(
            value
            for value in (
                self.exposure,
                self.privilege,
                self.sensitivity,
                self.criticality,
                self.encryption,
            )
            if value is not None
        )

    @property
    def defaulted_factors(self) -> tuple[str, ...]:
        """PLAN Q4: a declared value was absent. Only sensitivity and criticality."""
        return tuple(v.key for v in self.factors if v.state is FactorState.DEFAULTED)

    @property
    def unresolved_factors(self) -> tuple[str, ...]:
        """PLAN Q9: the extractor could not resolve. Only the three parsed factors."""
        return tuple(v.key for v in self.factors if v.state is FactorState.UNRESOLVED)

    @property
    def low_confidence(self) -> bool:
        return (
            len(self.defaulted_factors) + len(self.unresolved_factors) >= LOW_CONFIDENCE_THRESHOLD
        )


def contextualize(
    findings: Iterable[NormalizedFinding],
    declared: Mapping[str, Mapping[str, int]],
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    inference: Inference | None = None,
) -> list[ContextualizedFinding]:
    """Attach the five contextual attributes to every context-eligible finding.

    `inference` selects the auto-inference mode: sensitivity and criticality then come
    from the conventions (`context/inferred.py`) and `declared` is not consulted at all.
    The two are alternatives, never merged - a run is one mode or the other, so no value
    in a record can be of uncertain origin.
    """
    results: list[ContextualizedFinding] = []
    for finding in findings:
        if not finding.context_eligible:
            results.append(
                ContextualizedFinding(
                    finding=finding,
                    exposure=None,
                    privilege=None,
                    sensitivity=None,
                    criticality=None,
                    encryption=None,
                )
            )
            continue
        sensitivity, criticality = (
            join(finding.resource_identity, declared, tf_index)
            if inference is None
            else join_inferred(finding.resource_identity, inference, tf_index)
        )
        results.append(
            ContextualizedFinding(
                finding=finding,
                exposure=exposure_extractor.extract(finding, tf_index, k8s_index),
                privilege=privilege_extractor.extract(finding, tf_index, k8s_index),
                sensitivity=sensitivity,
                criticality=criticality,
                encryption=encryption_extractor.extract(finding, tf_index, k8s_index),
            )
        )
    return results


def defaulted_and_unresolved_are_disjoint(results: Sequence[ContextualizedFinding]) -> bool:
    """True when no finding reports a factor as both defaulted and unresolved.

    Disjointness holds by construction - sensitivity and criticality can only be
    defaulted, and the three parsed factors can only be unresolved - and gate 3 asserts it
    corpus-wide, because a future extractor returning the wrong state would otherwise
    corrupt two separately reported rates silently.

    This helper is **test-only** and is deliberately absent from `__all__`. Gate 3 asserts
    disjointness directly rather than calling it; an earlier version of this docstring
    credited gate 3 as the caller, which it is not.
    """
    return all(not (set(r.defaulted_factors) & set(r.unresolved_factors)) for r in results)
