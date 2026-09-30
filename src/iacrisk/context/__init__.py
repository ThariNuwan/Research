"""Layer 3 — context extraction (S3b, declared-context path only).

Auto-inference of the two declared factors is S3c; nothing in this package reads tags
or naming conventions, and adding such a read here would contaminate the primary
evaluation path's claim to deterministic, defensible inputs.
"""

from iacrisk.context.value import FactorState, FactorValue

__all__ = ["FactorState", "FactorValue"]
