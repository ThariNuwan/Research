"""The committed class-to-factor table, and the factor-gap marker derived from it.

Spec §2.2. This artifact did not exist before S4: the S2 handoff records that "no
class-to-factor mapping exists anywhere in the data", which is why single-factor purity
remained an authored judgement and the factor-gap set was never established as complete.
The table makes the 28 x 6 sweep a committed artifact, and `is_factor_gap` derives the
marker from it rather than from a hand-maintained list of class names that a taxonomy
change could leave stale.

The sweep it enabled has already paid for itself: `CLAUDE.md` named **five** candidate gap
classes and said the set was not established as complete. Applying the authoring rule to all
28 class *definitions* found **14**, covering 434 of 1,025 eligible findings rather than 122.
Spec §1.4 carries the full table and the two-number split that keeps the 178
self-declared-hygiene findings out of the 256 substantive figure.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

__all__ = [
    "GAP_CANDIDATE_FACTORS",
    "PATH",
    "bearing_factors",
    "is_factor_gap",
    "is_self_declared_minor",
    "is_substantive_gap",
    "rule",
    "table",
]

_MINOR_PATTERN = re.compile(r"lower-severity|no direct .{0,40}impact", re.IGNORECASE)
"""Matches a class definition that characterises itself as minor.

Spec §1.4 splits the 434 gap findings by a **textual test on each class's own definition**
rather than by judgement: does the definition describe the class as "lower-severity" or as
having "no direct … impact"? Deriving the split from the taxonomy keeps it checkable and
stops it drifting from a hand-maintained list.
"""

PATH = Path(__file__).resolve().parent.parent / "data" / "factor_map.json"

GAP_CANDIDATE_FACTORS = frozenset({"exposure", "privilege", "encryption"})
"""The only factors that can distinguish a gap.

`severity`, `sensitivity` and `criticality` bear on every class - they describe the rule
baseline, the asset and the environment rather than the risk mechanism - so including them
would make every class a non-gap and the marker meaningless.
"""


@lru_cache(maxsize=1)
def _document() -> Mapping[str, Any]:
    return MappingProxyType(json.loads(PATH.read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def table() -> Mapping[str, frozenset[str]]:
    """Class id to the set of factors that bear on the risk that class names."""
    classes = _document()["classes"]
    assert isinstance(classes, dict)
    return MappingProxyType(
        {class_id: frozenset(entry["bears"]) for class_id, entry in classes.items()}
    )


def bearing_factors(class_id: str) -> frozenset[str]:
    """The factors that bear on this class. KeyError for a class not in the table.

    An `unmapped:<scanner>:<rule_id>` class has no entry by design. Raising rather than
    returning an empty set keeps two different exclusions distinct: PLAN Q7 excludes
    `unmapped:` findings from prioritization-quality claims, while spec §2.3 deliberately
    does **not** exclude factor-gap findings. A silent empty set would collapse them.
    """
    return table()[class_id]


def is_factor_gap(class_id: str) -> bool:
    """True when no parsed factor bears on the risk this class names."""
    return not (bearing_factors(class_id) & GAP_CANDIDATE_FACTORS)


def is_self_declared_minor(class_id: str) -> bool:
    """True when the class's own definition calls it lower-severity or without direct impact.

    Read off `taxonomy`, not off this table, so the split spec §1.4 reports is derived from
    the class definitions rather than restated. Measured: 4 of the 14 gap classes match,
    covering 178 findings; the other 10 cover 256.
    """
    from iacrisk import taxonomy

    return bool(_MINOR_PATTERN.search(taxonomy.classes()[class_id].definition))


def is_substantive_gap(class_id: str) -> bool:
    """A factor gap whose class does **not** disclaim its own severity.

    This is the population spec §2.1's ruling is argued against - 256 findings, 25.0% - and
    the figure the write-up carries. Folding the 178 self-declared-minor findings into it
    would nearly double the apparent limitation.
    """
    return is_factor_gap(class_id) and not is_self_declared_minor(class_id)


def rule() -> str:
    """The authoring rule, carried as data so the table and its rule cannot drift apart."""
    value = _document()["rule"]
    assert isinstance(value, str)
    return value
