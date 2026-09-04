"""Aggregate InventoryRows into the committed rule inventory.

Output feeds two S1 deliverables directly: the `rule_ids` lists become the
taxonomy's mapping domain, and `observed_severity_levels` becomes the
severity-normalization table's input vocabulary.

Three states this module refuses to leave uncounted, each because dropping it makes
it indistinguishable from a different and better outcome:

- **No severity.** `native_severity is None` is counted as itself and reported as a
  rate, never folded into a level (PLAN.md R3-#4). Measured over the six committed
  fixtures: 489 of 1055 rows, and 489 of checkov's 489 - so a default level there
  would not be a small distortion, it would be the entire checkov column.
- **A scanner that found nothing.** Pass `scanners=` and a scanner with zero rows
  still gets an entry. tfsec on the kubernetes root exits 0 with `{"results": []}`,
  so "ran and found nothing" has to be tellable from "was never run".
- **An undefined rate.** `_rate` returns `None` when there is nothing to divide it
  over, never `0.0` - which is the value a scanner measured to be missing nothing
  reports.

Not done here, by ruling: attribution. `tally()` counts whatever `case_id` it is
handed and forms no opinion about how the label got there. The three scanners spell
paths three incompatible ways - checkov mixes separators and contradicts itself
across framework blocks of one run, trivy is scan-root-relative, tfsec is
drive-absolute - so no single prefix rule fits all three, and matching a row to a
corpus case belongs to the task that walks the corpus.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from tools.harvest.model import InventoryRow

RULE_ID_RECONCILIATION = "strip-leading-AVD-prefix"
"""How `distinct_rules` folds two spellings of one rule into one count.

Measured over the six committed fixtures: 255 distinct identifiers, none of them
used by more than one scanner - yet after stripping a leading `AVD-`, trivy's 79
rules and tfsec's 48 overlap on 45, leaving 210 in the union. On the Terraform
corpus both scanners analysed, 45 of tfsec's 48 rules are rules trivy already
reported. `AWS-0026` from trivy and `AVD-AWS-0026` from tfsec are one rule in one
database under two spellings.

Applied to every id rather than to tfsec's alone, which needs no per-scanner branch
and is the same answer on this corpus: the literal `AVD-` appears on none of trivy's
447 records and on all 119 of tfsec's, and checkov's ids are `CKV_*` and `CKV2_*`.
"""


def _canonical_rule_id(rule_id: str) -> str:
    """One rule's identifier with the `AVD-` namespace prefix removed if present."""
    return rule_id.removeprefix("AVD-")


def _rate(numerator: int, denominator: int) -> float | None:
    """The share, or `None` when there is no denominator to have measured one over.

    `0.0` would report an inventory with no rows as missing nothing, which is a
    measurement, and no measurement was made.
    """
    if denominator == 0:
        return None
    return round(numerator / denominator, 3)


def _scanner_summary(scanner_rows: list[InventoryRow]) -> dict[str, Any]:
    """One scanner's own numbers, in its own namespace.

    Deliberately carries no `distinct_rules` and no `rule_id_reconciliation`: a
    scanner's identifiers are its own namespace, so there is nothing to reconcile
    within one, and a second count here could only disagree with the first.
    """
    missing = sum(1 for row in scanner_rows if row.native_severity is None)
    levels = {row.native_severity for row in scanner_rows if row.native_severity is not None}
    rule_ids = {row.rule_id for row in scanner_rows}
    return {
        "rows": len(scanner_rows),
        "distinct_rule_ids": len(rule_ids),
        "rule_ids": sorted(rule_ids),
        "missing_severity_rows": missing,
        "missing_severity_rate": _rate(missing, len(scanner_rows)),
        "observed_severity_levels": sorted(levels),
        # Counts, not bare labels: a state that is present but uncounted - the
        # explicit `unattributed` one above all - reads as absent.
        "cases": dict(sorted(Counter(row.case_id for row in scanner_rows).items())),
    }


def tally(rows: Iterable[InventoryRow], scanners: Iterable[str] | None = None) -> dict[str, Any]:
    """Summarize rows per scanner and overall.

    `scanners` names the scanners that ran. It is a floor, not a filter: every name
    in it gets an entry even at zero rows, and a scanner that produced rows appears
    whether or not it was named. Omitted, only scanners with rows appear - which
    cannot represent a scanner that ran and found nothing.

    Every list in the output is sorted and every mapping is key-sorted, so the
    committed inventory diffs cleanly between runs.
    """
    materialized = list(rows)

    by_scanner_rows: dict[str, list[InventoryRow]] = defaultdict(list)
    for name in scanners or ():
        by_scanner_rows[name] = []
    for row in materialized:
        by_scanner_rows[row.scanner].append(row)

    by_scanner: dict[str, Any] = {
        name: _scanner_summary(by_scanner_rows[name]) for name in sorted(by_scanner_rows)
    }

    total_missing = sum(1 for row in materialized if row.native_severity is None)
    return {
        "totals": {
            "rows": len(materialized),
            # Identifiers, which is what the name says: two spellings of one rule
            # count twice here and once in `distinct_rules`, and both numbers are
            # reported because S1 needs the mapping domain and the deduplication
            # figure to be different numbers.
            "distinct_rule_ids": len({row.rule_id for row in materialized}),
            "distinct_rules": len({_canonical_rule_id(row.rule_id) for row in materialized}),
            "rule_id_reconciliation": RULE_ID_RECONCILIATION,
            "missing_severity_rows": total_missing,
            "missing_severity_rate": _rate(total_missing, len(materialized)),
            "scanners": sorted(by_scanner),
        },
        "by_scanner": by_scanner,
    }
