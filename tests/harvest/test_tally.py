"""The inventory is the S0 deliverable: what fired, how often, how much severity.

The rows `_row` builds are synthetic, and each carries its own scanner's measured
id namespace: checkov `CKV_*`, trivy `AWS-*` - the literal `AVD-` appears on none
of trivy's 447 records - and tfsec `AVD-*` on all 119 of its results. Getting that
backwards would make this file, the worked example of a row that a later reader
reaches for, teach the wrong vocabulary. Where a literal the corpus does not
contain is used deliberately, `Unobserved:` marks it in the test's own docstring -
the convention `tests/harvest/test_walkers.py` established.

Not tested here, by ruling: attribution. `tally()` counts whatever `case_id` it is
handed and forms no opinion about how the label got there. The three scanners spell
paths three incompatible ways, so no single prefix rule fits all three, and
deciding a row's case belongs to the task that walks the corpus.
"""

from __future__ import annotations

from tools.harvest.model import InventoryRow
from tools.harvest.tally import tally

# Every figure quoted in this module was measured this session, over the six
# committed fixtures and with the Task 6 walkers, by:
#
#   uv run python -c "import json, pathlib; \
#     from tools.harvest.walkers import walk; \
#     rows = [r for p in sorted(pathlib.Path('tests/harvest/fixtures').iterdir()) \
#       for r in walk(p.stem.split('-')[0], json.loads(p.read_bytes()), p.stem)]; \
#     canon = lambda i: i.removeprefix('AVD-'); \
#     ids = lambda s: {canon(r.rule_id) for r in rows if r.scanner == s}; \
#     print(len(rows), sum(1 for r in rows if r.native_severity is None), \
#       len({r.rule_id for r in rows}), len({canon(r.rule_id) for r in rows})); \
#     print(sorted({r.native_severity for r in rows if r.native_severity})); \
#     print(len(ids('trivy')), len(ids('tfsec')), len(ids('trivy') & ids('tfsec')), \
#       sorted(ids('tfsec') - ids('trivy')))"
#
#   1055 489 255 210
#   ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']
#   79 48 45 ['AWS-0057', 'AWS-0082', 'AWS-0088']
#
# Read: 1055 rows of which 489 carry no severity; 255 distinct identifiers that
# reconcile to 210 rules; the entire observed severity vocabulary; and trivy's 79
# rules against tfsec's 48, overlapping on 45 and leaving AWS-0057, AWS-0082 and
# AWS-0088 as the three tfsec reports here that trivy does not.


def _row(scanner: str, rule_id: str, severity: str | None, case_id: str = "c1") -> InventoryRow:
    return InventoryRow(
        scanner=scanner,
        rule_id=rule_id,
        native_severity=severity,
        target="x.tf",
        case_id=case_id,
    )


def test_empty_input_yields_zeroed_totals_not_a_crash() -> None:
    """Zero rows is a real outcome: tfsec on the kubernetes root produces exactly it.

    `missing_severity_rate` is `None`, not `0.0`. With no rows there is nothing to
    have measured, and `0.0` is what a scanner measured to be missing nothing
    reports - the discrimination `test_missing_severity_rate_is_reported_per_scanner`
    holds up from the other side.
    """
    out = tally([])
    assert out["totals"]["rows"] == 0
    assert out["totals"]["distinct_rule_ids"] == 0
    assert out["totals"]["distinct_rules"] == 0
    assert out["totals"]["missing_severity_rate"] is None
    assert out["by_scanner"] == {}


def test_counts_rows_and_distinct_rule_ids() -> None:
    """Rows are firings and rule ids are rules; a repeated id is one of each.

    Unobserved: checkov's `severity` is null on all 489 of its failed checks at this
    pin, so a checkov row carrying "HIGH" is a synthetic value. `tally()` reads the
    field it is given and never the scanner, so the literal is harmless here; it is
    marked because a test that reads like observed scanner behaviour and is not is
    the defect class these modules refuse.
    """
    rows = [
        _row("checkov", "CKV_AWS_18", "HIGH"),
        _row("checkov", "CKV_AWS_18", "HIGH", case_id="c2"),
        _row("checkov", "CKV_AWS_21", "LOW"),
        _row("trivy", "AWS-0088", "HIGH"),
    ]
    out = tally(rows)
    assert out["totals"]["rows"] == 4
    assert out["totals"]["distinct_rule_ids"] == 3
    assert out["by_scanner"]["checkov"]["rows"] == 3
    assert out["by_scanner"]["checkov"]["distinct_rule_ids"] == 2
    assert out["by_scanner"]["trivy"]["rows"] == 1


def test_missing_severity_rate_is_reported_per_scanner() -> None:
    """PLAN.md R3-#4 requires the missing-severity rate, not a silent default.

    checkov's real rate at this pin is 1.0 - 489 of 489 - so a default level here
    would not be a small distortion, it would be the entire checkov column.

    trivy's `0.0` is the assertion that makes `None` mean something: a measured
    zero, over a denominator of 1, next to the `None` an absent denominator gets.
    """
    rows = [
        _row("checkov", "CKV_AWS_18", None),
        _row("checkov", "CKV_AWS_21", None),
        _row("checkov", "CKV_AWS_22", "HIGH"),
        _row("trivy", "AWS-0088", "HIGH"),
    ]
    out = tally(rows)
    ck = out["by_scanner"]["checkov"]
    assert ck["missing_severity_rows"] == 2
    assert ck["missing_severity_rate"] == 0.667
    assert out["by_scanner"]["trivy"]["missing_severity_rate"] == 0.0
    assert out["totals"]["missing_severity_rate"] == 0.5


def test_rule_ids_are_listed_sorted_for_stable_diffs() -> None:
    """The inventory is committed, so its ordering must be deterministic."""
    rows = [_row("trivy", "AWS-0002", "LOW"), _row("trivy", "AWS-0001", "LOW")]
    out = tally(rows)
    assert out["by_scanner"]["trivy"]["rule_ids"] == ["AWS-0001", "AWS-0002"]


def test_observed_severity_levels_are_collected() -> None:
    """S1's severity-normalization table needs the real level vocabulary.

    Unobserved: the vocabulary measured across all six fixtures is CRITICAL, HIGH,
    MEDIUM, LOW - uppercase, and nothing else. The lowercase `"low"` below is a
    deliberately unobserved literal, and it is what pins that levels are collected
    verbatim and never case-folded: S1 has to be able to see for itself whether a
    scanner ever spells one level two ways.

    The `None` row contributes no level. It is counted by
    `missing_severity_rows`, which is the only place an absent severity appears.
    """
    rows = [
        _row("trivy", "AWS-0001", "CRITICAL"),
        _row("trivy", "AWS-0002", "low"),
        _row("trivy", "AWS-0003", None),
    ]
    out = tally(rows)
    assert out["by_scanner"]["trivy"]["observed_severity_levels"] == ["CRITICAL", "low"]
    assert out["by_scanner"]["trivy"]["missing_severity_rows"] == 1


def test_declared_scanner_that_found_nothing_is_reported_not_omitted() -> None:
    """A scanner that ran and found nothing may not read like one that never ran.

    tfsec on the kubernetes root exits 0 and returns `{"results": []}`, producing 0
    rows - byte-identical in shape to a clean scan. Populating `by_scanner` from the
    rows alone gives that scanner no key at all, so the same false negative the
    lockfile's platform matrix exists to expose would reappear one layer up, in the
    metrics. `scanners=` is what makes the zero visible.

    Each such entry's rate is `None` for the reason
    `test_empty_input_yields_zeroed_totals_not_a_crash` gives.
    """
    out = tally([], scanners=["checkov", "trivy", "tfsec"])
    assert sorted(out["by_scanner"]) == ["checkov", "tfsec", "trivy"]
    assert out["totals"]["scanners"] == ["checkov", "tfsec", "trivy"]
    for name in ("checkov", "tfsec", "trivy"):
        entry = out["by_scanner"][name]
        assert entry["rows"] == 0
        assert entry["distinct_rule_ids"] == 0
        assert entry["rule_ids"] == []
        assert entry["missing_severity_rows"] == 0
        assert entry["missing_severity_rate"] is None
        assert entry["observed_severity_levels"] == []
        assert entry["cases"] == {}


def test_declared_scanners_are_a_floor_not_a_filter() -> None:
    """Naming one scanner must not drop the rows another one produced."""
    out = tally([_row("trivy", "AWS-0088", "HIGH")], scanners=["checkov"])
    assert sorted(out["by_scanner"]) == ["checkov", "trivy"]
    assert out["by_scanner"]["checkov"]["rows"] == 0
    assert out["by_scanner"]["trivy"]["rows"] == 1
    assert out["totals"]["rows"] == 1


def test_cases_carry_row_counts_not_just_labels() -> None:
    """A bare label shows a state is present without showing how much of it there is.

    Task 8 stamps the explicit `unattributed` state, and a list that names it says
    nothing about whether it covers one row or every row - a state that is present
    but uncounted reads as absent. Keys are sorted, so `c2` inserted first still
    comes second.
    """
    rows = [
        _row("checkov", "CKV_AWS_18", None, case_id="c2"),
        _row("checkov", "CKV_AWS_21", None, case_id="c1"),
        _row("checkov", "CKV_AWS_22", None, case_id="c1"),
    ]
    out = tally(rows)
    assert out["by_scanner"]["checkov"]["cases"] == {"c1": 2, "c2": 1}
    assert list(out["by_scanner"]["checkov"]["cases"]) == ["c1", "c2"]


def test_distinct_rules_reconciles_one_rule_spelled_two_ways() -> None:
    """`distinct_rule_ids` counts identifiers; `distinct_rules` counts rules.

    Over the six fixtures those are 255 and 210: no identifier is used by more than
    one scanner, yet after stripping a leading `AVD-` trivy's 79 rules and tfsec's 48
    overlap on 45. `AWS-0088` from trivy and `AVD-AWS-0088` from tfsec are one rule
    in one database under two spellings - tfsec is being folded into Trivy, and both
    tfsec captures' recorded stderr in `artifacts/scanner-behavior.json` carries the
    "tfsec is joining the Trivy family" banner saying so.

    Measured, `AWS-0088` is one of exactly three rules tfsec reports on this corpus
    that trivy does not, so the pair below is a real cross-scanner spelling rather
    than an invented one; the trivy row is synthetic only in that trivy did not flag
    this rule here.

    This is the number that reaches furthest out of S0. S1's taxonomy maps rule ids
    and would otherwise map this rule twice under two names, and CLAUDE.md commits to
    reporting deduplication reduction as a figure of its own, of which this
    cross-scanner overlap is the dominant component.
    """
    rows = [_row("trivy", "AWS-0088", "HIGH"), _row("tfsec", "AVD-AWS-0088", "HIGH")]
    out = tally(rows)
    assert out["totals"]["distinct_rule_ids"] == 2
    assert out["totals"]["distinct_rules"] == 1
    assert out["totals"]["rule_id_reconciliation"] == "strip-leading-AVD-prefix"


def test_reconciliation_never_reaches_a_per_scanner_count() -> None:
    """A scanner's ids are its own namespace, so only the union needs reconciling.

    Per scanner there is deliberately no second number that could disagree with the
    first, and across the whole inventory `distinct_rule_ids >= distinct_rules`
    always: reconciliation can merge identifiers, never split them.
    """
    rows = [_row("trivy", "AWS-0088", "HIGH"), _row("tfsec", "AVD-AWS-0088", "HIGH")]
    out = tally(rows)
    for name in ("tfsec", "trivy"):
        assert out["by_scanner"][name]["distinct_rule_ids"] == 1
        assert "distinct_rules" not in out["by_scanner"][name]
        assert "rule_id_reconciliation" not in out["by_scanner"][name]
    assert out["totals"]["distinct_rule_ids"] >= out["totals"]["distinct_rules"]
