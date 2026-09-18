"""The inventory is the S0 deliverable: what fired, how often, how much severity.

The rows `_row` builds are synthetic, and each carries its own scanner's measured
id namespace: checkov `CKV_*`, trivy `AWS-*` - the literal `AVD-` appears on none
of trivy's 447 records - and tfsec `AVD-*` on all 119 of its results. Getting that
backwards would make this file, the worked example of a row that a later reader
reaches for, teach the wrong vocabulary. Where a literal the corpus does not
contain is used deliberately, `Unobserved:` marks it in the test's own docstring -
the convention `tests/harvest/test_walkers.py` established. **The markers are the
index of those cases, not an enumeration in this paragraph**: grep for `Unobserved`,
which reaches `_row`'s `target` and `case_id` defaults as well as the rule ids.

Two layers, the split `test_walkers.py` uses: hand-built rows that pin one behaviour
at a time, and a golden pin that runs the real walkers over the six committed
fixtures. The second layer is here because two of the figures `tally()` computes are
measured nowhere else in the suite. `test_walkers.py` pins each fixture's rows, its
severity distribution and its distinct rule *ids*, so `distinct_rules` and the
cross-scanner rule overlap can move on a pin bump with every number that suite holds
still holding. The `distinct_rule_ids >= distinct_rules` invariant `tally.py` states
is asserted in that second layer as well, over measured rows rather than over rows
this file chose: an inequality asserted over its own literals cannot fail.

Not tested here, by ruling: attribution. `tally()` counts whatever `case_id` it is
handed and forms no opinion about how the label got there. The three scanners spell
paths three incompatible ways, so no single prefix rule fits all three, and
deciding a row's case belongs to the task that walks the corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.harvest.model import InventoryRow

# `_canonical_rule_id` is private and imported anyway: the cross-scanner overlap test
# below has to fold ids with the same rule the module under test folds them with, and
# restating `removeprefix('AVD-')` in the test would let the two drift apart silently.
from tools.harvest.tally import _canonical_rule_id, tally
from tools.harvest.walkers import walk

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST = REPO_ROOT / "artifacts" / "scanner-behavior.json"
CAPTURES: tuple[dict[str, Any], ...] = tuple(json.loads(MANIFEST.read_bytes())["captures"])

# Every figure quoted in this module - the golden tables below and every number in a
# docstring - was measured this session, over the six committed fixtures and with the
# Task 6 walkers, by:
#
#   uv run python -c "import json, pathlib; \
#     from tools.harvest.tally import tally; \
#     from tools.harvest.walkers import walk; \
#     man = json.loads(pathlib.Path('artifacts/scanner-behavior.json').read_bytes()); \
#     caps = man['captures']; \
#     paths = [pathlib.Path(c['fixture']) for c in caps]; \
#     rows = [r for c, p in zip(caps, paths) \
#       for r in walk(c['scanner'], json.loads(p.read_bytes()), p.stem)]; \
#     out = tally(rows, scanners=sorted({c['scanner'] for c in caps})); \
#     t = out['totals']; \
#     ids = lambda s: {r.rule_id.removeprefix('AVD-') for r in rows if r.scanner == s}; \
#     print(t['rows'], t['distinct_rule_ids'], t['distinct_rules'], \
#       t['missing_severity_rows'], t['missing_severity_rate']); \
#     [print(n, e['rows'], e['distinct_rule_ids'], e['missing_severity_rows'], \
#       e['missing_severity_rate'], e['observed_severity_levels']) \
#       for n, e in sorted(out['by_scanner'].items())]; \
#     print(sorted(out['by_scanner']['tfsec']['cases'].items())); \
#     print(len(ids('trivy') & ids('tfsec')), sorted(ids('tfsec') - ids('trivy')), \
#       len(ids('checkov') & (ids('trivy') | ids('tfsec'))))"
#
#   1055 255 210 489 0.464
#   checkov 489 128 489 1.0 []
#   tfsec 119 48 0 0.0 ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']
#   trivy 447 79 0 0.0 ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']
#   [('tfsec-terraform', 119)]
#   45 ['AWS-0057', 'AWS-0082', 'AWS-0088'] 0
#
# Read: 1055 rows carrying 255 distinct identifiers that reconcile to 210 rules, 489
# of the rows with no severity at all - 0.464 of them; then per scanner its rows, its
# distinct identifiers, its missing-severity rows and rate, and its severity
# vocabulary; then tfsec's cases, where the kubernetes capture that produced no rows
# contributes no key at all; then trivy and tfsec overlapping on 45 canonical rules,
# the three rules tfsec reports here that trivy does not, and checkov's canonical ids
# intersecting the other two scanners' on none.

# What `tally()` reports over all six fixtures at once, key for key: an added or
# dropped `totals` key fails here too. `test_walkers.py` pins each fixture's rows and
# its severity distribution, so `rows` and `missing_severity_rows` moving here while
# that suite stays green means this aggregation changed rather than the bytes, and
# moving in both means a walker or a fixture did. `distinct_rule_ids` is implied there
# only while no two captures share an identifier - measured, none do, so 98 + 30 + 49
# + 30 + 48 + 0 sums to the 255 below - and a move with that suite green means two
# captures started sharing one. `distinct_rules` is pinned nowhere else in the suite.
EXPECTED_TOTALS: dict[str, Any] = {
    "rows": 1055,
    "distinct_rule_ids": 255,
    "distinct_rules": 210,
    "rule_id_reconciliation": "strip-leading-AVD-prefix",
    "missing_severity_rows": 489,
    "missing_severity_rate": 0.464,
    "scanners": ["checkov", "tfsec", "trivy"],
}

# The scalar half of each scanner's entry. `rule_ids` is left out for the reason
# `test_walkers.py` gives for holding no id table - 255 literals would couple this
# suite to bytes Task 8 re-derives anyway - and `cases` is left out because its labels
# are this module's own, not corpus data. EXPECTED_ENTRY_KEYS covers both by shape.
EXPECTED_BY_SCANNER: dict[str, dict[str, Any]] = {
    "checkov": {
        "rows": 489,
        "distinct_rule_ids": 128,
        "missing_severity_rows": 489,
        "missing_severity_rate": 1.0,
        "observed_severity_levels": [],
    },
    "tfsec": {
        "rows": 119,
        "distinct_rule_ids": 48,
        "missing_severity_rows": 0,
        "missing_severity_rate": 0.0,
        "observed_severity_levels": ["CRITICAL", "HIGH", "LOW", "MEDIUM"],
    },
    "trivy": {
        "rows": 447,
        "distinct_rule_ids": 79,
        "missing_severity_rows": 0,
        "missing_severity_rate": 0.0,
        "observed_severity_levels": ["CRITICAL", "HIGH", "LOW", "MEDIUM"],
    },
}

EXPECTED_ENTRY_KEYS = {
    "rows",
    "distinct_rule_ids",
    "rule_ids",
    "missing_severity_rows",
    "missing_severity_rate",
    "observed_severity_levels",
    "cases",
}

# How many canonical rules each scanner reports, and what the reconciliation folds.
# These three move on a trivy or tfsec pin bump that changes which rules the two
# scanners share, on a corpus bump, and on a change to the reconciliation rule itself -
# `_canonical_rule_id` is imported rather than restated below, so the fold under test
# is the fold measured. checkov's 128 are disjoint from both other scanners', so
# 255 - 210 = 45 is exactly the trivy/tfsec overlap and nothing else, and that identity
# is what says the fold merged the cross-scanner duplicate spellings only. The three
# ids are tfsec's residue in canonical spelling; its own rows spell them `AVD-AWS-0057`
# and so on.
EXPECTED_CANONICAL_RULES: dict[str, int] = {"checkov": 128, "trivy": 79, "tfsec": 48}
EXPECTED_TRIVY_TFSEC_OVERLAP = 45
EXPECTED_TFSEC_ONLY_RULES: list[str] = ["AWS-0057", "AWS-0082", "AWS-0088"]


def _fixture_rows() -> list[InventoryRow]:
    """Every row the six committed fixtures produce, through the walkers under test.

    The scanner name comes from `artifacts/scanner-behavior.json` rather than from
    splitting a filename: the manifest is the record of which binary produced which
    bytes. `case_id` is the fixture stem, a label this module supplies - attribution
    belongs to the task that walks the corpus, and `tally()` counts what it is handed.
    """
    rows: list[InventoryRow] = []
    for capture in CAPTURES:
        path = REPO_ROOT / capture["fixture"]
        assert path.exists(), f"golden fixture is missing from disk: {path}"
        rows.extend(walk(capture["scanner"], json.loads(path.read_bytes()), path.stem))
    return rows


def _row(scanner: str, rule_id: str, severity: str | None, case_id: str = "c1") -> InventoryRow:
    """One synthetic row for the hand-built layer, with two deliberate placeholders.

    Unobserved: `x.tf` is no target any fixture row carries - the 72 distinct targets
    the corpus produces are TerraGoat and KubeGoat paths - and `c1`/`c2` are no case
    ids either: `tools/corpus.lock.json` names five, `kg-scenarios`, `tg-aws-compute`,
    `tg-aws-iam`, `tg-aws-networking` and `tg-aws-s3`. `tally()` reads neither field's
    content - it counts rows per `scanner` and per `case_id` and never looks at
    `target` at all - so a placeholder cannot mask a defect here, while a real-looking
    path or case id would invite a later reader to grep the corpus for it.
    """
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

    Unobserved: trivy reports no `AWS-0088` on this corpus. `AVD-AWS-0088`, from
    tfsec, is the one spelling of that rule any fixture row carries, which is the
    pairing `test_distinct_rules_reconciles_one_rule_spelled_two_ways` turns on.
    `CKV_AWS_18` and `CKV_AWS_21` are checkov ids this corpus does emit.
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

    Unobserved: `CKV_AWS_22` and trivy's `AWS-0088` are ids no fixture row carries.
    Three checkov rows and one trivy row is the smallest shape that puts a rate of
    two thirds beside a rate of zero, and which ids carry them changes nothing.
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
    """The inventory is committed, so its ordering must be deterministic.

    Unobserved: neither `AWS-0001` nor `AWS-0002` appears in the corpus. Two ids one
    digit apart, inserted in reverse, is the plainest shape the claim has.
    """
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

    Unobserved: `AWS-0001`, `AWS-0002` and `AWS-0003` are ids no fixture row carries.
    One id per row keeps the three severity states - a level, a second spelling of a
    level, and none - from sharing a row and being indistinguishable in the result.

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
    """Naming one scanner must not drop the rows another one produced.

    Unobserved: trivy reports no `AWS-0088` here; the row exists to be a row from a
    scanner that was not named, and its id carries none of the claim.
    """
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

    Unobserved: `CKV_AWS_22` is an id no fixture row carries. Three distinct ids keep
    the two case counts from being read off a repeated id instead.
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
    overlap on 45. Both numbers are asserted against the fixtures themselves in
    `test_tally_over_the_six_fixtures_matches_the_golden_table`, which leaves this
    test the two-row worked example of the fold they aggregate: `AWS-0088` from trivy
    and `AVD-AWS-0088` from tfsec are one rule in one database under two spellings -
    tfsec is being folded into Trivy, and both tfsec captures' recorded stderr in
    `artifacts/scanner-behavior.json` carries the "tfsec is joining the Trivy family"
    banner saying so.

    Measured, `AWS-0088` is one of exactly three rules tfsec reports on this corpus
    that trivy does not. Unobserved: trivy reports none of the three, so the pair
    below is a real cross-scanner spelling of one rule rather than an invented one,
    while the trivy half is a row trivy did not produce - `AVD-AWS-0088`, from tfsec,
    is the only half any fixture row carries.

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
    first. The `distinct_rule_ids >= distinct_rules` invariant that follows from the
    same fact is stated in `tally.py`'s module docstring and asserted in
    `test_tally_over_the_six_fixtures_matches_the_golden_table`, over measured rows:
    asserted here it would have read `2 >= 1` over two ids this test chose, and an
    inequality that cannot fail reports coverage it does not have.

    Unobserved: trivy reports no `AWS-0088`, the same pair as the test above.
    """
    rows = [_row("trivy", "AWS-0088", "HIGH"), _row("tfsec", "AVD-AWS-0088", "HIGH")]
    out = tally(rows)
    for name in ("tfsec", "trivy"):
        assert out["by_scanner"][name]["distinct_rule_ids"] == 1
        assert "distinct_rules" not in out["by_scanner"][name]
        assert "rule_id_reconciliation" not in out["by_scanner"][name]


def test_a_bare_string_for_scanners_is_refused_rather_than_iterated() -> None:
    """The one argument mistake the annotation cannot express and mypy cannot see.

    `str` is `Iterable[str]`, so `tally(rows, scanners="checkov")` type-checks, and
    iterating it seeds six single-character scanners - `c`, `e`, `h`, `k`, `o`, `v` -
    each with zero rows. Nothing downstream fails: the six are well-formed entries in
    a committed inventory, and every claim about scanner coverage still passes over
    them. The error names the parameter because the call site's mistake is one pair of
    brackets wide.
    """
    with pytest.raises(TypeError, match="scanners"):
        tally([], scanners="checkov")
    assert tally([], scanners=["checkov"])["totals"]["scanners"] == ["checkov"]


def test_tally_over_the_six_fixtures_matches_the_golden_table() -> None:
    """Golden pin: the six committed fixtures, through the real walkers, into `tally()`.

    The hand-built tests above pin one behaviour each over two to four rows they chose.
    This one pins what the module actually reports over the corpus, which is the only
    place `distinct_rules` can be checked at all - two rows cannot show a 45-rule
    overlap. What each number's movement means is recorded above its table.

    It also restates the `distinct_rule_ids >= distinct_rules` invariant `tally.py`
    states, as 255 >= 210 beside the measured numbers it holds over. **The restatement
    cannot fail here**: `EXPECTED_TOTALS` pins both operands, so a reconciliation that
    split one identifier into two breaks the whole-dict assertion above before this line
    is reached. Testing the fold is
    `test_the_cross_scanner_rule_overlap_is_pinned_not_only_reported`'s job - it derives
    the 45 from the rows with `_canonical_rule_id` and never consults `totals`, so a
    changed fold breaks it on its own terms.

    The last assertion is the case-level half of the empty-scan problem `scanners=`
    solves at scanner level: tfsec's kubernetes capture produced no rows, so it
    contributes no `cases` key at all, while tfsec keeps a `by_scanner` entry because
    it was named. The label is this module's (see `_fixture_rows`); the 119 and the
    absence are measured.
    """
    rows = _fixture_rows()
    out = tally(rows, scanners=sorted({capture["scanner"] for capture in CAPTURES}))

    assert out["totals"] == EXPECTED_TOTALS
    assert sorted(out["by_scanner"]) == sorted(EXPECTED_BY_SCANNER)
    for name, expected in EXPECTED_BY_SCANNER.items():
        entry = out["by_scanner"][name]
        assert set(entry) == EXPECTED_ENTRY_KEYS, f"{name}'s entry changed shape"
        assert {key: entry[key] for key in expected} == expected, f"{name} drifted"
        assert len(entry["rule_ids"]) == entry["distinct_rule_ids"], f"{name} miscounted ids"

    totals = out["totals"]
    assert totals["distinct_rule_ids"] >= totals["distinct_rules"]
    assert totals["distinct_rule_ids"] - totals["distinct_rules"] == EXPECTED_TRIVY_TFSEC_OVERLAP
    assert out["by_scanner"]["tfsec"]["cases"] == {"tfsec-terraform": 119}


def test_the_cross_scanner_rule_overlap_is_pinned_not_only_reported() -> None:
    """The 45 rules two scanners spell two ways, and the three tfsec keeps to itself.

    `distinct_rules` is one integer, and one integer cannot say *which* rules folded.
    This test names the membership: 79 trivy rules against 48 tfsec ones, 45 shared,
    and `AWS-0057`, `AWS-0082`, `AWS-0088` left over. A pin bump that swapped one
    shared rule for one exclusive rule would hold 210 still and move this list, which
    is the drift a count alone cannot see.

    checkov intersecting neither is asserted rather than assumed, because it is what
    makes `distinct_rule_ids - distinct_rules` equal to this overlap rather than to
    some sum of overlaps. It is also why the fold is applied to every id and not to
    tfsec's alone: on this corpus that is the same answer, and `tally.py` says so.
    """
    rows = _fixture_rows()
    canonical = {
        name: {_canonical_rule_id(row.rule_id) for row in rows if row.scanner == name}
        for name in EXPECTED_CANONICAL_RULES
    }

    assert {name: len(ids) for name, ids in canonical.items()} == EXPECTED_CANONICAL_RULES
    assert len(canonical["trivy"] & canonical["tfsec"]) == EXPECTED_TRIVY_TFSEC_OVERLAP
    assert sorted(canonical["tfsec"] - canonical["trivy"]) == EXPECTED_TFSEC_ONLY_RULES
    assert not canonical["checkov"] & (canonical["trivy"] | canonical["tfsec"])
