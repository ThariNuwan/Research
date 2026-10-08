"""`tools.overview.build`: the results page shows the records, and nothing else.

The page is the one place a reader meets every headline figure at once, so it is the one
place a stale or mistyped number would do most harm. Two things keep it honest. The page
is generated, not written: every figure on it is read from a committed record by
`figures`. And the figures are held here to literals taken from the dissertation's own
tables, which the acceptance gates already check against those records by a second route -
so a slip in how this module reads a record shows up as a disagreement with Chapter 6.

The page's prose is not tested. Its numbers are.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from tools.overview import build


@lru_cache(maxsize=1)
def _figures() -> dict[str, Any]:
    return build.figures(build.load())


# --- the figures are the dissertation's -------------------------------------------------


def test_the_populations_are_the_four_chapter_6_names() -> None:
    """Catches the 986 and the 246 being confused, which Chapter 6's first draft did."""
    population = _figures()["population"]

    assert population == {
        "reported": 1055,
        "no_severity": 489,
        "duplicates": 39,
        "ranked": 1016,
        "context_eligible": 986,
        "not_low_confidence": 246,
    }


def test_the_pair_result_carries_how_much_of_it_holds_by_construction() -> None:
    """Catches the headline being shown without what qualifies it: of the eight passes,
    four put one resource under two declarations, and three are hand-crafted."""
    pairs = _figures()["pairs"]

    assert (pairs["total"], pairs["framework"], pairs["baseline"]) == (10, 8, 1)
    assert pairs["by_construction"] == 4
    assert pairs["hand_crafted_passed"] == 3
    assert pairs["mined_needing_extraction"] == {"passed": 1, "total": 3}
    assert pairs["failed"] == ["encryption-s3-data", "encryption-s3-financials"]


def test_each_pair_row_is_the_one_chapter_6_tabulates() -> None:
    rows = {row["pair_id"]: row for row in _figures()["pairs"]["rows"]}

    assert len(rows) == 10
    assert (
        rows["exposure-s3-public-access"]["high"],
        rows["exposure-s3-public-access"]["low"],
    ) == (
        17,
        12,
    )
    assert rows["encryption-s3-data"]["framework"] == "tie"
    assert rows["sensitivity-s3-financials"]["kind"] == "by construction"
    assert rows["privilege-iam-bucket-to-account"]["kind"] == "hand-crafted"
    assert rows["exposure-security-group"]["kind"] == "mined"
    assert [row["baseline"] for row in rows.values()].count("pass") == 1


def test_the_scenario_result_carries_where_the_correct_orderings_come_from() -> None:
    """Nine of the nineteen are decided by declared context alone and three are on
    hand-crafted cases; of the other seven, two are ordered by values read on both sides."""
    scenarios = _figures()["scenarios"]

    assert scenarios["exact"] == {"framework": 2, "baseline": 0, "total": 5}
    assert scenarios["ordered"] == {
        "total": 21,
        "framework": {"right": 19, "tied": 2, "inverted": 0},
        "baseline": {"right": 4, "tied": 16, "inverted": 1},
    }
    assert scenarios["decided_by"] == {
        "declared context alone": 9,
        "hand-crafted cases": 3,
        "code or scanner evidence": 7,
    }
    assert scenarios["read_on_both_sides"] == 2
    assert [row["domain"] for row in scenarios["rows"] if row["exact"]] == ["storage", "iam"]


def test_the_band_figures_are_given_over_both_populations() -> None:
    bands = _figures()["bands"]
    eligible, confident = bands["context_eligible"], bands["not_low_confidence"]

    assert eligible["baseline"] == {"Critical": 16, "High": 633, "Medium": 138, "Low": 199}
    assert eligible["framework"] == {"Critical": 0, "High": 235, "Medium": 747, "Low": 4}
    assert (eligible["before"], eligible["after"], eligible["reduction"]) == (649, 235, "63.8%")
    assert (confident["before"], confident["after"], confident["reduction"]) == (192, 35, "81.8%")


def test_the_band_figures_carry_what_makes_them_unreliable() -> None:
    """Catches the alert-reduction percentage being shown bare."""
    caveats = _figures()["bands"]["caveats"]

    assert caveats == {
        "baseline_high_with_no_severity": 441,
        "low_confidence": 740,
        "high_findings": 235,
        "high_on_the_boundary": 199,
        "highest_score": 20,
        "critical_boundary": 22,
    }


def test_the_sensitivity_figures_are_the_registered_sweeps() -> None:
    sensitivity = _figures()["sensitivity"]

    assert sensitivity["variants"] == 63
    assert sensitivity["pairs_unchanged"] == 59
    assert sensitivity["exact_matches_unchanged"] == 56
    assert sensitivity["high_boundary"] == {14: 581, 15: 296, 16: 235, 17: 36, 18: 19}
    assert sensitivity["defaults"]["exposure"] == {0: 37, 1: 54, 2: 60, 3: 235, 4: 281, 5: 547}
    assert sensitivity["defaults"]["encryption"] == {0: 48, 1: 64, 2: 235, 3: 278}
    assert sensitivity["frozen_defaults"] == {
        "severity": 4,
        "exposure": 3,
        "privilege": 4,
        "sensitivity": 3,
        "criticality": 4,
        "encryption": 2,
    }


def test_the_auto_inference_figures_show_how_little_it_resolved() -> None:
    inference = _figures()["inference"]

    assert inference["resolved"] == {"resources": 2, "of_resources": 81, "findings": 3}
    assert inference["ordered"] == {"right": 11, "tied": 10, "inverted": 0}
    assert inference["high"] == {"declared": 235, "inferred": 326}


def test_the_sample_is_the_five_hand_crafted_resources_as_the_record_scores_them() -> None:
    sample = _figures()["sample"]

    assert [
        (row["resource"], row["score"], row["band"], row["baseline_band"]) for row in sample
    ] == [
        ("aws_iam_policy.unrestricted_scope", 18, "High", "High"),
        ("aws_s3_bucket.public_exposed", 17, "High", "High"),
        ("aws_iam_policy.s3_account_scope", 16, "High", "High"),
        ("aws_iam_policy.s3_bucket_scope", 15, "Medium", "High"),
        ("aws_s3_bucket.private_baseline", 12, "Medium", "High"),
    ]
    assert len(sample[0]["explanation"]) == 6
    assert sample[1]["contributions"]["exposure"] == 5
    assert "encryption" in sample[1]["defaults"] and "exposure" not in sample[1]["defaults"]


def test_the_model_is_read_from_the_rubric() -> None:
    model = _figures()["model"]

    assert [(f["key"], f["minimum"], f["maximum"]) for f in model["factors"]] == [
        ("severity", 1, 5),
        ("exposure", 0, 5),
        ("privilege", 0, 5),
        ("sensitivity", 0, 5),
        ("criticality", 0, 5),
        ("encryption", 0, 3),
    ]
    assert [(b["name"], b["minimum"], b["maximum"]) for b in model["bands"]] == [
        ("Critical", 22, 28),
        ("High", 16, 21),
        ("Medium", 9, 15),
        ("Low", 1, 8),
    ]


# --- the page ---------------------------------------------------------------------------


def test_the_committed_page_is_what_the_committed_records_render_to() -> None:
    """Catches the page being left behind when a record is regenerated, or edited by hand."""
    assert build.OUTPUT.read_text(encoding="utf-8") == build.render(_figures())


def test_the_page_loads_nothing_from_anywhere_else() -> None:
    """It is opened from disk, possibly offline, and holds unpublished results: no script,
    no stylesheet or font from a network, no link out."""
    page = build.render(_figures()).lower()

    assert "http://" not in page and "https://" not in page
    assert "<script" not in page and "<link" not in page and "@import" not in page


def test_every_figure_shown_as_a_headline_is_on_the_page() -> None:
    """Catches a figure computed and never rendered, or rendered from a stale literal."""
    page = build.render(_figures())

    for shown in ("8 of 10", "19 of 21", "2 of 5", "1,016", "63.8%", "81.8%", "986", "246"):
        assert shown in page, shown


def test_the_corpus_and_scanner_counts_are_the_measured_ones() -> None:
    figures = _figures()

    assert figures["scanners"] == {"checkov": 489, "trivy": 447, "tfsec": 119}
    assert figures["corpus"] == {"cases": 26, "hand_crafted": 5, "pairs": 10, "scenarios": 5}


def test_statements_the_page_makes_in_words_are_carried_as_figures() -> None:
    """Catches a sentence outliving the fact it states. Each of these is prose on the page:
    that every finding without a severity is Checkov's, that both failing pairs are ties on
    the encryption factor, and that without declarations no finding scores lower."""
    figures = _figures()

    assert figures["scanners_without_severity"] == {"checkov": 489}
    assert figures["pairs"]["failures"] == [("encryption", "tie")]
    assert figures["inference"]["scores"] == {"higher": 199, "same": 787, "lower": 0}
