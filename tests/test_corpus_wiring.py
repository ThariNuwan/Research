"""Pins the five-run corpus wiring `_corpus.py` centralizes (whole-branch review, Finding 4).

Without this, `_corpus.real_results()` could grow a sixth run, or lose one, and
nothing would notice - which was exactly the hazard the three consuming
modules (`test_dedupe.py`, `test_report.py`, `test_s3a_gates.py`) shared
before this branch's review: each specified the same five `(adapter, fixture,
scan-root, index)` tuples independently, with no test enforcing that they
stayed identical. This is that test, aimed at the one shared copy of the
wiring rather than at any one of its three importers.
"""

from __future__ import annotations

from _corpus import RUN_KEYS, real_results


def test_pinned_run_set() -> None:
    """`real_results()` produces exactly the five `(scanner, platform)` keys
    `RUN_KEYS` names - no more, no fewer - so widening or narrowing either one
    without the other is a failing test, not a silent divergence. Corpus v0's
    headline numbers (1055 findings / 39 Tier-1 collapsed / 207 Tier-2
    candidates) are measured over exactly this run set; a sixth run changes
    what every one of them means.
    """
    assert set(real_results()) == set(RUN_KEYS)
    assert len(RUN_KEYS) == 5
