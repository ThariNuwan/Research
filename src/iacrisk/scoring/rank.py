"""Ranking, with ties preserved as ties.

Spec §5. Equal scores share a rank, competition-style: after three findings at rank 1 the
next is rank 4. `corpus-v1`'s containers scenario contains a **deliberate tie**, so breaking
ties into distinct ranks would make the framework appear to discriminate where it does not -
and S5's scenario-ordering metric compares against an expected ordering that can express a
tie.

The sub-order *within* a tie is canonical resource identity, then issue class, then scanner.
It is **presentational only**: it exists so output is reproducible across runs, and it never
changes a rank number.

Ranking runs over the **deduplicated** set. S3a's Tier-1 collapse happens first; Tier-2
candidates are not collapsed, so a Tier-2 pair appears here as two ranked findings. That is
correct, and it is why PLAN Q7 reports deduplication and band reduction as two numbers that
are never combined.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from iacrisk.scoring.engine import ScoredFinding

__all__ = ["RankedFinding", "rank_all"]


@dataclass(frozen=True, slots=True)
class RankedFinding:
    scored: ScoredFinding
    rank: int


def _sort_key(scored: ScoredFinding) -> tuple[int, str, str, str]:
    finding = scored.finding
    return (
        -scored.score,
        finding.resource_identity,
        finding.issue_class,
        finding.scanner,
    )


def rank_all(scored: Iterable[ScoredFinding]) -> list[RankedFinding]:
    """Rank by descending score, assigning equal ranks to equal scores."""
    ordered = sorted(scored, key=_sort_key)
    ranked: list[RankedFinding] = []
    previous_score: int | None = None
    current_rank = 0
    for position, item in enumerate(ordered, start=1):
        if item.score != previous_score:
            current_rank = position
            previous_score = item.score
        ranked.append(RankedFinding(scored=item, rank=current_rank))
    return ranked
