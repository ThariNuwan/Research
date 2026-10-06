"""Layers 2-5 composed: normalized findings in, one ranked payload out.

Until this module existed the composition lived only in test helpers, and no path applied
S3a's Tier-1 collapse before scoring - although the S4 design spec (section 5.1) and
`scoring/rank.py` both state that ranking runs over the deduplicated set. `deduplicate`
reports groups and a count; it never returned what survives. `tier1_survivors` is that
missing step, and `prioritize` is the one place the order of the layers is fixed.

**Two populations, and each block of the payload says which it is over.** S3b's and S4's
recorded figures were measured over every normalized finding (1,055 in corpus v0); the
ranking the spec describes is over what survives Tier 1 (1,016). `run` emits the ranked
payload over the survivors and repeats the distributions over all findings under
`before_dedupe`, so the earlier record stays reproducible from the artifact and neither
figure can be mistaken for the other.

**The representative of a collapsed group.** Tier-1 members agree on resource, class and
fingerprint, so they agree on every contextual factor; severity is the only addend that can
differ. The representative is a member whose severity the scanner supplied, in preference
to one that reports none; among those, the highest level; then scanner and rule id, for
determinism. Measured on corpus v0: of 35 groups, 34 are uniform in normalized severity,
and the one that is not (`aws_db_instance.default`, checkov with no severity beside tfsec
at 4) contributes 4 either way, because the rubric's `unknown_resolves_to` is 4. The rule
therefore changes no score in this corpus - it changes one severity *state*, from
unresolved to resolved.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from iacrisk.context import coverage
from iacrisk.context.extract import contextualize
from iacrisk.context.terraform import TerraformResource
from iacrisk.dedupe import DedupeGroup, DedupeResult, deduplicate
from iacrisk.finding import NormalizedFinding
from iacrisk.report import build_report
from iacrisk.scanners.base import AdapterResult
from iacrisk.scoring import emit, report
from iacrisk.scoring.engine import score_all
from iacrisk.scoring.rank import rank_all

__all__ = ["Survivor", "prioritize", "run", "tier1_survivors"]


@dataclass(frozen=True, slots=True)
class Survivor:
    """One logical finding: what is ranked, and every raw finding it stands for.

    `members` holds `finding` alone when nothing collapsed into it. PLAN Q8 keeps scanner
    provenance as metadata on a collapsed finding, and this is where it is carried.
    """

    finding: NormalizedFinding
    members: tuple[NormalizedFinding, ...]


def _representative(members: Sequence[NormalizedFinding]) -> NormalizedFinding:
    """The member a Tier-1 group is scored as - see the module docstring for the rule."""
    known = [m for m in members if isinstance(m.severity_level, int)]

    def order(member: NormalizedFinding) -> tuple[int, str, str]:
        level = member.severity_level if isinstance(member.severity_level, int) else 0
        return (-level, member.scanner, member.rule_id)

    return min(known or members, key=order)


def tier1_survivors(findings: Sequence[NormalizedFinding], dedupe: DedupeResult) -> list[Survivor]:
    """`findings` with each Tier-1 group reduced to its representative, input order kept.

    `dedupe` must be `deduplicate` run over these same objects: membership is by object
    identity, not equality, because two value-equal findings are still two rows a scanner
    reported and only the ones a group actually holds may collapse. A group is emitted at
    the position of its first member.

    Tier-2 candidates are not touched. They are surfaced, never merged (spec S3a section 7),
    so each of their findings survives as its own row.
    """
    group_of: dict[int, DedupeGroup] = {
        id(member): group for group in dedupe.groups for member in group.findings
    }
    emitted: set[int] = set()
    survivors: list[Survivor] = []
    for finding in findings:
        group = group_of.get(id(finding))
        if group is None:
            survivors.append(Survivor(finding=finding, members=(finding,)))
        elif id(group) not in emitted:
            emitted.add(id(group))
            survivors.append(
                Survivor(finding=_representative(group.findings), members=group.findings)
            )
    return survivors


def prioritize(
    findings: Sequence[NormalizedFinding],
    declared: Mapping[str, Mapping[str, int]],
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    collapse: bool = True,
) -> dict[str, Any]:
    """Tier-1 collapse, context, score, rank and emit for one set of findings.

    `collapse=False` scores every finding as its own row. It exists so the figures S3b and
    S4 recorded before any path applied the collapse stay reproducible; the ranking a
    practitioner is handed is the default.

    Each emitted finding gains `flagged_by`, the scanner and rule of every raw finding it
    stands for - one entry unless it is a Tier-1 representative.
    """
    dedupe = deduplicate(findings)
    survivors = (
        tier1_survivors(findings, dedupe)
        if collapse
        else [Survivor(finding=f, members=(f,)) for f in findings]
    )
    contextualized = contextualize([s.finding for s in survivors], declared, tf_index, k8s_index)
    scored = score_all(contextualized)
    ranked = rank_all(scored)
    payload = emit.to_json(ranked, report.build(scored))

    members = {id(s.finding): s.members for s in survivors}
    for entry, item in zip(payload["findings"], ranked, strict=True):
        entry["flagged_by"] = [
            {"scanner": m.scanner, "rule_id": m.rule_id} for m in members[id(item.scored.finding)]
        ]

    return {
        "population": {
            "findings_in": len(findings),
            "tier1_collapsed": dedupe.collapsed_count if collapse else 0,
            "ranked": len(survivors),
        },
        "context_coverage": coverage.to_json(coverage.build(contextualized)),
        **payload,
    }


def run(
    results: Mapping[tuple[str, str], AdapterResult],
    declared: Mapping[str, Mapping[str, int]],
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None,
    unparseable: frozenset[str],
) -> dict[str, Any]:
    """Every adapter run for one corpus, through to the payload S5's harness reads.

    `retention` is S3a's coverage report, which also carries both deduplication tiers.
    `before_dedupe` repeats the distributions over every finding, without the per-finding
    list - the population S3b's and S4's handoff figures were measured on.
    """
    findings = [finding for result in results.values() for finding in result.findings]
    ranked = prioritize(findings, declared, tf_index, k8s_index)
    uncollapsed = prioritize(findings, declared, tf_index, k8s_index, collapse=False)
    return {
        "retention": build_report(results, deduplicate(findings), unparseable).to_json(),
        **ranked,
        "before_dedupe": {
            "population": uncollapsed["population"],
            "context_coverage": uncollapsed["context_coverage"],
            "report": uncollapsed["report"],
        },
    }
