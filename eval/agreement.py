"""Auto-inference agreement: the second half of ranking consistency (PLAN Q7).

    uv run python -m eval.agreement      # artifacts/auto-inference-agreement-v1.json

Compares two runs of the same findings through the same pipeline. In one, Resource
Sensitivity and Environment Criticality came from corpus v1's declared context; in the
other, from the registered conventions (`src/iacrisk/data/inference_conventions.json`).
Like the rest of `eval/`, it reads the scored JSON and imports nothing of the framework.

**The rules below were committed with the conventions, before any inferred run existed.**

1. **The declared run is the reference, not the truth.** Corpus v1's declared values were
   authored for this evaluation, several of them to build contrastive pairs. Agreement
   with them measures how close the conventions come to one author's declarations. It does
   not measure whether either is right about a real estate.
2. **Level agreement is measured only where there is one declared value to agree with.**
   A resource that corpus v1's cases declare differently - the declared-factor pairs do
   this on purpose - has no single reference, so it is excluded and counted. A factor a
   case deliberately leaves undeclared is excluded for the same reason.
3. **The all-default strawman is reported beside every agreement figure.** A convention
   that fires on nothing produces exactly the rubric's defaults. Reporting agreement
   without that comparison would credit the conventions with what the defaults achieve
   unaided.
4. **Under-estimates are counted apart from over-estimates.** An inferred value below the
   declared one lowers a finding's priority on a heuristic; that is the direction PLAN Q9
   is written to prevent.
5. **Coverage is reported before agreement.** How many findings and resources took any
   inferred value at all bounds what every later figure can mean.
6. **A pair on one resource is not applicable in this mode.** The conventions give a
   resource one value, so two cases that differ only in what they declare about the same
   resource are scored identically by construction. They are reported as not applicable,
   never as failures.
7. **Pairs and scenarios are graded by `eval.harness`'s own rules**, in both modes, so the
   only thing that differs between the two columns is where the two factors came from.
"""

from __future__ import annotations

import json
import platform
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval import harness
from eval.ground_truth import load_and_validate
from eval.sensitivity import kendall_tau_b_grouped
from tools.harvest.provenance import _git_commit, hash_file, worktree_clean

__all__ = [
    "INFERRED_FACTORS",
    "agreement",
    "coverage",
    "level_agreement",
    "oracle",
    "pair_findings",
    "ranking_agreement",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"
PLAN = REPO_ROOT / "eval" / "sensitivity_plan.json"
DECLARED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0.json"
DECLARED_CASES = REPO_ROOT / "artifacts" / "scored-cases-v1.json"
INFERRED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0-inferred.json"
INFERRED_CASES = REPO_ROOT / "artifacts" / "scored-cases-v1-inferred.json"
OUTPUT = REPO_ROOT / "artifacts" / "auto-inference-agreement-v1.json"

INPUTS = (GROUND_TRUTH, PLAN, DECLARED_CORPUS, DECLARED_CASES, INFERRED_CORPUS, INFERRED_CASES)

INFERRED_FACTORS = ("sensitivity", "criticality")
"""The two factors the mode replaces. Every other contribution is identical in both runs."""


def _counts(finding: Mapping[str, Any]) -> bool:
    return not finding["unmapped"] and not finding["baseline_only_informational"]


# --- pairing the two runs -------------------------------------------------------------


def _key(finding: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        finding["resource_identity"],
        finding["issue_class"],
        finding["scanner"],
        finding["rule_id"],
        finding["file_path"],
        json.dumps(finding["flagged_by"], sort_keys=True),
    )


def pair_findings(
    declared: Sequence[Mapping[str, Any]], inferred: Sequence[Mapping[str, Any]]
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Each declared-run finding with the same finding in the inferred run.

    The scored JSON carries no finding id, so findings are matched on what identifies
    them: resource, class, scanner, rule, file and the raw findings they stand for. Where
    several share all of that - one rule firing more than once on a resource - they are
    interchangeable for this purpose and are matched in score order. The two runs must
    hold exactly the same findings; anything else means they were not the same corpus,
    and that raises.
    """
    groups: dict[tuple[str, ...], list[Mapping[str, Any]]] = {}
    for finding in inferred:
        groups.setdefault(_key(finding), []).append(finding)
    for members in groups.values():
        members.sort(key=lambda f: f["score"])

    pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for finding in sorted(declared, key=lambda f: f["score"]):
        candidates = groups.get(_key(finding))
        if not candidates:
            raise ValueError(
                f"the inferred run has no finding matching {finding['resource_identity']} / "
                f"{finding['issue_class']} ({finding['scanner']} {finding['rule_id']})"
            )
        pairs.append((finding, candidates.pop(0)))
    left = sum(len(members) for members in groups.values())
    if left:
        raise ValueError(f"the inferred run holds {left} finding(s) the declared run does not")
    return pairs


# --- coverage -------------------------------------------------------------------------


def coverage(inferred_corpus: Mapping[str, Any]) -> dict[str, Any]:
    """How much of the corpus the conventions resolved anything for (rule 5).

    In an inferred run a `resolved` sensitivity or criticality is one a convention
    supplied; everything else took the default. Counted over the findings the framework
    makes a quality claim about, and over the distinct resources those findings sit on.
    """
    findings = [f for f in inferred_corpus["findings"] if _counts(f)]
    resources = {f["resource_identity"] for f in findings}
    sources: Counter[str] = Counter()
    for entry in inferred_corpus["inference"]["values"].values():
        for factor, value in entry.items():
            sources[f"{factor}:{value['source']}"] += 1
    return {
        "findings": len(findings),
        "resources": len(resources),
        "findings_inferred": {
            factor: sum(1 for f in findings if f["factor_states"][factor] == "resolved")
            for factor in INFERRED_FACTORS
        },
        "resources_inferred": {
            factor: len(
                {
                    f["resource_identity"]
                    for f in findings
                    if f["factor_states"][factor] == "resolved"
                }
            )
            for factor in INFERRED_FACTORS
        },
        "indexed_resources_with_any_inferred_value": len(inferred_corpus["inference"]["values"]),
        "inferred_values_by_factor_and_source": dict(sorted(sources.items())),
    }


# --- level agreement ------------------------------------------------------------------


def _tally(rows: Sequence[Mapping[str, Any]], field: str) -> dict[str, Any]:
    differences = [row[field] - row["declared"] for row in rows]
    count = len(differences)
    return {
        "exact": sum(1 for d in differences if d == 0),
        "under": sum(1 for d in differences if d < 0),
        "over": sum(1 for d in differences if d > 0),
        "mean_absolute_difference": sum(abs(d) for d in differences) / count if count else None,
    }


def level_agreement(
    ground_truth: Mapping[str, Any],
    inferred_cases: Mapping[str, Any],
    defaults: Mapping[str, int],
) -> dict[str, Any]:
    """Inferred level against declared level, where one declared level exists (rules 2-4).

    The inferred level is read from the inferred run's own findings on the resource, so it
    is what the pipeline scored, not a recomputation. `default` is the all-default
    strawman: the level every resource would take if no convention fired.
    """
    declarations: dict[str, set[tuple[Any, Any]]] = {}
    holder: dict[str, str] = {}
    for case in ground_truth["cases"]:
        for identity, values in case["declared_context"].items():
            declarations.setdefault(identity, set()).add(
                (values["sensitivity"], values["criticality"])
            )
            holder.setdefault(identity, case["case_id"])

    conflicting = sorted(identity for identity, seen in declarations.items() if len(seen) > 1)
    rows: dict[str, list[dict[str, Any]]] = {factor: [] for factor in INFERRED_FACTORS}
    undeclared: dict[str, int] = dict.fromkeys(INFERRED_FACTORS, 0)
    for identity, seen in sorted(declarations.items()):
        if len(seen) != 1:
            continue
        (declared,) = seen
        findings = [
            f
            for f in inferred_cases["cases"][holder[identity]]["findings"]
            if f["resource_identity"] == identity and _counts(f)
        ]
        if not findings:
            raise ValueError(f"the inferred run has no countable finding on {identity}")
        finding = findings[0]
        for factor, declared_level in zip(INFERRED_FACTORS, declared, strict=True):
            if declared_level is None:
                undeclared[factor] += 1
                continue
            rows[factor].append(
                {
                    "resource_identity": identity,
                    "declared": declared_level,
                    "inferred": finding["contributions"][factor],
                    "inferred_from_a_convention": finding["factor_states"][factor] == "resolved",
                    "default": defaults[factor],
                }
            )

    return {
        "declared_resources": len(declarations),
        "excluded_as_conflicting": conflicting,
        "by_factor": {
            factor: {
                "resources": len(rows[factor]),
                "excluded_as_undeclared": undeclared[factor],
                "resolved_by_a_convention": sum(
                    1 for row in rows[factor] if row["inferred_from_a_convention"]
                ),
                "inferred": _tally(rows[factor], "inferred"),
                "all_default": _tally(rows[factor], "default"),
                "rows": rows[factor],
            }
            for factor in INFERRED_FACTORS
        },
    }


# --- ranking agreement ----------------------------------------------------------------


def _rank_tally(pairs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> dict[str, Any]:
    count = len(pairs)
    return {
        "findings": count,
        "kendall_tau_b": kendall_tau_b_grouped((d["score"], i["score"]) for d, i in pairs),
        "same_score": sum(1 for d, i in pairs if d["score"] == i["score"]),
        "same_band": sum(1 for d, i in pairs if d["band"] == i["band"]),
        "inferred_higher": sum(1 for d, i in pairs if i["score"] > d["score"]),
        "inferred_lower": sum(1 for d, i in pairs if i["score"] < d["score"]),
        "mean_absolute_score_difference": (
            sum(abs(d["score"] - i["score"]) for d, i in pairs) / count if count else None
        ),
    }


def ranking_agreement(
    declared_corpus: Mapping[str, Any], inferred_corpus: Mapping[str, Any]
) -> dict[str, Any]:
    """How closely the inferred ranking follows the declared one, finding by finding.

    Two populations, because one would hide the other. Most findings sit on resources
    corpus v1 never declares; both runs give those the defaults and they agree trivially.
    `on_declared_resources` is the part where the two modes could differ at all.
    """
    pairs = [
        (d, i)
        for d, i in pair_findings(declared_corpus["findings"], inferred_corpus["findings"])
        if _counts(d)
    ]
    declared_only = [
        (d, i)
        for d, i in pairs
        if any(d["factor_states"][factor] == "resolved" for factor in INFERRED_FACTORS)
    ]
    return {
        "all_quality_claim_findings": _rank_tally(pairs),
        "on_declared_resources": _rank_tally(declared_only),
    }


# --- the oracle in both modes ---------------------------------------------------------


def _grade(
    ground_truth: Mapping[str, Any],
    scored_cases: Mapping[str, Any],
    applicable: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    rule = harness.PRIMARY_RULE
    cases = {
        case["case_id"]: harness.case_score(case, scored_cases["cases"][case["case_id"]])
        for case in ground_truth["cases"]
    }
    pairs = [harness.evaluate_pair(pair, cases) for pair in applicable]
    scenarios = [harness.evaluate_scenario(s, cases) for s in ground_truth["scenarios"]]
    headline = harness._summarise_scenarios(scenarios)["headline"]["framework"][rule]
    return {
        "pairs_passed": sum(1 for p in pairs if p["framework"][rule]["passes"]),
        "pairs_failed": [p["pair_id"] for p in pairs if not p["framework"][rule]["passes"]],
        "scenarios_exact": headline["exact_tier_matches"],
        "ordered_pairs_concordant": headline["ordered_pairs_concordant"],
        "ordered_pairs_tied": headline["ordered_pairs_tied"],
        "ordered_pairs_discordant": headline["ordered_pairs_discordant"],
        "by_scenario": {
            s["scenario_id"]: {
                "exact_tier_match": s["framework"][rule]["exact_tier_match"],
                "kendall_tau_b": s["framework"][rule]["kendall_tau_b"],
                "ordering": s["framework"][rule]["ordering"],
            }
            for s in scenarios
            if s["evaluable"]
        },
    }


def oracle(
    ground_truth: Mapping[str, Any],
    declared_cases: Mapping[str, Any],
    inferred_cases: Mapping[str, Any],
) -> dict[str, Any]:
    """The pairs and scenarios, graded the same way in both modes (rules 6 and 7)."""
    by_id = {case["case_id"]: case for case in ground_truth["cases"]}

    def one_resource(pair: Mapping[str, Any]) -> bool:
        return set(by_id[pair["case_high"]]["declared_context"]) == set(
            by_id[pair["case_low"]]["declared_context"]
        )

    pairs = ground_truth["contrastive_pairs"]
    applicable = [pair for pair in pairs if not one_resource(pair)]
    return {
        "pairs_authored": len(pairs),
        "pairs_applicable": len(applicable),
        "pairs_not_applicable": [pair["pair_id"] for pair in pairs if one_resource(pair)],
        "scenarios": len(ground_truth["scenarios"]),
        "declared": _grade(ground_truth, declared_cases, applicable),
        "inferred": _grade(ground_truth, inferred_cases, applicable),
    }


# --- everything -----------------------------------------------------------------------


def agreement(
    ground_truth: Mapping[str, Any],
    defaults: Mapping[str, int],
    declared_corpus: Mapping[str, Any],
    declared_cases: Mapping[str, Any],
    inferred_corpus: Mapping[str, Any],
    inferred_cases: Mapping[str, Any],
) -> dict[str, Any]:
    for name, document in (("corpus", inferred_corpus), ("cases", inferred_cases)):
        if document.get("context_mode") != "auto-inference":
            raise ValueError(f"the inferred {name} document is not marked auto-inference")
    return {
        "coverage": coverage(inferred_corpus),
        "level_agreement": level_agreement(ground_truth, inferred_cases, defaults),
        "ranking_agreement": ranking_agreement(declared_corpus, inferred_corpus),
        "oracle": oracle(ground_truth, declared_cases, inferred_cases),
    }


def _load(path: Path) -> Any:
    return json.loads(path.read_bytes())


def agreement_document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "description": (
            "Auto-inference agreement: the declared-context run against the run whose "
            "sensitivity and criticality were read from the registered conventions."
        ),
        "provenance": {
            "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": platform.python_version(),
            "repo_commit": _git_commit(REPO_ROOT),
            "source_clean": worktree_clean(REPO_ROOT, ignoring=("artifacts",)),
            "inputs": {path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in INPUTS},
        },
        **agreement(
            load_and_validate(GROUND_TRUTH),
            _load(PLAN)["frozen"]["unresolved_defaults"],
            _load(DECLARED_CORPUS),
            _load(DECLARED_CASES),
            _load(INFERRED_CORPUS),
            _load(INFERRED_CASES),
        ),
    }


def main(argv: list[str] | None = None) -> int:
    document = agreement_document()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    covered = document["coverage"]
    ranking = document["ranking_agreement"]["all_quality_claim_findings"]
    print(
        f"findings={covered['findings']} inferred_sensitivity="
        f"{covered['findings_inferred']['sensitivity']} inferred_criticality="
        f"{covered['findings_inferred']['criticality']} same_band={ranking['same_band']} "
        f"tau_b={ranking['kendall_tau_b']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
