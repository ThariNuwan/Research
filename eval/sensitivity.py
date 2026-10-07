"""The PLAN Q10 sensitivity analysis: the registered variants, recomputed from scored JSON.

    uv run python -m eval.sensitivity      # artifacts/sensitivity-v1.json

**A reported experiment, not a search.** `eval/sensitivity_plan.json` lists every variant,
was approved by the project author and committed before any of them was computed, and this
module computes all of them and filters none. Nothing here chooses a variant, names one
best, or feeds a value back into the frozen model.

**Why it runs from JSON instead of rescoring.** Every scored finding carries its six
contributions and, per factor, whether that contribution was `resolved` from evidence or
taken from a default. That is enough to recompute a score under a different default, weight
or band boundary without the framework and without editing the frozen rubric. What it risks
is the analysed model drifting from the scored one, so `check_identity` runs first: at the
frozen settings the recomputation must reproduce every committed score, band and
low-confidence flag, or nothing is computed.

**What a variant can and cannot say.**

- A changed *default* or *weight* changes scores, so pairs, scenarios and rank agreement can
  all move.
- A changed *band boundary* or *low-confidence threshold* changes no score. Those variants
  can only move band counts and the clean subsets, and the ordering metrics beside them are
  the frozen ones by construction.
- A *weighted* variant reports no bands. The bands are positioned against the 1-28 ceiling;
  a weighted sum has another, and rescaling the boundaries to it would define a new model.

Pairs and scenarios are graded by `eval.harness`'s own functions on the rescored findings,
so the registered rules - a case ranks at its highest finding, a tie fails - apply to every
variant exactly as they do to the frozen model.
"""

from __future__ import annotations

import json
import math
import platform
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval import harness
from eval.ground_truth import load_and_validate
from tools.harvest.provenance import _git_commit, hash_file, worktree_clean

__all__ = [
    "Variant",
    "analyse",
    "check_identity",
    "kendall_tau_b_grouped",
    "rescore",
    "variants",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
PLAN = REPO_ROOT / "eval" / "sensitivity_plan.json"
GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"
SCORED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0.json"
SCORED_CASES = REPO_ROOT / "artifacts" / "scored-cases-v1.json"
OUTPUT = REPO_ROOT / "artifacts" / "sensitivity-v1.json"

INPUTS = (PLAN, GROUND_TRUTH, SCORED_CORPUS, SCORED_CASES)

_BAND_ORDER = ("Critical", "High", "Medium")
"""Checked highest first; a score below every minimum is Low."""


@dataclass(frozen=True)
class Variant:
    """One setting of the four things the plan moves. `change` is what differs from frozen."""

    id: str
    experiment: str
    defaults: Mapping[str, int]
    weights: Mapping[str, int]
    band_minimums: Mapping[str, int]
    low_confidence_threshold: int
    change: Mapping[str, Any]

    @property
    def weighted(self) -> bool:
        return any(weight != 1 for weight in self.weights.values())


def _frozen(plan: Mapping[str, Any]) -> Variant:
    frozen = plan["frozen"]
    return Variant(
        id="frozen",
        experiment="frozen",
        defaults=dict(frozen["unresolved_defaults"]),
        weights=dict(frozen["weights"]),
        band_minimums=dict(frozen["band_minimums"]),
        low_confidence_threshold=frozen["low_confidence_threshold"],
        change={},
    )


def variants(plan: Mapping[str, Any]) -> list[Variant]:
    """Every registered variant, in the plan's own order. The frozen setting is not one."""
    base = _frozen(plan)
    experiments = plan["experiments"]
    out: list[Variant] = []

    def variant(variant_id: str, experiment: str, change: Mapping[str, Any], **moved: Any) -> None:
        out.append(
            Variant(
                id=variant_id,
                experiment=experiment,
                defaults=moved.get("defaults", base.defaults),
                weights=moved.get("weights", base.weights),
                band_minimums=moved.get("band_minimums", base.band_minimums),
                low_confidence_threshold=moved.get(
                    "low_confidence_threshold", base.low_confidence_threshold
                ),
                change=change,
            )
        )

    defaults = experiments["unresolved_defaults"]
    for factor, values in defaults["one_at_a_time"].items():
        for value in values:
            if value == base.defaults[factor]:
                continue
            variant(
                f"default:{factor}={value}",
                "unresolved_defaults",
                {"factor": factor, "value": value},
                defaults={**base.defaults, factor: value},
            )
    for name, joint in defaults["joint"].items():
        variant(f"default:{name}", "unresolved_defaults", {"joint": name}, defaults=dict(joint))

    boundaries = experiments["band_boundaries"]
    if boundaries["each_alone"]:
        for band in boundaries["boundaries"]:
            for shift in boundaries["shifts"]:
                variant(
                    f"boundary:{band}{shift:+d}",
                    "band_boundaries",
                    {"boundary": band, "shift": shift},
                    band_minimums={**base.band_minimums, band: base.band_minimums[band] + shift},
                )
    if boundaries["all_together"]:
        for shift in boundaries["shifts"]:
            variant(
                f"boundary:all{shift:+d}",
                "band_boundaries",
                {"boundary": "all", "shift": shift},
                band_minimums={
                    **base.band_minimums,
                    **{b: base.band_minimums[b] + shift for b in boundaries["boundaries"]},
                },
            )

    weights = experiments["weights"]
    for factor in weights["drop_one"]:
        variant(
            f"weight:drop-{factor}",
            "weights",
            {"drop": factor},
            weights={**base.weights, factor: 0},
        )
    for factor in weights["double_one"]:
        variant(
            f"weight:double-{factor}",
            "weights",
            {"double": factor},
            weights={**base.weights, factor: 2},
        )
    for name, entry in weights["named"].items():
        variant(
            f"weight:{name}",
            "weights",
            {"named": name},
            weights={**base.weights, **entry["weights"]},
        )

    for value in experiments["low_confidence_threshold"]["values"]:
        variant(
            f"low-confidence:{value}",
            "low_confidence_threshold",
            {"threshold": value},
            low_confidence_threshold=value,
        )
    return out


# --- one finding ----------------------------------------------------------------------


def _band(score: int, minimums: Mapping[str, int]) -> str:
    for band in _BAND_ORDER:
        if score >= minimums[band]:
            return band
    return "Low"


def rescore(finding: Mapping[str, Any], variant: Variant) -> dict[str, Any]:
    """`finding` as the variant would have scored it.

    A contribution whose factor state is `resolved` keeps its level: evidence does not move
    when a default does. Any other state - `unresolved` or `defaulted` - takes the variant's
    default for that factor. Each level is then multiplied by the variant's weight.

    Low-confidence is recounted over the contextual factors present, so a finding with no
    context block (`baseline_only_informational`) is never low-confidence, as upstream.
    """
    states: Mapping[str, str] = finding["factor_states"]
    contributions: dict[str, int] = {}
    for factor, committed in finding["contributions"].items():
        level = committed if states[factor] == "resolved" else variant.defaults[factor]
        contributions[factor] = level * variant.weights[factor]
    score = sum(contributions.values())

    missing = sum(
        1 for factor in harness.CONTEXT_FACTORS if states.get(factor, "resolved") != "resolved"
    )
    return {
        **finding,
        "contributions": contributions,
        "score": score,
        "band": None if variant.weighted else _band(score, variant.band_minimums),
        "low_confidence": missing >= variant.low_confidence_threshold,
    }


def check_identity(findings: Iterable[Mapping[str, Any]], frozen: Variant) -> int:
    """Recompute every finding at the frozen settings and require the committed values back.

    Returns how many were checked. Raises on the first that differs, naming it: a mismatch
    means this module's model of the scoring is not the scoring, and every variant computed
    from it would be a statement about something else.

    `contributions` is compared as well as the total. A total can survive two wrong
    addends that cancel - an unresolved exposure committed at 4 beside an unresolved
    encryption committed at 1 sums as 3 and 2 do - and a variant then substitutes defaults
    for values that were never the defaults. `tests/test_s6_gates.py` adds the other half:
    every score-moving variant is recomputed by the framework's own engine and compared.
    """
    checked = 0
    for finding in findings:
        again = rescore(finding, frozen)
        for field in ("contributions", "score", "band", "low_confidence"):
            if again[field] != finding[field]:
                raise ValueError(
                    f"the frozen settings do not reproduce the committed {field} for "
                    f"{finding['resource_identity']} / {finding['issue_class']} "
                    f"({finding['scanner']} {finding['rule_id']}): committed "
                    f"{finding[field]!r}, recomputed {again[field]!r}"
                )
        checked += 1
    return checked


# --- rank agreement -------------------------------------------------------------------


def kendall_tau_b_grouped(pairs: Iterable[tuple[int, int]]) -> float | None:
    """Kendall's tau-b over `(x, y)` observations, counted by distinct value pair.

    The same statistic as `harness.kendall_tau_b`, which compares every pair of
    observations. Scores are small integers and a corpus has about a thousand findings, so
    the observations fall into a few hundred distinct `(x, y)` cells; counting cell against
    cell is exact and avoids half a million comparisons per variant.
    """
    cells = Counter(pairs)
    total = sum(cells.values())
    if total < 2:
        return None

    def tied(counts: Iterable[int]) -> int:
        return sum(n * (n - 1) // 2 for n in counts)

    by_x: Counter[int] = Counter()
    by_y: Counter[int] = Counter()
    for (x, y), n in cells.items():
        by_x[x] += n
        by_y[y] += n

    difference = 0
    items = list(cells.items())
    for i, ((x1, y1), n1) in enumerate(items):
        for (x2, y2), n2 in items[i + 1 :]:
            dx = (x1 > x2) - (x1 < x2)
            dy = (y1 > y2) - (y1 < y2)
            difference += dx * dy * n1 * n2

    all_pairs = total * (total - 1) // 2
    denominator = math.sqrt((all_pairs - tied(by_x.values())) * (all_pairs - tied(by_y.values())))
    if denominator == 0:
        return None
    return difference / denominator


# --- one variant ----------------------------------------------------------------------


def _counts(finding: Mapping[str, Any]) -> bool:
    return not finding["unmapped"] and not finding["baseline_only_informational"]


def _corpus_result(
    committed: Sequence[Mapping[str, Any]], variant: Variant, frozen: Variant
) -> dict[str, Any]:
    """The variant over the context-eligible corpus findings.

    The plan calls these "the findings the framework makes a quality claim about". They are
    the mapped findings that carry a context block; low-confidence findings are among them.
    """
    then = [rescore(f, frozen) for f in committed]
    now = [rescore(f, variant) for f in committed]

    bands: dict[str, int] | None = None
    if not variant.weighted:
        bands = dict.fromkeys(harness.BANDS, 0)
        for finding in now:
            bands[finding["band"]] += 1
    return {
        "findings": len(now),
        "bands": bands,
        "critical_or_high": None if bands is None else bands["Critical"] + bands["High"],
        "band_changed": None
        if variant.weighted
        else sum(1 for a, b in zip(then, now, strict=True) if a["band"] != b["band"]),
        "score_changed": sum(1 for a, b in zip(then, now, strict=True) if a["score"] != b["score"]),
        "low_confidence": sum(1 for f in now if f["low_confidence"]),
        "rank_agreement_tau_b": kendall_tau_b_grouped(
            (a["score"], b["score"]) for a, b in zip(then, now, strict=True)
        ),
    }


def _oracle_result(
    ground_truth: Mapping[str, Any], entries: Mapping[str, Mapping[str, Any]], variant: Variant
) -> dict[str, Any]:
    """Pairs and scenarios regraded by the harness's own rules on the rescored findings."""
    cases = {
        case["case_id"]: harness.case_score(
            case,
            {"findings": [rescore(f, variant) for f in entries[case["case_id"]]["findings"]]},
        )
        for case in ground_truth["cases"]
    }
    pairs = [harness.evaluate_pair(pair, cases) for pair in ground_truth["contrastive_pairs"]]
    scenarios = [harness.evaluate_scenario(s, cases) for s in ground_truth["scenarios"]]
    pair_summary = harness._summarise_pairs(pairs)
    scenario_summary = harness._summarise_scenarios(scenarios)
    rule = harness.PRIMARY_RULE

    def scenario_tally(block: Mapping[str, Any]) -> dict[str, Any]:
        graded = block["framework"][rule]
        return {
            "scenarios": block["scenarios"],
            "exact_tier_matches": graded["exact_tier_matches"],
            "ordered_pairs_concordant": graded["ordered_pairs_concordant"],
            "ordered_pairs_tied": graded["ordered_pairs_tied"],
            "ordered_pairs_discordant": graded["ordered_pairs_discordant"],
        }

    return {
        "pairs": {
            "evaluable": pair_summary["authored"]["evaluable"],
            "passes": pair_summary["authored"]["framework_passes"][rule],
            "failed": [
                p["pair_id"] for p in pairs if p["evaluable"] and not p["framework"][rule]["passes"]
            ],
            "isolated": pair_summary["authored"]["isolated"],
            "clean_pairs": pair_summary["clean"]["pairs"],
            "clean_passes": pair_summary["clean"]["framework_passes"][rule],
        },
        "scenarios": {
            "headline": scenario_tally(scenario_summary["headline"]),
            "clean": scenario_tally(scenario_summary["clean"]),
            "by_scenario": {
                s["scenario_id"]: {
                    "exact_tier_match": s["framework"][rule]["exact_tier_match"],
                    "kendall_tau_b": s["framework"][rule]["kendall_tau_b"],
                    "ordering": s["framework"][rule]["ordering"],
                }
                for s in scenarios
                if s["evaluable"]
            },
        },
    }


def _result(
    variant: Variant,
    frozen: Variant,
    ground_truth: Mapping[str, Any],
    corpus_findings: Sequence[Mapping[str, Any]],
    entries: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "id": variant.id,
        "change": dict(variant.change),
        "weighted": variant.weighted,
        "corpus": _corpus_result(corpus_findings, variant, frozen),
        **_oracle_result(ground_truth, entries, variant),
    }


# --- everything -----------------------------------------------------------------------


def analyse(
    plan: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    corpus: Mapping[str, Any],
    scored_cases: Mapping[str, Any],
) -> dict[str, Any]:
    """Every registered variant, after the identity check has passed on both documents."""
    frozen = _frozen(plan)
    entries: Mapping[str, Mapping[str, Any]] = scored_cases["cases"]
    case_findings = [f for entry in entries.values() for f in entry["findings"]]
    checked = check_identity(corpus["findings"], frozen) + check_identity(case_findings, frozen)

    quality = [f for f in corpus["findings"] if _counts(f)]
    experiments: dict[str, list[dict[str, Any]]] = {name: [] for name in plan["experiments"]}
    for variant in variants(plan):
        experiments[variant.experiment].append(
            _result(variant, frozen, ground_truth, quality, entries)
        )
    return {
        "identity": {"findings_checked": checked, "reproduces_committed_values": True},
        "variants_registered": sum(len(results) for results in experiments.values()),
        "frozen": _result(frozen, frozen, ground_truth, quality, entries),
        "experiments": experiments,
    }


def _load(path: Path) -> Any:
    return json.loads(path.read_bytes())


def sensitivity_document() -> dict[str, Any]:
    plan = _load(PLAN)
    return {
        "schema_version": 1,
        "description": (
            "The registered Q10 sensitivity analysis: every variant in "
            "eval/sensitivity_plan.json, recomputed from the committed scored documents. "
            "A reported experiment; the frozen model is the result."
        ),
        "provenance": {
            "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": platform.python_version(),
            "repo_commit": _git_commit(REPO_ROOT),
            "source_clean": worktree_clean(REPO_ROOT, ignoring=("artifacts",)),
            "inputs": {path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in INPUTS},
        },
        "plan": plan,
        **analyse(plan, load_and_validate(GROUND_TRUTH), _load(SCORED_CORPUS), _load(SCORED_CASES)),
    }


def main(argv: list[str] | None = None) -> int:
    document = sensitivity_document()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(
        f"identity_checked={document['identity']['findings_checked']} "
        f"variants={document['variants_registered']} "
        + " ".join(f"{name}={len(results)}" for name, results in document["experiments"].items())
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
