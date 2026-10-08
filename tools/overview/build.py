"""The results overview page, generated from the committed records.

    uv run python -m tools.overview.build      # docs/results-overview.html

One self-contained HTML file: the headline results as charts and tables, each with the
qualification Chapter 6 attaches to it, and a sample of what the tool reports. It is for
reading - by the author, a supervisor, an examiner - and it is not evidence. The evidence
is the records it is generated from.

**Generated, not written, and that is the point.** `figures` reads every number from a
committed record; `render` turns those numbers into the page and holds no number of its
own. A figure cannot be mistyped here, and a regenerated record cannot leave the page
behind: `tests/overview/test_build.py` fails if the committed page is not what the
committed records render to, and holds the figures to the dissertation's own tables.

The page loads nothing from a network - no script, no remote stylesheet or font - so it
opens from disk and sends nothing anywhere.
"""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from itertools import combinations
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"
OUTPUT = REPO_ROOT / "docs" / "results-overview.html"
STYLE = Path(__file__).with_name("style.css")

RECORDS = {
    "ground_truth": REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json",
    "rubric": REPO_ROOT / "src" / "iacrisk" / "data" / "rubric.json",
    "corpus": ARTIFACTS / "scored-corpus-v0.json",
    "cases": ARTIFACTS / "scored-cases-v1.json",
    "evaluation": ARTIFACTS / "evaluation-v1.json",
    "sensitivity": ARTIFACTS / "sensitivity-v1.json",
    "agreement": ARTIFACTS / "auto-inference-agreement-v1.json",
    "inferred_corpus": ARTIFACTS / "scored-corpus-v0-inferred.json",
}

FACTORS = ("severity", "exposure", "privilege", "sensitivity", "criticality", "encryption")
CODE_DERIVED = ("exposure", "privilege", "encryption")
DECLARED = ("sensitivity", "criticality")
BANDS = ("Critical", "High", "Medium", "Low")
RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

Record = dict[str, Any]


def load() -> dict[str, Record]:
    return {name: json.loads(path.read_bytes()) for name, path in RECORDS.items()}


# --- the figures ------------------------------------------------------------------------


def _claimed(findings: list[Record]) -> list[Record]:
    """Findings the framework makes a claim about: mapped, with a context block."""
    return [f for f in findings if not f["unmapped"] and not f["baseline_only_informational"]]


def _top(findings: list[Record]) -> Record:
    """A case's highest-scoring claimed finding - the evaluation's registered case rule."""
    return max(_claimed(findings), key=lambda f: f["score"])


def _verdict(comparison: Record) -> str:
    if comparison["passes"]:
        return "pass"
    return "tie" if comparison["delta"] == 0 else "fail"


def _population(records: dict[str, Record]) -> Record:
    population = records["corpus"]["population"]
    bands = records["evaluation"]["alert_reduction"]["priority_band"]
    return {
        "reported": population["findings_in"],
        "no_severity": records["evaluation"]["retention"]["unknown_severity"],
        "duplicates": population["tier1_collapsed"],
        "ranked": population["ranked"],
        "context_eligible": bands["context_eligible"]["findings"],
        "not_low_confidence": bands["excluding_low_confidence"]["findings"],
    }


def _scanners(records: dict[str, Record]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for run, entry in records["corpus"]["retention"]["scanners"].items():
        counts[run.split("/")[0]] += entry["findings_in"]
    return dict(counts.most_common())


def _scanners_without_severity(records: dict[str, Record]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for run, entry in records["corpus"]["retention"]["scanners"].items():
        counts[run.split("/")[0]] += entry["unknown_severity"]
    return {name: count for name, count in counts.most_common() if count}


def _corpus(records: dict[str, Record]) -> dict[str, int]:
    truth = records["ground_truth"]
    return {
        "cases": len(truth["cases"]),
        "hand_crafted": sum(1 for case in truth["cases"] if case["source"] == "hand-crafted"),
        "pairs": len(truth["contrastive_pairs"]),
        "scenarios": len(truth["scenarios"]),
    }


def _pairs(records: dict[str, Record]) -> Record:
    cases = {case["case_id"]: case for case in records["ground_truth"]["cases"]}
    rows = []
    for pair in records["evaluation"]["contrastive_pairs"]["pairs"]:
        one_resource = set(cases[pair["case_high"]]["declared_context"]) == set(
            cases[pair["case_low"]]["declared_context"]
        )
        framework = pair["framework"]["max"]
        if one_resource:
            kind = "by construction"
        elif pair["hand_crafted"]:
            kind = "hand-crafted"
        else:
            kind = "mined"
        rows.append(
            {
                "pair_id": pair["pair_id"],
                "factor": pair["factor_under_test"],
                "kind": kind,
                "high": framework["high"],
                "low": framework["low"],
                "framework": _verdict(framework),
                "baseline": _verdict(pair["baseline"]),
            }
        )
    passed = [row for row in rows if row["framework"] == "pass"]
    mined = [row for row in rows if row["kind"] == "mined"]
    return {
        "total": len(rows),
        "framework": len(passed),
        "baseline": sum(1 for row in rows if row["baseline"] == "pass"),
        "by_construction": sum(1 for row in passed if row["kind"] == "by construction"),
        "hand_crafted_passed": sum(1 for row in passed if row["kind"] == "hand-crafted"),
        "mined_needing_extraction": {
            "passed": sum(1 for row in mined if row["framework"] == "pass"),
            "total": len(mined),
        },
        "mined_passes_also_pass_the_baseline": all(
            row["baseline"] == "pass" for row in mined if row["framework"] == "pass"
        ),
        "failed": [row["pair_id"] for row in rows if row["framework"] != "pass"],
        "failures": sorted(
            {(row["factor"], row["framework"]) for row in rows if row["framework"] != "pass"}
        ),
        "rows": rows,
    }


def _decided_by(records: dict[str, Record]) -> tuple[dict[str, Counter[str]], int]:
    """For each correctly ordered scenario case pair, what separated the two cases.

    `declared context alone`: the two top findings agree on severity and on every factor
    read from code, so only the declared sensitivity and criticality differ. Chapter 6
    section 6.4.3 gives the same breakdown. The second value counts the remaining pairs in
    which every code-derived factor that differs was read from evidence on both sides.
    """
    truth = records["ground_truth"]
    source = {case["case_id"]: case["source"] for case in truth["cases"]}
    tops = {
        case_id: _top(entry["findings"]) for case_id, entry in records["cases"]["cases"].items()
    }

    decided: dict[str, Counter[str]] = {}
    read_on_both_sides = 0
    for scenario in truth["scenarios"]:
        tier_of = {
            c: index for index, tier in enumerate(scenario["expected_ordering"]) for c in tier
        }
        tally = decided.setdefault(scenario["domain"], Counter())
        for first, second in combinations(sorted(tier_of), 2):
            if tier_of[first] == tier_of[second]:
                continue
            upper, lower = (first, second) if tier_of[first] < tier_of[second] else (second, first)
            high, low = tops[upper], tops[lower]
            if not high["score"] > low["score"]:
                continue
            differing = [
                key
                for key in CODE_DERIVED
                if high["contributions"][key] != low["contributions"][key]
            ]
            if "hand-crafted" in (source[upper], source[lower]):
                tally["hand-crafted cases"] += 1
            elif (
                not differing
                and high["contributions"]["severity"] == low["contributions"]["severity"]
            ):
                tally["declared context alone"] += 1
            else:
                tally["code or scanner evidence"] += 1
                read_on_both_sides += bool(differing) and all(
                    side["factor_states"][key] == "resolved"
                    for key in differing
                    for side in (high, low)
                )
    return decided, read_on_both_sides


def _ordered(block: Record) -> dict[str, int]:
    return {
        "right": block["ordered_pairs_concordant"],
        "tied": block["ordered_pairs_tied"],
        "inverted": block["ordered_pairs_discordant"],
    }


def _scenarios(records: dict[str, Record]) -> Record:
    evaluation = records["evaluation"]["scenarios"]
    headline = evaluation["summary"]["headline"]
    decided, read_on_both_sides = _decided_by(records)
    kinds = ("declared context alone", "hand-crafted cases", "code or scanner evidence")

    def counts(block: Record) -> dict[str, int]:
        pairs = block["ordered_pairs"]
        return {
            "right": pairs["concordant"],
            "tied": pairs["tied"],
            "inverted": pairs["discordant"],
        }

    rows = [
        {
            "domain": scenario["domain"],
            "reviewer_verdict": scenario["reviewer_verdict"],
            "exact": scenario["framework"]["max"]["exact_tier_match"],
            "framework": counts(scenario["framework"]["max"]),
            "baseline": counts(scenario["baseline"]),
            "decided_by": {kind: decided[scenario["domain"]].get(kind, 0) for kind in kinds},
        }
        for scenario in evaluation["scenarios"]
    ]
    return {
        "exact": {
            "framework": headline["framework"]["max"]["exact_tier_matches"],
            "baseline": headline["baseline"]["exact_tier_matches"],
            "total": headline["scenarios"],
        },
        "ordered": {
            "total": headline["framework"]["max"]["ordered_pairs_expected"],
            "framework": _ordered(headline["framework"]["max"]),
            "baseline": _ordered(headline["baseline"]),
        },
        "decided_by": {
            kind: sum(tally.get(kind, 0) for tally in decided.values()) for kind in kinds
        },
        "read_on_both_sides": read_on_both_sides,
        "rows": rows,
    }


def _band_minimum(records: dict[str, Record], name: str) -> int:
    return int(next(b["minimum"] for b in records["rubric"]["bands"] if b["name"] == name))


def _bands(records: dict[str, Record]) -> Record:
    priority = records["evaluation"]["alert_reduction"]["priority_band"]

    def block(source: Record) -> Record:
        return {
            "findings": source["findings"],
            "baseline": dict(source["baseline"]),
            "framework": dict(source["framework"]),
            "before": source["baseline_critical_or_high"],
            "after": source["framework_critical_or_high"],
            "reduction": f"{source['reduction_rate']:.1%}",
        }

    eligible = _claimed(records["corpus"]["findings"])
    high = _band_minimum(records, "High")
    return {
        "context_eligible": block(priority["context_eligible"]),
        "not_low_confidence": block(priority["excluding_low_confidence"]),
        "caveats": {
            "baseline_high_with_no_severity": priority["context_eligible"][
                "baseline_critical_or_high_from_unknown_severity"
            ],
            "low_confidence": sum(1 for f in eligible if f["low_confidence"]),
            "high_findings": priority["context_eligible"]["framework"]["High"],
            "high_on_the_boundary": sum(1 for f in eligible if f["score"] == high),
            "highest_score": max(f["score"] for f in eligible),
            "critical_boundary": _band_minimum(records, "Critical"),
        },
    }


def _sensitivity(records: dict[str, Record]) -> Record:
    record = records["sensitivity"]
    plan, frozen = record["plan"], record["frozen"]
    variants = {v["id"]: v for block in record["experiments"].values() for v in block}
    frozen_defaults = dict(plan["frozen"]["unresolved_defaults"])

    def critical_or_high(variant_id: str) -> int:
        return int(variants[variant_id]["corpus"]["critical_or_high"])

    high = plan["frozen"]["band_minimums"]["High"]
    boundary = {high: int(frozen["corpus"]["critical_or_high"])}
    for shift in plan["experiments"]["band_boundaries"]["shifts"]:
        boundary[high + shift] = critical_or_high(f"boundary:High{shift:+d}")

    defaults = {
        factor: {
            value: (
                int(frozen["corpus"]["critical_or_high"])
                if value == frozen_defaults[factor]
                else critical_or_high(f"default:{factor}={value}")
            )
            for value in values
        }
        for factor, values in plan["experiments"]["unresolved_defaults"]["one_at_a_time"].items()
    }
    pairs = frozen["pairs"]["passes"]
    exact = frozen["scenarios"]["headline"]["exact_tier_matches"]
    return {
        "variants": record["variants_registered"],
        "pairs_unchanged": sum(1 for v in variants.values() if v["pairs"]["passes"] == pairs),
        "pairs_changed": {
            v["id"]: v["pairs"]["passes"]
            for v in variants.values()
            if v["pairs"]["passes"] != pairs
        },
        "exact_matches_unchanged": sum(
            1
            for v in variants.values()
            if v["scenarios"]["headline"]["exact_tier_matches"] == exact
        ),
        "high_boundary": dict(sorted(boundary.items())),
        "defaults": defaults,
        "frozen_defaults": frozen_defaults,
        "all_defaults": {
            "minimum": critical_or_high("default:all_minimum"),
            "maximum": critical_or_high("default:all_maximum"),
        },
    }


def _inference(records: dict[str, Record]) -> Record:
    eligible = _claimed(records["inferred_corpus"]["findings"])
    took = [f for f in eligible if any(f["factor_states"][key] == "resolved" for key in DECLARED)]
    ranking = records["agreement"]["ranking_agreement"]["all_context_eligible_findings"]
    return {
        "resolved": {
            "resources": len({f["resource_identity"] for f in took}),
            "of_resources": records["agreement"]["coverage"]["resources"],
            "findings": len(took),
        },
        "ordered": _ordered(records["agreement"]["oracle"]["inferred"]),
        "scores": {
            "higher": ranking["inferred_higher"],
            "same": ranking["same_score"],
            "lower": ranking["inferred_lower"],
        },
        "high": {
            "declared": records["corpus"]["report"]["eligible_only"]["High"],
            "inferred": records["inferred_corpus"]["report"]["eligible_only"]["High"],
        },
    }


def _sample(records: dict[str, Record]) -> list[Record]:
    """The five hand-crafted resources, each at its highest-scoring claimed finding."""
    rows = []
    for case in records["ground_truth"]["cases"]:
        if case["source"] != "hand-crafted":
            continue
        findings = _claimed(records["cases"]["cases"][case["case_id"]]["findings"])
        top = _top(findings)
        (resource,) = case["declared_context"]
        rows.append(
            {
                "resource": resource,
                "score": top["score"],
                "band": top["band"],
                "baseline_band": max((f["baseline_band"] for f in findings), key=RANK.__getitem__),
                "contributions": dict(top["contributions"]),
                "defaults": [key for key in FACTORS if top["factor_states"][key] != "resolved"],
                "explanation": list(top["explanation"]),
                "issue_class": top["issue_class"],
                "findings": len(findings),
            }
        )
    return sorted(rows, key=lambda row: (-row["score"], row["resource"]))


def _model(records: dict[str, Record]) -> Record:
    rubric = records["rubric"]
    raw = rubric["factors"]
    by_key = raw if isinstance(raw, dict) else {factor["key"]: factor for factor in raw}
    return {
        "factors": [
            {
                "key": key,
                "minimum": by_key[key]["minimum"],
                "maximum": by_key[key]["maximum"],
                "default": by_key[key]["unresolved_default"],
            }
            for key in FACTORS
        ],
        "bands": [
            {
                "name": band["name"],
                "minimum": band["minimum"],
                "maximum": band["maximum"],
                "action": band["action"],
            }
            for band in rubric["bands"]
        ],
    }


def figures(records: dict[str, Record]) -> dict[str, Any]:
    """Every number the page shows, each read from a committed record."""
    return {
        "corpus": _corpus(records),
        "scanners": _scanners(records),
        "scanners_without_severity": _scanners_without_severity(records),
        "population": _population(records),
        "model": _model(records),
        "pairs": _pairs(records),
        "scenarios": _scenarios(records),
        "bands": _bands(records),
        "sensitivity": _sensitivity(records),
        "inference": _inference(records),
        "sample": _sample(records),
    }


# --- the page ---------------------------------------------------------------------------


DISPLAY = {"checkov": "Checkov", "trivy": "Trivy", "tfsec": "tfsec", "iam": "IAM"}
"""Names that are not their capitalized key."""


def _n(value: int) -> str:
    return f"{value:,}"


def _name(key: str) -> str:
    return DISPLAY.get(key, key.capitalize())


def _listed(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _share(label: str, note: str, value: int, total: int, kind: str) -> str:
    width = 100 * value / total if total else 0
    return (
        f'<div class="row"><div class="name">{label}<small>{note}</small></div>'
        f'<div class="track"><div class="fill {kind}" style="width:{width:.1f}%"></div>'
        f'<div class="rest num">{_n(value)} of {_n(total)}</div></div></div>'
    )


def _stack(label: str, note: str, counts: dict[str, int]) -> str:
    """One bar split by count. A segment too thin to hold its number shows none; the number
    is in the segment's tooltip and in the table that accompanies every such chart."""
    total = sum(counts.values())
    segments = "".join(
        f'<div class="seg {name.lower()}{"" if count else " empty"}" style="flex:{count} 1 0" '
        f'title="{name}: {count}">{_n(count) if count / total >= 0.035 else ""}</div>'
        for name, count in counts.items()
    )
    return (
        f'<div class="row"><div class="name">{label}<small>{note}</small></div>'
        f'<div class="bar">{segments}</div></div>'
    )


def _legend(*names: str) -> str:
    items = "".join(
        f'<span><i class="dot {name.split()[0].lower()}"></i>{name}</span>' for name in names
    )
    return f'<div class="legend">{items}</div>'


def _tag(verdict: str) -> str:
    return f'<span class="tag {verdict}">{verdict}</span>'


def _pill(band: str) -> str:
    return f'<span class="pill {band.lower()}">{band}</span>'


def _triple(counts: dict[str, int]) -> str:
    return f"{counts['right']} / {counts['tied']} / {counts['inverted']}"


def _header(f: dict[str, Any]) -> str:
    pairs, scenarios, population = f["pairs"], f["scenarios"], f["population"]
    ordered, exact = scenarios["ordered"], scenarios["exact"]
    return f"""
<header>
  <p class="step">Results overview</p>
  <h1>Risk-aware prioritization of IaC security misconfigurations</h1>
  <p class="lede">Rule-based scanners report many misconfigurations with a flat severity
  label. This framework sits on top of three of them and re-ranks what they find, using six
  inspectable factors about the affected resource. This page shows what the evaluation
  found, with the qualification that belongs to each result.</p>
  <p class="who">Jayathissa E.A.T.N. (258243J) &middot; MSc in Computer Science (Cloud
  Computing), University of Moratuwa</p>
  <div class="tiles">
    <div class="tile"><div class="big">{pairs["framework"]} of {pairs["total"]}</div>
      <div class="lbl">contrastive pairs ranked in the predicted direction</div>
      <div class="vs">scanner severity alone: {pairs["baseline"]} of {pairs["total"]}</div></div>
    <div class="tile"><div class="big">{ordered["framework"]["right"]} of {ordered["total"]}</div>
      <div class="lbl">scenario case pairs ordered correctly</div>
      <div class="vs">scanner severity alone: {ordered["baseline"]["right"]}, with
      {ordered["baseline"]["tied"]} tied</div></div>
    <div class="tile"><div class="big">{exact["framework"]} of {exact["total"]}</div>
      <div class="lbl">scenarios matched tier for tier</div>
      <div class="vs">scanner severity alone: {exact["baseline"]}</div></div>
    <div class="tile"><div class="big">{_n(population["ranked"])}</div>
      <div class="lbl">findings ranked</div>
      <div class="vs">from {_n(population["reported"])} reported by three scanners</div></div>
  </div>
</header>"""


def _model_section(f: dict[str, Any]) -> str:
    model = f["model"]
    chips = '<span class="eq">+</span>'.join(
        f'<span class="chip">{factor["key"].capitalize()}'
        f'<span class="rng">{factor["minimum"]}&ndash;{factor["maximum"]}</span></span>'
        for factor in model["factors"]
    )
    scale = "".join(
        f'<div class="band {band["name"].lower()}" '
        f'style="flex:{band["maximum"] - band["minimum"] + 1} 1 0">'
        f'<b>{band["name"]}</b><span class="num">{band["minimum"]}&ndash;{band["maximum"]}</span>'
        f"<span>{escape(band['action'])}</span></div>"
        for band in reversed(model["bands"])
    )
    defaults = ", ".join(f"{factor['key']} {factor['default']}" for factor in model["factors"])
    lowest = min(factor["minimum"] for factor in model["factors"] if factor["key"] == "severity")
    ceiling = sum(factor["maximum"] for factor in model["factors"])
    return f"""
<section>
  <p class="step">The framework</p>
  <h2>What it does</h2>
  <p class="sub">A five-layer pipeline. Detection is left to the existing scanners; the
  contribution is the prioritization layer on top of them.</p>
  <div class="pipe">
    <div class="stage given"><div class="n">1</div><h3>IaC input</h3>
      <p>Terraform files and Kubernetes manifests.</p></div>
    <div class="stage given"><div class="n">2</div><h3>Security scanning</h3>
      <p>Checkov, tfsec and Trivy run unchanged. Their findings are normalized and exact
      duplicates merged.</p></div>
    <div class="stage"><div class="n">3</div><h3>Context extraction</h3>
      <p>Exposure, privilege and encryption are read from the code. Sensitivity and
      criticality are declared.</p></div>
    <div class="stage"><div class="n">4</div><h3>Risk scoring</h3>
      <p>A transparent additive score. No machine learning: every point is attributable.</p></div>
    <div class="stage"><div class="n">5</div><h3>Reporting</h3>
      <p>A ranked list in four priority bands, with one explanation line per factor.</p></div>
  </div>
  <div class="formula"><span class="eq">Score =</span>{chips}
    <span class="eq">from {lowest} to {ceiling}</span></div>
  <div class="scale">{scale}</div>
  <p class="sub" style="margin-top:16px">A factor that cannot be read from the code is never
  treated as low. It takes a stated default ({defaults}) and is marked as a default wherever
  it is shown.</p>
</section>"""


def _measured_section(f: dict[str, Any]) -> str:
    population, corpus, scanners = f["population"], f["corpus"], f["scanners"]
    reported = population["reported"]
    share = f"{population['no_severity'] / reported:.1%}"
    by_scanner = ", ".join(f"{_name(name)} {_n(count)}" for name, count in scanners.items())
    silent = _listed([_name(name) for name in f["scanners_without_severity"]])
    funnel = "".join(
        _share(label, note, value, reported, "framework")
        for label, note, value in (
            ("Reported by the scanners", by_scanner, reported),
            (
                "Ranked",
                f"after merging {population['duplicates']} exact duplicates",
                population["ranked"],
            ),
            (
                "Context-eligible",
                "attached to a cloud resource the framework can describe",
                population["context_eligible"],
            ),
            (
                "Not low-confidence",
                "at least three of five contextual factors read from evidence",
                population["not_low_confidence"],
            ),
        )
    )
    return f"""
<section>
  <p class="step">The evaluation</p>
  <h2>What was measured</h2>
  <p class="sub">Two deliberately insecure teaching repositories, TerraGoat and Kubernetes
  Goat, plus {corpus["hand_crafted"]} hand-written cases: {corpus["cases"]} cases,
  {corpus["pairs"]} contrastive pairs and {corpus["scenarios"]} scenarios, with expected
  orderings registered before any score existed. Four populations recur, and a figure means
  little without knowing which it is over.</p>
  <div class="funnel">{funnel}</div>
  <div class="notice"><strong>The baseline is weaker than it looks.</strong>
    <p>{_n(population["no_severity"])} of the {_n(reported)} findings ({share}) arrive with
    no severity at all, every one of them from {silent}. For those findings the "scanner
    severity" the framework is compared against is itself a default.</p></div>
</section>"""


def _ordering_section(f: dict[str, Any]) -> str:
    pairs, scenarios = f["pairs"], f["scenarios"]
    ordered, exact, decided = scenarios["ordered"], scenarios["exact"], scenarios["decided_by"]
    outcome = {"Right": "right", "Tied": "tied", "Inverted": "inverted"}

    def stack(label: str, note: str, counts: dict[str, int]) -> str:
        return _stack(label, note, {name: counts[key] for name, key in outcome.items()})

    def decided_text(by: dict[str, int]) -> str:
        return ", ".join(f"{count} by {kind}" for kind, count in by.items() if count) or "&ndash;"

    matched = "scenarios matched exactly"
    pair_rows = "".join(
        f"<tr><td><code>{escape(row['pair_id'])}</code></td><td>{row['factor']}</td>"
        f"<td>{row['kind']}</td><td class='n'>{row['high']}</td><td class='n'>{row['low']}</td>"
        f"<td>{_tag(row['framework'])}</td><td>{_tag(row['baseline'])}</td></tr>"
        for row in pairs["rows"]
    )
    scenario_rows = "".join(
        f"<tr><td>{_name(row['domain'])}</td>"
        f"<td class='n'>{_triple(row['framework'])}</td>"
        f"<td>{'yes' if row['exact'] else 'no'}</td>"
        f"<td class='n'>{_triple(row['baseline'])}</td>"
        f"<td>{decided_text(row['decided_by'])}</td></tr>"
        for row in scenarios["rows"]
    )
    mined = pairs["mined_needing_extraction"]
    also = (
        " and scanner severity alone passes it too"
        if pairs["mined_passes_also_pass_the_baseline"]
        else ""
    )
    other = decided["code or scanner evidence"]
    remaining = mined["total"] - mined["passed"]
    if len(pairs["failures"]) == 1:
        factor, verdict = pairs["failures"][0]
        rest = (
            f" The other {remaining} are the {factor} pairs, which {verdict}: the {factor} "
            "factor is not shown to work."
        )
    else:
        rest = f" The other {remaining} do not pass; the table below gives each."
    return f"""
<section>
  <p class="step">Result 1</p>
  <h2>Does context rank better than scanner severity alone?</h2>
  <p class="sub">Two tests. A <em>contrastive pair</em> is two cases that should differ in
  one factor only: the riskier one must score strictly higher. A <em>scenario</em> is three
  to five cases with an expected order. Both are graded for the framework and, by the same
  rules, for scanner severity alone.</p>
  {_share("Framework", "pairs passed", pairs["framework"], pairs["total"], "framework")}
  {_share("Scanner severity", "pairs passed", pairs["baseline"], pairs["total"], "baseline")}
  {_share("Framework", matched, exact["framework"], exact["total"], "framework")}
  {_share("Scanner severity", matched, exact["baseline"], exact["total"], "baseline")}
  {stack("Framework", f"{ordered['total']} scenario case pairs", ordered["framework"])}
  {stack("Scanner severity", f"{ordered['total']} scenario case pairs", ordered["baseline"])}
  {_legend("Framework", "Baseline (scanner severity)", "Right order", "Tied", "Inverted")}

  <div class="notice"><strong>Read these with what qualifies them.</strong>
    <ul>
      <li><strong>{pairs["by_construction"]} of the {pairs["framework"]} passing pairs hold by
      construction.</strong> Each puts one resource under two declared contexts, so the only
      difference between the two scores is the number that was declared.</li>
      <li><strong>{pairs["hand_crafted_passed"]} more are on hand-crafted cases</strong>,
      written by the author because the corpus offered no pair for those factors.</li>
      <li><strong>Of the {mined["total"]} mined pairs that need something read from the
      code, {mined["passed"]} passes</strong>{also}.{rest}</li>
      <li><strong>Of the {ordered["framework"]["right"]} correctly ordered scenario pairs,
      {decided["declared context alone"]} are decided by declared context alone</strong> and
      {decided["hand-crafted cases"]} are on hand-crafted cases. Of the remaining {other},
      {scenarios["read_on_both_sides"]} are ordered by a value read from the code on both
      sides.</li>
    </ul></div>

  <table>
    <tr><th>Contrastive pair</th><th>Factor tested</th><th>Source</th><th class="n">High case</th>
    <th class="n">Low case</th><th>Framework</th><th>Scanner severity</th></tr>
    {pair_rows}
  </table>
  <table>
    <tr><th>Scenario</th><th class="n">Framework right / tied / inverted</th><th>Exact match</th>
    <th class="n">Scanner severity right / tied / inverted</th><th>Correct pairs decided</th></tr>
    {scenario_rows}
  </table>
</section>"""


def _band_section(f: dict[str, Any]) -> str:
    bands, population = f["bands"], f["population"]
    eligible, confident, caveats = (
        bands["context_eligible"],
        bands["not_low_confidence"],
        bands["caveats"],
    )

    def group(title: str, block: dict[str, Any]) -> str:
        return (
            f'<h3 style="margin-top:20px">{title}</h3>'
            + _stack("Scanner severity", f"{_n(block['findings'])} findings", block["baseline"])
            + _stack("Framework", f"{_n(block['findings'])} findings", block["framework"])
        )

    rows = "".join(
        f"<tr><td>{_pill(band)}</td><td class='n'>{_n(eligible['baseline'][band])}</td>"
        f"<td class='n'>{_n(eligible['framework'][band])}</td>"
        f"<td class='n'>{_n(confident['baseline'][band])}</td>"
        f"<td class='n'>{_n(confident['framework'][band])}</td></tr>"
        for band in BANDS
    )
    return f"""
<section>
  <p class="step">Result 2</p>
  <h2>What happens to the priority bands?</h2>
  <p class="sub">The framework moves most findings into the middle. Critical and High
  together fall from {_n(eligible["before"])} to {_n(eligible["after"])}
  (<strong>{eligible["reduction"]}</strong>) over the {_n(population["context_eligible"])}
  context-eligible findings, and from {_n(confident["before"])} to {_n(confident["after"])}
  (<strong>{confident["reduction"]}</strong>) over the {_n(population["not_low_confidence"])}
  that are not low-confidence.</p>
  {group(f"All {_n(population['context_eligible'])} context-eligible findings", eligible)}
  {group(f"The {_n(population['not_low_confidence'])} that are not low-confidence", confident)}
  {_legend("Critical", "High", "Medium", "Low")}
  <table>
    <tr><th>Band</th><th class="n">Scanner severity, of {_n(eligible["findings"])}</th>
    <th class="n">Framework, of {_n(eligible["findings"])}</th>
    <th class="n">Scanner severity, of {_n(confident["findings"])}</th>
    <th class="n">Framework, of {_n(confident["findings"])}</th></tr>
    {rows}
  </table>
  <div class="notice">
    <strong>These percentages are the least reliable numbers on this page.</strong>
    <ul>
      <li>{_n(caveats["baseline_high_with_no_severity"])} of the baseline's
      {_n(eligible["before"])} Critical or High findings carry no scanner severity. Their
      baseline band is a default the framework chose itself.</li>
      <li>{_n(caveats["low_confidence"])} of the {_n(population["context_eligible"])} findings
      are low-confidence: three or more of their five contextual factors are defaults.</li>
      <li>{_n(caveats["high_on_the_boundary"])} of the {_n(caveats["high_findings"])} High
      findings score exactly on the High boundary, so a one-point change moves most of the
      band (next section).</li>
      <li>No finding reaches Critical. The highest score in the corpus is
      {caveats["highest_score"]}, against a boundary of {caveats["critical_boundary"]}.</li>
    </ul></div>
</section>"""


def _stability_section(f: dict[str, Any]) -> str:
    s = f["sensitivity"]
    boundary = s["high_boundary"]
    frozen_boundary = f["bands"]["caveats"]["high_findings"]
    tallest = max(boundary.values())
    columns = "".join(
        f'<div class="col{" frozen" if count == frozen_boundary else ""}">'
        f'<div class="v">{_n(count)}</div>'
        f'<div class="rect" style="height:{100 * count / tallest:.1f}%"></div></div>'
        for count in boundary.values()
    )
    axis = "".join(
        f'<div class="{"frozen" if count == frozen_boundary else ""}">High starts at {value}'
        f"{' (frozen)' if count == frozen_boundary else ''}</div>"
        for value, count in boundary.items()
    )
    values = sorted({value for sweep in s["defaults"].values() for value in sweep})
    head = "".join(f'<th class="n">{value}</th>' for value in values)
    rows = "".join(
        f"<tr><td>{factor.capitalize()}</td>"
        + "".join(
            (
                f'<td class="n{" frozen" if value == s["frozen_defaults"][factor] else ""}">'
                f"{_n(sweep[value])}</td>"
                if value in sweep
                else '<td class="n">&ndash;</td>'
            )
            for value in values
        )
        + "</tr>"
        for factor, sweep in s["defaults"].items()
    )
    around = sorted(boundary)
    position = around.index(next(v for v, c in boundary.items() if c == frozen_boundary))
    lower, upper = boundary[around[position - 1]], boundary[around[position + 1]]
    return f"""
<section>
  <p class="step">Result 3</p>
  <h2>How stable are the results?</h2>
  <p class="sub">{s["variants"]} variants of the model were registered before any was
  computed: every unresolved default across its range, every band boundary moved by one and
  two points, every factor dropped and doubled. All {s["variants"]} are reported.</p>
  <div class="two">
    <div class="card yes"><h3>The ordering results hold</h3>
      <ul>
        <li>The pair result is unchanged in <strong>{s["pairs_unchanged"]} of
        {s["variants"]}</strong> variants. It moves only when the factor a pair tests is
        removed altogether.</li>
        <li>The number of exactly matched scenarios is unchanged in
        <strong>{s["exact_matches_unchanged"]} of {s["variants"]}</strong>.</li>
      </ul></div>
    <div class="card no"><h3>The band counts do not</h3>
      <ul>
        <li>Moving the High boundary one point changes the Critical/High count from
        <strong>{_n(frozen_boundary)}</strong> to <strong>{_n(upper)}</strong> or
        <strong>{_n(lower)}</strong>.</li>
        <li>With every default at its minimum the count is
        {_n(s["all_defaults"]["minimum"])}; at its maximum, {_n(s["all_defaults"]["maximum"])}.</li>
      </ul></div>
  </div>
  <h3 style="margin-top:22px">Findings in Critical or High, by where the High band starts</h3>
  <div class="cols">{columns}</div>
  <div class="xaxis">{axis}</div>
  <h3 style="margin-top:24px">Findings in Critical or High, by the default given to one
  unresolved factor</h3>
  <table>
    <tr><th>Default for</th>{head}</tr>
    {rows}
  </table>
  <p class="tiny" style="margin-top:8px">The frozen value of each default is highlighted.
  All counts are of the {_n(f["population"]["context_eligible"])} context-eligible findings.</p>
</section>"""


def _inference_section(f: dict[str, Any]) -> str:
    inference, ordered = f["inference"], f["scenarios"]["ordered"]
    outcome = {"Right": "right", "Tied": "tied", "Inverted": "inverted"}

    def stack(label: str, counts: dict[str, int]) -> str:
        note = f"{ordered['total']} scenario case pairs"
        return _stack(label, note, {name: counts[key] for name, key in outcome.items()})

    resolved = inference["resolved"]
    return f"""
<section>
  <p class="step">Result 4</p>
  <h2>What if nobody declares the context?</h2>
  <p class="sub">A second mode reads sensitivity and criticality from tags, labels and
  resource names instead. On this corpus it resolved <strong>{resolved["resources"]} of
  {resolved["of_resources"]} resources</strong> ({resolved["findings"]} findings): the
  teaching repositories carry almost no literal tags. So this result shows what declared
  context was contributing, more than it tests the mode.</p>
  {stack("Declared context", ordered["framework"])}
  {stack("Inferred instead", inference["ordered"])}
  {_legend("Right order", "Tied", "Inverted")}
  <p class="sub" style="margin-top:14px">Without declarations
  {_n(inference["scores"]["higher"])} findings score higher, {_n(inference["scores"]["same"])}
  the same and {_n(inference["scores"]["lower"])} lower, so
  {_n(inference["high"]["inferred"])} land in High against
  {_n(inference["high"]["declared"])} with declared context. Missing context makes the
  framework more cautious, never less.</p>
</section>"""


def _sample_section(f: dict[str, Any]) -> str:
    sample = f["sample"]

    def factors(row: dict[str, Any]) -> str:
        return " &nbsp; ".join(
            f"{key} {row['contributions'][key]}{'*' if key in row['defaults'] else ''}"
            for key in FACTORS
        )

    rows = "".join(
        f"<tr><td><code>{escape(row['resource'])}</code>"
        f"<div class='factors'>{factors(row)}</div></td>"
        f"<td>{_pill(row['baseline_band'])}</td>"
        f"<td class='n'><strong>{row['score']}</strong></td><td>{_pill(row['band'])}</td>"
        f"<td class='n'>{row['findings']}</td></tr>"
        for row in sample
    )
    first = sample[0]
    lines = "".join(f"<li>{escape(line)}</li>" for line in first["explanation"])
    same = len({row["baseline_band"] for row in sample}) == 1
    spread = (
        f"Scanner severity alone puts all {len(sample)} in {sample[0]['baseline_band']}. "
        if same
        else ""
    )
    return f"""
<section>
  <p class="step">The tool</p>
  <h2>What it reports for one small folder</h2>
  <p class="sub">The five hand-written resources, each at its highest-scoring finding.
  {spread}The framework spreads them from {sample[0]["score"]} down to {sample[-1]["score"]},
  and says why.</p>
  <table>
    <tr><th>Resource, and its six factor values</th><th>Scanner severity</th>
    <th class="n">Score</th><th>Framework</th><th class="n">Ranked findings</th></tr>
    {rows}
  </table>
  <p class="tiny" style="margin-top:8px">* a default: not read from the code, or not declared.</p>
  <div class="explain"><h3>Why <code>{escape(first["resource"])}</code> scores {first["score"]}</h3>
    <ul>{lines}</ul></div>
  <p class="sub" style="margin-top:16px">Produced by
  <code>uv run iacrisk &lt;folder&gt; --declared context.json</code>, which runs the three
  scanners live. Where the scanners are installed, a test scans both corpus folders again
  and requires the recorded scores back, finding for finding.</p>
</section>"""


def _conclusion_section(f: dict[str, Any]) -> str:
    pairs, scenarios, s = f["pairs"], f["scenarios"], f["sensitivity"]
    ordered, decided = scenarios["ordered"], scenarios["decided_by"]
    boundary = sorted(s["high_boundary"].values())
    return f"""
<section>
  <p class="step">Conclusion</p>
  <h2>What the evidence supports, and what it does not</h2>
  <div class="two">
    <div class="card yes"><h3>Supported</h3>
      <ul>
        <li><strong>Context separates findings that scanner severity cannot.</strong> The
        baseline ties {ordered["baseline"]["tied"]} of the {ordered["total"]} scenario pairs;
        the framework orders {ordered["framework"]["right"]} and inverts
        {ordered["framework"]["inverted"]}.</li>
        <li><strong>A declared business context reaches the ranking faithfully</strong>, and
        every point of every score is attributable to a named factor.</li>
        <li><strong>The ordering results are stable</strong> across the registered
        perturbations ({s["pairs_unchanged"]} of {s["variants"]} for the pairs).</li>
        <li><strong>Exposure and privilege move the ranking in the predicted
        direction</strong> where they resolve: on the hand-crafted cases and in the
        networking scenario.</li>
      </ul></div>
    <div class="card no"><h3>Not supported</h3>
      <ul>
        <li><strong>Any claim about how many alerts are saved.</strong> The Critical/High
        count ranges from {_n(boundary[0])} to {_n(boundary[-1])} as one boundary moves two
        points either way.</li>
        <li><strong>That the encryption factor works.</strong> Both of its pairs tie.</li>
        <li><strong>That most of the ordering is derived from code.</strong>
        {decided["declared context alone"]} of {ordered["framework"]["right"]} correct
        scenario pairs and {pairs["by_construction"]} of {pairs["framework"]} passing pairs
        rest on declared context alone.</li>
        <li><strong>External validity.</strong> The expected orderings were reviewed by an
        automated reviewer, not a human expert, and the corpus is two teaching
        repositories.</li>
        <li><strong>Behaviour at the top of the range.</strong> No finding reaches Critical.</li>
      </ul></div>
  </div>
</section>"""


def render(f: dict[str, Any]) -> str:
    """The whole page from the figures. Holds prose and layout, and no number of its own."""
    style = STYLE.read_text(encoding="utf-8")
    body = "".join(
        section(f)
        for section in (
            _header,
            _model_section,
            _measured_section,
            _ordering_section,
            _band_section,
            _stability_section,
            _inference_section,
            _sample_section,
            _conclusion_section,
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Risk-aware IaC prioritization - results overview</title>
<style>
{style}</style>
</head>
<body>
<div class="wrap">
{body}
<footer>
  <p class="tiny">Generated by <code>tools/overview/build.py</code> from the committed
  records under <code>artifacts/</code>; every number on this page is read from them. The
  full account, with both recorded states of each result, is Chapter 6
  (<code>docs/writeup/06-evaluation.md</code>).</p>
</footer>
</div>
</body>
</html>
"""


def main() -> int:
    OUTPUT.write_text(render(figures(load())), encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
