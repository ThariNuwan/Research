"""The end-to-end command: a folder of IaC files in, a ranked remediation list out.

    uv run iacrisk <folder> [--declared FILE | --infer] [--out DIR] [--top N]

This module adds no layer and decides nothing. It joins the pieces that already exist -
discovery, live scanner invocation, the adapters, and `pipeline.run` - in the order the
evaluated replay path (`tools/score/run.py`) joins them, and it reads the same indexes in
the same way, so that what it reports for a folder is what the evaluation measured for
that folder. `tests/test_cli.py` holds it to that, against the committed per-case record.

**It was built after the evaluation and no reported result came from it.** Every figure in
the dissertation was replayed from captured scanner output. What this command adds is the
one step the replay never took - launching the scanners - and a test that runs them for
real over `corpus/authored` and arrives at the committed scores.

Three limits, each a refusal instead of a wrong answer:

- **One platform per folder.** Each adapter reads the platform off a whole scanner run, so
  a folder holding both Terraform and Kubernetes files is refused.
- **Every scanner must answer.** A scanner that is missing, times out or prints nothing
  usable stops the run; the folder is never ranked on the scanners that did answer.
- **It runs from a bootstrapped checkout.** Scanner binaries are resolved from
  `tools/resolved.json` and nowhere else (`scanners/invoke.py`), so `tools/bootstrap.ps1`
  has to have run.

Exit codes: 0 with a report, 2 when the request cannot be carried out as asked, 1 when a
scanner failed. There is no option that fails on a priority band.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iacrisk import pipeline, rubric
from iacrisk.context.declared import load_declared
from iacrisk.context.inferred import infer
from iacrisk.context.kubernetes import build_body_index, lookup
from iacrisk.context.terraform import build_index as build_terraform_index
from iacrisk.input import DiscoveryResult, discover
from iacrisk.resources import build_index as build_resource_index
from iacrisk.scanners import invoke
from iacrisk.scanners.base import ScannerAdapter
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter
from iacrisk.scoring import emit
from iacrisk.scoring.engine import FACTOR_ORDER

__all__ = [
    "InputError",
    "ResourceRow",
    "Scan",
    "ScanFailedError",
    "Summary",
    "analyse",
    "by_resource",
    "live_scan",
    "main",
    "render_summary",
    "write_report",
]

Scan = Callable[[DiscoveryResult, Path], Mapping[tuple[str, str], object]]
"""Launch every applicable scanner over a folder: `(scanner, platform)` to its raw output."""

ADAPTERS: Mapping[str, ScannerAdapter] = {
    "checkov": CheckovAdapter(),
    "tfsec": TfsecAdapter(),
    "trivy": TrivyAdapter(),
}


class InputError(Exception):
    """The folder or the context supplied cannot be analysed as asked."""


class ScanFailedError(Exception):
    """A scanner ran and returned nothing usable."""


def live_scan(discovery: DiscoveryResult, scan_root: Path) -> dict[tuple[str, str], object]:
    """Launch each pinned scanner the lockfile declares for the folder's platform.

    Every scanner must answer. One that returns unusable output raises instead of being
    left out: a ranking built on the scanners that did answer would understate the folder
    and say nothing about it.
    """
    raw: dict[tuple[str, str], object] = {}
    for invocation in invoke.build_invocations(discovery, scan_root):
        try:
            raw[(invocation.scanner, invocation.platform)] = invoke.run(invocation)
        except ValueError as exc:
            raise ScanFailedError(str(exc)) from exc
    return raw


def analyse(
    scan_root: Path,
    *,
    declared: Mapping[str, Mapping[str, int]] | None = None,
    infer_context: bool = False,
    scan: Scan,
) -> dict[str, Any]:
    """Every layer for one folder, through to the payload the reports are rendered from.

    `context_mode` records where sensitivity and criticality came from: `declared`,
    `auto-inference`, or `defaults` when neither was supplied - in which case both factors
    take the rubric's defaults on every finding, never a low value.
    """
    # tfsec reports absolute paths, so the folder has to be absolute before any finding can
    # be placed under it.
    scan_root = scan_root.resolve()
    try:
        discovery = discover(scan_root)
    except FileNotFoundError as exc:
        raise InputError(str(exc)) from exc
    platforms = sorted({found.platform for found in discovery.files})
    if not platforms:
        raise InputError(f"no Terraform or Kubernetes files were found under {scan_root}")
    if len(platforms) > 1:
        # Each adapter reads the platform off a whole scanner run (`_platform_of`), so one
        # run over a mixed folder would be parsed as a single platform.
        raise InputError(
            f"{scan_root} holds both {' and '.join(platforms)} files, which one run cannot "
            "attribute correctly; point the command at each platform's folder in turn"
        )
    resource_index = build_resource_index(discovery) if "kubernetes" in platforms else None

    results = {
        (scanner, platform): ADAPTERS[scanner].parse(raw, scan_root, resource_index)
        for (scanner, platform), raw in scan(discovery, scan_root).items()
    }

    tf_index = build_terraform_index(sorted(scan_root.rglob("*.tf")), scan_root)
    manifests = sorted(scan_root.rglob("*.yaml")) + sorted(scan_root.rglob("*.yml"))
    k8s_index = build_body_index(manifests)
    unparseable = frozenset(discovery.unparseable)
    if resource_index is not None:
        unparseable |= frozenset(resource_index.unparseable)

    if infer_context:
        mode = "auto-inference"
    elif declared is not None:
        mode = "declared"
    else:
        mode = "defaults"
    not_found = sorted(
        identity
        for identity in declared or {}
        if identity not in tf_index and lookup(k8s_index, identity) is None
    )
    return {
        "scan_root": str(scan_root),
        "context_mode": mode,
        "declared_identities_not_found": not_found,
        **pipeline.run(
            results,
            declared or {},
            tf_index,
            k8s_index,
            unparseable,
            inference=infer(tf_index, k8s_index) if infer_context else None,
        ),
    }


@dataclass(frozen=True)
class ResourceRow:
    """One resource, at the finding that ranks it."""

    identity: str
    score: int
    band: str
    baseline_band: str
    contributions: Mapping[str, int]
    defaults: tuple[str, ...]
    low_confidence: bool
    findings: int
    informational: int


@dataclass(frozen=True)
class Summary:
    ranked: tuple[ResourceRow, ...]
    informational_only: tuple[ResourceRow, ...]


def _claimed(finding: Mapping[str, Any]) -> bool:
    return not finding["unmapped"] and not finding["baseline_only_informational"]


def by_resource(payload: Mapping[str, Any]) -> Summary:
    """The ranked findings folded to one row per resource.

    A resource ranks where its highest-scoring finding ranks, counting only findings the
    framework makes a claim about - the rule the evaluation registered for a case. Findings
    from a rule the taxonomy has never seen, and findings with no context block, are
    counted on the row as `informational` and do not rank it. A resource with nothing else
    is listed apart. `baseline_band` is the highest band scanner severity alone gives any
    of the resource's ranking findings.
    """
    floor = {band.name: band.minimum for band in rubric.bands()}
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for finding in payload["findings"]:
        groups.setdefault(finding["resource_identity"], []).append(finding)

    ranked: list[ResourceRow] = []
    informational_only: list[ResourceRow] = []
    for identity, members in groups.items():
        claimed = [f for f in members if _claimed(f)]
        ranking = claimed or members
        top = max(ranking, key=lambda f: f["score"])
        row = ResourceRow(
            identity=identity,
            score=top["score"],
            band=top["band"],
            baseline_band=max((f["baseline_band"] for f in ranking), key=floor.__getitem__),
            contributions=dict(top["contributions"]),
            defaults=tuple(
                key
                for key in FACTOR_ORDER
                if top["factor_states"].get(key, "resolved") != "resolved"
            ),
            low_confidence=bool(top["low_confidence"]),
            findings=len(members),
            informational=len(members) - len(claimed),
        )
        (ranked if claimed else informational_only).append(row)

    def order(row: ResourceRow) -> tuple[int, str]:
        return (-row.score, row.identity)

    return Summary(tuple(sorted(ranked, key=order)), tuple(sorted(informational_only, key=order)))


def _positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, not {value}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iacrisk",
        description=(
            "Scan a folder of Terraform or Kubernetes files with the pinned scanners and "
            "rank what they find by contextual risk."
        ),
    )
    parser.add_argument("folder", type=Path, help="the folder to scan")
    context = parser.add_mutually_exclusive_group()
    context.add_argument(
        "--declared",
        type=Path,
        metavar="FILE",
        help="JSON mapping a resource identity to its sensitivity and criticality",
    )
    context.add_argument(
        "--infer",
        action="store_true",
        help="read sensitivity and criticality from tags, labels and names instead",
    )
    parser.add_argument(
        "--out",
        type=Path,
        metavar="DIR",
        help="also write every finding with its explanation, as JSON and Markdown",
    )
    parser.add_argument(
        "--top",
        type=_positive,
        default=20,
        metavar="N",
        help="how many resources to show in the terminal (default 20)",
    )
    return parser


def _load_declared(path: Path) -> dict[str, dict[str, int]]:
    try:
        return load_declared(path)
    except (OSError, ValueError) as exc:
        raise InputError(f"the declared context {path} cannot be read: {exc}") from exc


_CONTEXT_LINES = {
    "declared": "declared: sensitivity and criticality as declared for {count} resource(s)",
    "auto-inference": (
        "auto-inference: sensitivity and criticality read from tags, labels and names"
    ),
    "defaults": (
        "defaults: no context was supplied, so sensitivity and criticality take the "
        "rubric's defaults on every finding (--declared FILE or --infer)"
    ),
}


def _factors(row: ResourceRow) -> str:
    """The six contributions in formula order, a default marked with `*`."""
    parts = [
        f"{key} {row.contributions[key]}{'*' if key in row.defaults else ''}"
        for key in FACTOR_ORDER
        if key in row.contributions
    ]
    if row.low_confidence:
        parts.append("(low confidence: most contextual factors are defaults)")
    return "  ".join(parts)


def render_summary(payload: Mapping[str, Any], top: int, declared_count: int) -> str:
    """What the terminal shows: the accounting, then one entry per resource.

    Plain ASCII, because a Windows console's default code page is not UTF-8.
    """
    population = payload["population"]
    runs = payload["retention"]["scanners"]
    bands = payload["report"]["overall"]
    summary = by_resource(payload)

    lines = [
        f"folder     {payload['scan_root']}",
        "scanners   " + ", ".join(f"{name} {run['findings_out']}" for name, run in runs.items()),
        f"findings   {population['findings_in']} reported, {population['tier1_collapsed']} "
        f"exact duplicates merged, {population['ranked']} ranked",
        "context    " + _CONTEXT_LINES[payload["context_mode"]].format(count=declared_count),
        "bands      " + ", ".join(f"{name} {count}" for name, count in bands.items()),
        "",
        "Resources, each at its highest-scoring finding. 'scanners' is the band scanner",
        "severity alone gives it.",
        "",
        f"{'score':>5}  {'band':8}  {'scanners':8}  {'findings':>8}  resource",
    ]
    for row in summary.ranked[:top]:
        lines.append(
            f"{row.score:>5}  {row.band:8}  {row.baseline_band:8}  {row.findings:>8}  "
            f"{row.identity}"
        )
        lines.append(f"{'':7}{_factors(row)}")
    hidden = len(summary.ranked) - top
    if hidden > 0:
        lines.append(f"{'':7}... and {hidden} more ranked resource(s) not shown (--top)")
    lines += ["", f"{'':7}* a default: not read from the code, or not declared"]

    if summary.informational_only:
        lines += [
            "",
            "Informational only - every finding is from a rule the taxonomy has not seen, or",
            "has no cloud resource to attach context to. Not ranked.",
            "",
        ]
        lines += [
            f"{'':7}{row.findings} finding(s) on  {row.identity}"
            for row in summary.informational_only[:top]
        ]
        unlisted = len(summary.informational_only) - top
        if unlisted > 0:
            lines.append(f"{'':7}... and {unlisted} more not shown (--top)")
    return "\n".join(lines)


def write_report(payload: Mapping[str, Any], out: Path) -> None:
    """Every finding with its explanation lines, as JSON and as the Markdown rendered from it."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "priority-report.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (out / "priority-report.md").write_text(
        emit.render_markdown(dict(payload)), encoding="utf-8", newline="\n"
    )


def main(argv: Sequence[str] | None = None, *, scan: Scan = live_scan) -> int:
    """Exit 0 with a report, 2 for something wrong with the request, 1 for a failed scan."""
    args = _parser().parse_args(argv)
    try:
        declared = _load_declared(args.declared) if args.declared else None
        payload = analyse(args.folder, declared=declared, infer_context=args.infer, scan=scan)
    except (InputError, invoke.ScannerNotResolvedError) as exc:
        print(f"iacrisk: {exc}", file=sys.stderr)
        return 2
    except (ScanFailedError, invoke.ScannerTimeoutError) as exc:
        print(f"iacrisk: a scanner failed, so nothing is reported: {exc}", file=sys.stderr)
        return 1

    not_found = payload["declared_identities_not_found"]
    if not_found:
        print(
            f"iacrisk: warning: the declared context names {len(not_found)} resource(s) this "
            f"folder does not contain, so their values were not used: {', '.join(not_found)}",
            file=sys.stderr,
        )
    print(render_summary(payload, args.top, len(declared or {})))
    if args.out is not None:
        write_report(payload, args.out)
        print(f"\nfull report  {args.out}")
    return 0
