"""Replay the committed scanner captures through the pipeline and write the scored record.

A research instrument, beside `tools/harvest/` and `tools/paircand/`: outside `src/` because
it is not part of the artifact, and outside `eval/` because it imports the framework that
`eval/` grades (`tests/test_architecture.py`). What it writes is the only thing S5's harness
reads - the harness sees JSON, never `iacrisk`.

    uv run python -m tools.score.run corpus    # artifacts/scored-corpus-v0.json
    uv run python -m tools.score.run cases     # artifacts/scored-cases-v1.json

`corpus --markdown` also renders the human report. It is a view over the JSON and about a
megabyte, so it is written on request rather than committed beside its own source.

**No scanner runs here.** Every figure comes from the captures under
`tests/harvest/fixtures/`, the same bytes S3a, S3b and S4 measured, so a result does not
depend on a scanner being installed or on what it would emit today. The provenance block
says so and records a digest of every input.

**Two targets, because they answer two questions.**

`corpus` scores corpus v0 - the two vendored roots, 1,055 findings - under one declared
value per resource. It feeds the band distributions, alert reduction and the baseline
comparison.

`cases` scores each `corpus-v1` case **under that case's own declared context**. The corpus
target cannot stand in for it: the four declared-factor pairs put two or three cases on one
resource with different declared values, on purpose, and a single merged map can hold only
one of them. `merged_declared` reports every such identity and which case it applied, so the
arbitrary part of the corpus target's input is visible instead of implicit.

A case is scored at finding level and no further. How a case's findings become one rank is
the harness's rule to state, not this tool's.
"""

from __future__ import annotations

import argparse
import json
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval.ground_truth import load_and_validate
from iacrisk import pipeline
from iacrisk.context.kubernetes import build_body_index
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.terraform import build_index as build_tf_index
from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.resources import build_index
from iacrisk.scanners.base import AdapterResult, ScannerAdapter
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.invoke import applicable_scanners
from iacrisk.scanners.tfsec import TfsecAdapter, capture_scan_root
from iacrisk.scanners.trivy import TrivyAdapter
from iacrisk.scoring import emit

# `_git_commit` is harvest's six-state HEAD probe. Imported rather than restated so every
# committed artifact reports `repo_commit` in one shape.
from tools.harvest.provenance import _git_commit, hash_file, worktree_clean

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "harvest" / "fixtures"
GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"
SCANNERS_LOCK = REPO_ROOT / "tools" / "scanners.lock.json"
DATA = REPO_ROOT / "src" / "iacrisk" / "data"
ARTIFACTS = REPO_ROOT / "artifacts"

CORPUS_JSON = ARTIFACTS / "scored-corpus-v0.json"
CORPUS_MARKDOWN = ARTIFACTS / "priority-report-corpus-v0.md"
CASES_JSON = ARTIFACTS / "scored-cases-v1.json"

ADAPTERS: dict[str, ScannerAdapter] = {
    "checkov": CheckovAdapter(),
    "tfsec": TfsecAdapter(),
    "trivy": TrivyAdapter(),
}


@dataclass(frozen=True)
class Root:
    """One scanned directory and where its captures were saved."""

    platform: str
    scan_root: Path
    fixtures: Path


ROOTS: dict[str, Root] = {
    "terragoat": Root(
        "terraform",
        REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws",
        FIXTURES,
    ),
    "kubernetes-goat": Root(
        "kubernetes",
        REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios",
        FIXTURES,
    ),
    "authored": Root("terraform", REPO_ROOT / "corpus" / "authored", FIXTURES / "authored"),
}
"""Every scan root `tools/corpus.lock.json` declares. `tests/score/test_run.py` pins the two
against each other, so a root added to the lockfile and not here is a failing test."""

CORPUS_V0 = ("terragoat", "kubernetes-goat")
"""The measurement corpus: the two vendored roots, and the 1,055 findings every S3a-S4
figure is over. The authored root exists for five `corpus-v1` cases and is scored only for
them, so it cannot move a corpus-level figure."""


@dataclass(frozen=True)
class Replayed:
    """One or more roots' adapter runs, with the indexes layer 3 reads."""

    results: dict[tuple[str, str], AdapterResult]
    tf_index: dict[str, TerraformResource]
    k8s_index: dict[str, dict[str, Any]]
    unparseable: frozenset[str]

    @property
    def findings(self) -> list[NormalizedFinding]:
        return [finding for result in self.results.values() for finding in result.findings]


def _load(path: Path) -> Any:
    return json.loads(path.read_bytes())


def fixture_paths(root: Root) -> dict[str, Path]:
    """The capture each applicable scanner left for `root`, keyed by scanner.

    Which scanners apply is the lockfile's platform matrix, read as data
    (`applicable_scanners`) - tfsec has no Kubernetes capture to replay because the
    lockfile declares it Terraform-only, not because of a branch here.
    """
    return {
        scanner: root.fixtures / f"{scanner}-{root.platform}.json"
        for scanner in applicable_scanners(root.platform)
    }


def replay(root: Root) -> Replayed:
    """Parse one root's captures and index its source files."""
    discovery = discover(root.scan_root)
    resource_index = build_index(discovery) if root.platform == "kubernetes" else None

    results: dict[tuple[str, str], AdapterResult] = {}
    for scanner, path in fixture_paths(root).items():
        raw = _load(path)
        # tfsec alone reports absolute paths, so its capture replays against the root it
        # was recorded under, not wherever this checkout lives.
        parse_root = (
            capture_scan_root(raw, root.scan_root, REPO_ROOT)
            if scanner == "tfsec"
            else root.scan_root
        )
        results[(scanner, root.platform)] = ADAPTERS[scanner].parse(raw, parse_root, resource_index)

    manifests = sorted(root.scan_root.rglob("*.yaml")) + sorted(root.scan_root.rglob("*.yml"))
    unparseable = frozenset(discovery.unparseable)
    if resource_index is not None:
        unparseable |= frozenset(resource_index.unparseable)
    return Replayed(
        results=results,
        tf_index=build_tf_index(sorted(root.scan_root.rglob("*.tf")), root.scan_root),
        k8s_index=build_body_index(manifests),
        unparseable=unparseable,
    )


def merge(parts: list[Replayed]) -> Replayed:
    """Several roots as one corpus. A `(scanner, platform)` key two roots share is an error:
    silently keeping one would drop a whole adapter run from every figure."""
    results: dict[tuple[str, str], AdapterResult] = {}
    tf_index: dict[str, TerraformResource] = {}
    k8s_index: dict[str, dict[str, Any]] = {}
    unparseable: frozenset[str] = frozenset()
    for part in parts:
        clash = results.keys() & part.results.keys()
        if clash:
            raise ValueError(f"two roots share the adapter runs {sorted(clash)}")
        results.update(part.results)
        tf_index.update(part.tf_index)
        k8s_index.update(part.k8s_index)
        unparseable |= part.unparseable
    return Replayed(results, tf_index, k8s_index, unparseable)


def merged_declared(
    document: dict[str, Any],
) -> tuple[dict[str, dict[str, int]], list[dict[str, Any]]]:
    """One declared value per identity, and every identity the cases disagree on.

    The last case in document order wins - the rule S4's gates applied, kept so the
    corpus target reproduces the figures S4 recorded. It is arbitrary, which is why the
    conflicts are returned and written into the artifact: each names the declarations
    that competed and the case that was applied.
    """
    declared: dict[str, dict[str, int]] = {}
    seen: dict[str, list[dict[str, Any]]] = {}
    for case in document["cases"]:
        for identity, values in case["declared_context"].items():
            declared[identity] = values
            seen.setdefault(identity, []).append({"case_id": case["case_id"], **values})

    conflicts = []
    for identity, declarations in sorted(seen.items()):
        distinct = {(d["sensitivity"], d["criticality"]) for d in declarations}
        if len(distinct) > 1:
            conflicts.append(
                {
                    "resource_identity": identity,
                    "declarations": declarations,
                    "applied": declarations[-1]["case_id"],
                }
            )
    return declared, conflicts


def _root_for(case: dict[str, Any]) -> str:
    if case["source"] == "hand-crafted":
        return "authored"
    return "terragoat" if case["platform"] == "terraform" else "kubernetes-goat"


def score_cases(document: dict[str, Any]) -> dict[str, Any]:
    """Each case's findings, scored under that case's own declared context.

    A case's findings are those on the identities it declares. A case that matches none is
    an error, not an empty entry: there would be nothing to rank, and an identity that has
    drifted from the adapters' spelling would otherwise score as silently absent.
    """
    replayed = {name: replay(root) for name, root in ROOTS.items()}
    cases: dict[str, Any] = {}
    for case in document["cases"]:
        root = _root_for(case)
        part = replayed[root]
        declared = case["declared_context"]
        findings = [f for f in part.findings if f.resource_identity in declared]
        if not findings:
            raise ValueError(
                f"case {case['case_id']!r} declares {sorted(declared)} and no finding in "
                f"the {root} root carries that identity"
            )
        scored = pipeline.prioritize(findings, declared, part.tf_index, part.k8s_index)
        cases[case["case_id"]] = {
            "root": root,
            "declared_context": declared,
            "population": scored["population"],
            "findings": scored["findings"],
        }
    return cases


def provenance(inputs: list[Path]) -> dict[str, Any]:
    """What produced an artifact: a replay, of these bytes, at this commit.

    `scanner_pins` is the lockfile's record of what the captures were made with. It is not
    a claim about any scanner installed on this host - none was run.
    """
    lock = _load(SCANNERS_LOCK)
    return {
        "mode": "replay",
        "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "repo_commit": _git_commit(REPO_ROOT),
        # Outside `artifacts/`: whether the code and inputs that ran are `repo_commit`'s.
        "source_clean": worktree_clean(REPO_ROOT, ignoring=("artifacts",)),
        "scanner_pins": {
            name: entry["version"] for name, entry in sorted(lock["scanners"].items())
        },
        "inputs": {path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in inputs},
    }


def _inputs(roots: tuple[str, ...]) -> list[Path]:
    """Every file a target's numbers depend on, other than the code at `repo_commit`."""
    captures = [path for name in roots for path in fixture_paths(ROOTS[name]).values()]
    sources = [
        path
        for name in roots
        for path in sorted(ROOTS[name].scan_root.rglob("*"))
        if path.is_file()
    ]
    return [GROUND_TRUTH, SCANNERS_LOCK, *sorted(DATA.glob("*.json")), *captures, *sources]


def corpus_document() -> dict[str, Any]:
    document = load_and_validate(GROUND_TRUTH)
    declared, conflicts = merged_declared(document)
    corpus = merge([replay(ROOTS[name]) for name in CORPUS_V0])
    return {
        "schema_version": 1,
        "description": (
            "Corpus v0 through pipeline layers 2-5, replayed from the committed scanner "
            "captures under corpus-v1's declared context."
        ),
        "provenance": provenance(_inputs(CORPUS_V0)),
        "declared_context": {
            "source": GROUND_TRUTH.relative_to(REPO_ROOT).as_posix(),
            "merge_rule": "one value per identity; the last case in document order wins",
            "identities": len(declared),
            "conflicts": conflicts,
        },
        **pipeline.run(
            corpus.results, declared, corpus.tf_index, corpus.k8s_index, corpus.unparseable
        ),
    }


def cases_document() -> dict[str, Any]:
    document = load_and_validate(GROUND_TRUTH)
    return {
        "schema_version": 1,
        "description": (
            "Each corpus-v1 case's findings, scored under that case's own declared "
            "context. Finding level only: no case-level aggregate is computed here."
        ),
        "provenance": provenance(_inputs(tuple(ROOTS))),
        "cases": score_cases(document),
    }


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path: Path, document: dict[str, Any]) -> None:
    _write(path, json.dumps(document, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay the scanner captures and score them.")
    parser.add_argument("target", choices=("corpus", "cases"))
    parser.add_argument(
        "--markdown",
        action="store_true",
        help=f"also render the corpus target's human report to {CORPUS_MARKDOWN.name}",
    )
    args = parser.parse_args(argv)

    if args.target == "corpus":
        document = corpus_document()
        _write_json(CORPUS_JSON, document)
        if args.markdown:
            _write(CORPUS_MARKDOWN, emit.render_markdown(document))
        population = document["population"]
        print(
            f"findings_in={population['findings_in']} "
            f"tier1_collapsed={population['tier1_collapsed']} ranked={population['ranked']} "
            f"bands={document['report']['overall']}"
        )
    else:
        document = cases_document()
        _write_json(CASES_JSON, document)
        print(f"cases={len(document['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
