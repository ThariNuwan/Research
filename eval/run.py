"""Run the harness over the committed artifacts and write the evaluation record.

    uv run python -m eval.run      # artifacts/evaluation-v1.json

Reads three files and writes one. It imports `eval.harness` and nothing of the framework:
what it grades reaches it as JSON, produced beforehand by `tools.score.run`. The provenance
block records a digest of each input, so a figure in the output names the exact scored
documents it was computed from.
"""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval import harness
from eval.ground_truth import load_and_validate

# The harvest's provenance helpers import nothing of the framework, so reusing them keeps
# `repo_commit` in one shape across every committed artifact without crossing the boundary
# `tests/test_architecture.py` guards.
from tools.harvest.provenance import _git_commit, hash_file, worktree_clean

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth" / "corpus-v1.json"
SCORED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0.json"
SCORED_CASES = REPO_ROOT / "artifacts" / "scored-cases-v1.json"
OUTPUT = REPO_ROOT / "artifacts" / "evaluation-v1.json"

INPUTS = (GROUND_TRUTH, SCORED_CORPUS, SCORED_CASES)


def _load(path: Path) -> Any:
    return json.loads(path.read_bytes())


def evaluation_document() -> dict[str, Any]:
    """The harness's verdict over the three committed inputs, with their digests."""
    result = harness.evaluate(
        load_and_validate(GROUND_TRUTH), _load(SCORED_CORPUS), _load(SCORED_CASES)
    )
    return {
        "schema_version": 1,
        "description": (
            "The independent harness's metrics over corpus v0's ranked findings and "
            "corpus v1's cases, graded against the pre-registered oracle."
        ),
        "provenance": {
            "generated_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "python": platform.python_version(),
            "repo_commit": _git_commit(REPO_ROOT),
            # Outside `artifacts/`: the harness's inputs live there and are pinned by the
            # digests below, so what this states is that the harness code is the commit's.
            "source_clean": worktree_clean(REPO_ROOT, ignoring=("artifacts",)),
            "inputs": {path.relative_to(REPO_ROOT).as_posix(): hash_file(path) for path in INPUTS},
        },
        **result,
    }


def main(argv: list[str] | None = None) -> int:
    document = evaluation_document()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")

    pairs = document["contrastive_pairs"]["summary"]["authored"]
    scenarios = document["scenarios"]["summary"]["headline"]
    rule = harness.PRIMARY_RULE
    print(
        f"pairs={pairs['pairs']} evaluable={pairs['evaluable']} "
        f"framework_passes={pairs['framework_passes'][rule]} "
        f"baseline_passes={pairs['baseline_passes']} | "
        f"scenarios={scenarios['scenarios']} "
        f"framework_exact={scenarios['framework'][rule]['exact_tier_matches']} "
        f"baseline_exact={scenarios['baseline']['exact_tier_matches']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
