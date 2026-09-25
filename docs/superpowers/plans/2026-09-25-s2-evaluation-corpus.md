# S2 — Evaluation Corpus v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Author corpus v1 — twelve contrastive pairs and five scenarios with blinded-reviewer oracles — into one schema-valid ground-truth document, so the framework has something to be evaluated against.

**Architecture:** A candidate generator under `tools/` proposes pairs mechanically from corpus v0's adapter output and writes a JSON artifact; two factors corpus v0 cannot isolate get minimal hand-crafted IaC in a new scan root with its own fixtures; the ground truth itself is authored data validated by S1's committed validator; and the scenario oracles come from a blinded reviewer that never sees the author's orderings. Six gates enforce what the validator does not.

**Tech Stack:** Python 3.12, uv, pytest, ruff, mypy strict. The three pinned scanners (Checkov 3.3.12, Trivy 0.74.0, tfsec 1.28.14) run **once**, over the new authored root only. Windows-native.

**Spec:** `docs/superpowers/specs/2026-09-25-s2-evaluation-corpus-design.md`

## Global Constraints

Copied from the spec's §0.1 and the project's standing rules. Every task's requirements implicitly include this section.

- **Relative claims are primary.** Pairs and scenario orderings carry the prioritization-quality claim. `expected_band` is authored only where genuinely unambiguous, and every such finding also sets `excluded_from_quality_claims: true` so the Q10 threshold sensitivity analysis can exclude it.
- **`defaulted_factors` and `unresolved_factors` are never merged.** Q4's missing-declared-value and Q9's extractor-failure are separate rates forever.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — docstrings, comments, test names, commit messages, and JSON `rationale` strings. **Ten instances were found on the previous branch.** Do not assert how a later sub-project consumes your output: S3b, S4 and S5 do not exist.
- **Corpus v0's fixtures are the experimental control.** `tests/harvest/fixtures/checkov-*.json`, `trivy-*.json` and `tfsec-terraform.json` are **never** re-captured, rewritten or deleted. Task 2 writes only under `tests/harvest/fixtures/authored/`.
- **`eval/` may not import `iacrisk`.** Enforced by `tests/test_architecture.py::test_eval_does_not_import_the_framework`, wholesale. Anything needing the adapters goes in `tools/`.
- **Always `uv run python`** — bare `python` may resolve to a broken Microsoft Store stub on this host.
- **`uv run mypy` takes NO path argument.** A path overrides `[tool.mypy] files` and silently drops the test files.
- **Judge pytest by its exit code, never by grepping for `FAILED`.** This project's `addopts` carry `-q -rs`, under which a failing test prints `F` and a traceback but emits **no line beginning with `FAILED`**. This has already cost two errors here.
- Gates, all must exit 0: `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .` (0 files to reformat), `uv run mypy`. Ruff line-length 100, rules `E,F,I,N,UP,B,SIM,PTH,RUF`. Mypy `strict = true`, tests included.
- **`git commit -m` with a multi-line message breaks in PowerShell 5.1.** Write the message to a file under the session scratchpad and use `git commit -F`.
- **Write files with LF and no BOM:** `path.write_text(text, encoding="utf-8", newline="\n")`.
- **Use Write/Edit, not Bash heredocs, for anything containing backslashes** — the Bash tool strips one backslash level even inside quoted heredocs.
- **Never run `.\tools\bootstrap.ps1`** and never modify `tools/scanners.lock.json`, `tools/bin/`, `tools/cache/`, `tools/resolved.json`, or anything under `corpus/vendor/`.

## Measured facts this plan is built on

All measured through S3a's committed adapters over `tests/harvest/fixtures/` on this host. **Drive every assertion from the fixtures, never from these literals** — a test that restates a number cannot detect it changing.

| Fact | Value |
|---|---|
| same-type combinations considered | 249 |
| with an empty class difference | 129 |
| usable candidates | 120 |
| resource pairs with identical class sets but differing max severity | **0** |
| clean exposure pairs | `aws_security_group.default` vs `.web-node`; `aws_security_group_rule.egress` vs `.ingress` |
| clean encryption pairs | `aws_s3_bucket.logs` against each of `data`, `financials`, `flowbucket`, `operations` |
| factors corpus v0 cannot isolate | **privilege** and **severity** |

## File Structure

| Path | Responsibility | Task |
|---|---|---|
| `tools/paircand/__init__.py` | package marker | 1 |
| `tools/paircand/generate.py` | propose pair candidates; write `artifacts/pair-candidates.json` | 1 |
| `tests/paircand/test_generate.py` | generator tests | 1 |
| `corpus/authored/iam_privilege.tf` | three IAM policies differing in scope alone | 2 |
| `corpus/authored/storage_severity.tf` | resources sharing one class at differing severities | 2 |
| `tools/corpus.lock.json` | declare the authored scan root and its cases | 2 |
| `tests/harvest/fixtures/authored/` | golden scanner JSON for the authored root only | 2 |
| `eval/ground_truth/corpus-v1.json` | the ground-truth document (cases, pairs, scenarios) | 3–6 |
| `tests/test_s2_gates.py` | the six S2 acceptance gates | 7 |
| `CLAUDE.md` | current-state update | 7 |
| `docs/superpowers/specs/2026-09-25-s2-handoff.md` | residual risks for S4/S5 | 7 |

---

### Task 1: The pair-candidate generator

Implements spec §3.

**Files:**
- Create: `tools/paircand/__init__.py`, `tools/paircand/generate.py`
- Create: `tests/paircand/test_generate.py`. **No `__init__.py` under `tests/`** — neither `tests/` nor `tests/harvest/` has one, and adding one would diverge from the existing layout.
- Output: `artifacts/pair-candidates.json`

**Interfaces:**
- Consumes: `iacrisk.scanners.{checkov,trivy,tfsec}` adapters, `iacrisk.input.discover`, `iacrisk.resources.build_index`. This is the **first `tools/ → iacrisk` import** in the repo — deliberate, and the sound direction (`src/ → tools/` stays forbidden).
- Produces: `grouping_type(identity: str, identity_kind: str) -> str`; `enumerate_candidates(findings: Sequence[NormalizedFinding]) -> CandidateReport`; `CandidateReport` frozen dataclass with `considered: int`, `empty_difference: int`, `candidates: tuple[Candidate, ...]`, `clean_severity_pairs: int`; `Candidate` frozen dataclass with `grouping_type: str`, `a: str`, `b: str`, `only_a: tuple[str, ...]`, `only_b: tuple[str, ...]`, `shared: int`; `to_json(report) -> dict[str, object]`; `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing test**

```python
from iacrisk.finding import NormalizedFinding
from tools.paircand.generate import enumerate_candidates, grouping_type

# `tools` is a package at the repository root and `pythonpath = ["src", "."]` in
# pyproject.toml, so this is the same import form `tests/harvest/test_run.py`
# already uses (`from tools.harvest.run import ...`). `tools/paircand/__init__.py`
# is required; a `tests/paircand/__init__.py` is not, and must not be added.


def _f(identity: str, issue_class: str, kind: str = "terraform", severity: int | str = 3):
    return NormalizedFinding(
        scanner="checkov", rule_id="R1", canonical_rule_id="R1", issue_class=issue_class,
        title="t", remediation=None, native_severity=None, severity_level=severity,
        platform="terraform", resource_identity=identity, identity_kind=kind,
        file_path="x.tf", line_range=None, fingerprint=None, context_eligible=True,
    )


def test_differing_class_sets_are_emitted_with_the_difference_in_both_directions() -> None:
    report = enumerate_candidates([
        _f("aws_s3_bucket.a", "storage-encryption-at-rest"),
        _f("aws_s3_bucket.a", "storage-logging-audit"),
        _f("aws_s3_bucket.b", "storage-logging-audit"),
    ])
    assert report.considered == 1
    assert report.empty_difference == 0
    (candidate,) = report.candidates
    assert candidate.grouping_type == "aws_s3_bucket"
    assert candidate.only_a == ("storage-encryption-at-rest",)
    assert candidate.only_b == ()
    assert candidate.shared == 1


def test_identical_class_sets_are_counted_but_not_emitted() -> None:
    report = enumerate_candidates([
        _f("aws_rds_cluster.one", "iam-authentication-controls"),
        _f("aws_rds_cluster.two", "iam-authentication-controls"),
    ])
    assert report.considered == 1
    assert report.empty_difference == 1
    assert report.candidates == ()


def test_resources_of_different_types_are_never_compared() -> None:
    report = enumerate_candidates([
        _f("aws_s3_bucket.a", "storage-logging-audit"),
        _f("aws_vpc.b", "networking-flow-logging"),
    ])
    assert report.considered == 0
    assert report.candidates == ()


def test_clean_severity_pairs_counts_identical_class_sets_with_differing_severity() -> None:
    report = enumerate_candidates([
        _f("aws_s3_bucket.a", "storage-logging-audit", severity=2),
        _f("aws_s3_bucket.b", "storage-logging-audit", severity=4),
    ])
    assert report.clean_severity_pairs == 1


def test_an_unknown_severity_never_counts_toward_a_severity_pair() -> None:
    report = enumerate_candidates([
        _f("aws_s3_bucket.a", "storage-logging-audit", severity="unknown"),
        _f("aws_s3_bucket.b", "storage-logging-audit", severity=4),
    ])
    assert report.clean_severity_pairs == 0


def test_kubernetes_identities_group_by_api_version_and_kind() -> None:
    assert grouping_type("apps/v1/Deployment/default/web", "kubernetes") == "apps/v1/Deployment"
    assert grouping_type("batch/v1/Job/default/j [container=c]", "kubernetes") == "batch/v1/Job"
    assert grouping_type("aws_s3_bucket.data", "terraform") == "aws_s3_bucket"


def test_unresolved_identities_are_excluded_entirely() -> None:
    report = enumerate_candidates([
        _f("<unresolved>", "storage-logging-audit", kind="unresolved"),
        _f("<unresolved>", "storage-encryption-at-rest", kind="unresolved"),
    ])
    assert report.considered == 0
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `uv run pytest tests/paircand/test_generate.py`
Expected: collection error — `ModuleNotFoundError: No module named 'paircand'`. Confirm by **exit code**, not by grepping output.

- [ ] **Step 3: Implement `tools/paircand/generate.py`**

```python
"""Propose contrastive-pair candidates from corpus v0's normalized findings.

A research instrument, beside `tools/harvest/`: outside `src/` because it is not
part of the artifact, and outside `eval/` because `eval/` may not import the
framework it grades (`tests/test_architecture.py`). This is the first
`tools/ -> iacrisk` import in the repository, and the direction is deliberate -
an instrument consuming the artifact. The reverse stays forbidden.

It proposes; it does not judge. There is no class-to-factor mapping in the data
(design spec section 1), so single-factor purity cannot be established here and
is not claimed: the output records exactly which classes differ, and a human
names the factor and argues purity in the pair's rationale.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Sequence

from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.resources import build_index
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"
OUTPUT = REPO_ROOT / "artifacts" / "pair-candidates.json"

PAIRABLE_KINDS = ("terraform", "kubernetes")


@dataclass(frozen=True)
class Candidate:
    """Two same-type resources whose issue-class sets differ, and how they differ."""

    grouping_type: str
    a: str
    b: str
    only_a: tuple[str, ...]
    only_b: tuple[str, ...]
    shared: int


@dataclass(frozen=True)
class CandidateReport:
    """Candidates plus the denominators that make their count interpretable.

    `considered` and `empty_difference` are reported because "120 usable
    candidates" says nothing without how many combinations were examined.
    `clean_severity_pairs` is a deliberate negative: design spec section 1
    measured it at 0, and recomputing it keeps that claim re-derivable rather
    than a one-time observation.
    """

    considered: int
    empty_difference: int
    candidates: tuple[Candidate, ...]
    clean_severity_pairs: int


def grouping_type(identity: str, identity_kind: str) -> str:
    """The bucket two identities must share before they are worth comparing.

    Terraform: the resource type before the first dot. Kubernetes: apiVersion
    plus Kind, which is the identity minus its namespace and name - and any
    `[container=...]` suffix goes with the name.

    A grouping heuristic for *proposal* only. It is never used as an identity
    and never written into ground truth.
    """
    if identity_kind == "terraform":
        return identity.split(".", 1)[0]
    parts = identity.split("/")
    if len(parts) >= 3:
        return "/".join(parts[:-2])
    return identity


def enumerate_candidates(findings: Sequence[NormalizedFinding]) -> CandidateReport:
    """Every same-type resource combination, split into usable and empty-difference."""
    classes: dict[str, set[str]] = defaultdict(set)
    severities: dict[str, set[int]] = defaultdict(set)
    kinds: dict[str, str] = {}
    for finding in findings:
        if finding.identity_kind not in PAIRABLE_KINDS:
            continue
        classes[finding.resource_identity].add(finding.issue_class)
        kinds[finding.resource_identity] = finding.identity_kind
        if isinstance(finding.severity_level, int):
            severities[finding.resource_identity].add(finding.severity_level)

    buckets: dict[str, list[str]] = defaultdict(list)
    for identity, kind in kinds.items():
        buckets[grouping_type(identity, kind)].append(identity)

    considered = 0
    empty_difference = 0
    clean_severity_pairs = 0
    candidates: list[Candidate] = []
    for bucket, identities in sorted(buckets.items()):
        for a, b in combinations(sorted(identities), 2):
            considered += 1
            only_a = classes[a] - classes[b]
            only_b = classes[b] - classes[a]
            if not only_a and not only_b:
                empty_difference += 1
                if severities[a] and severities[b] and max(severities[a]) != max(severities[b]):
                    clean_severity_pairs += 1
                continue
            candidates.append(
                Candidate(
                    grouping_type=bucket,
                    a=a,
                    b=b,
                    only_a=tuple(sorted(only_a)),
                    only_b=tuple(sorted(only_b)),
                    shared=len(classes[a] & classes[b]),
                )
            )
    return CandidateReport(
        considered=considered,
        empty_difference=empty_difference,
        candidates=tuple(candidates),
        clean_severity_pairs=clean_severity_pairs,
    )


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def real_findings() -> list[NormalizedFinding]:
    """The five corpus v0 adapter runs. Scan roots are absolute: `rebase_to_scan_root`
    raises on tfsec's absolute Windows paths when given a relative root.
    """
    index = build_index(discover(KUBERNETES_ROOT))
    findings: list[NormalizedFinding] = []
    for result in (
        CheckovAdapter().parse(_load("checkov-terraform.json"), TERRAFORM_ROOT, None),
        TrivyAdapter().parse(_load("trivy-terraform.json"), TERRAFORM_ROOT, None),
        TfsecAdapter().parse(_load("tfsec-terraform.json"), TERRAFORM_ROOT, None),
        CheckovAdapter().parse(_load("checkov-kubernetes.json"), KUBERNETES_ROOT, index),
        TrivyAdapter().parse(_load("trivy-kubernetes.json"), KUBERNETES_ROOT, index),
    ):
        findings.extend(result.findings)
    return findings


def to_json(report: CandidateReport) -> dict[str, object]:
    """JSON-safe primitives, candidate order preserved."""
    return {
        "schema_version": 1,
        "considered": report.considered,
        "empty_difference": report.empty_difference,
        "usable": len(report.candidates),
        "clean_severity_pairs": report.clean_severity_pairs,
        "candidates": [
            {
                "grouping_type": c.grouping_type,
                "a": c.a,
                "b": c.b,
                "only_a": list(c.only_a),
                "only_b": list(c.only_b),
                "shared": c.shared,
            }
            for c in report.candidates
        ],
    }


def main(argv: list[str] | None = None) -> int:
    report = enumerate_candidates(real_findings())
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(to_json(report), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"considered={report.considered} empty_difference={report.empty_difference} "
        f"usable={len(report.candidates)} clean_severity_pairs={report.clean_severity_pairs}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`tools/paircand/__init__.py` is empty, matching `tools/harvest/`.

- [ ] **Step 4: Run the tests and the real generator**

Run: `uv run pytest tests/paircand/test_generate.py` — expect exit 0.
Run: `uv run python -m tools.paircand.generate`
Expected output exactly: `considered=249 empty_difference=129 usable=120 clean_severity_pairs=0`

**If any of those four numbers differs, stop and report it.** They were measured against these fixtures; a difference means either the generator is wrong or the fixtures changed, and both need a human.

- [ ] **Step 5: Add a real-corpus test** asserting the four figures are **derived**, not restated: run `enumerate_candidates(real_findings())` and assert `considered == empty_difference + usable`, `clean_severity_pairs == 0`, and that at least one candidate has `only_a` and `only_b` both non-empty (a two-directional difference exists, so the both-directions code path is exercised by real data).

- [ ] **Step 6: Gates and commit**

Run all four gates, judging by exit code. Subject: `S2: pair-candidate generator`.

---

### Task 2: Hand-crafted cases for the two factors v0 cannot isolate

Implements spec §4. **This is the only task that runs a scanner.**

**Files:**
- Create: `corpus/authored/iam_privilege.tf`, `corpus/authored/storage_severity.tf`
- Modify: `tools/corpus.lock.json` (add cases)
- Create: `tests/harvest/fixtures/authored/{checkov,trivy,tfsec}-terraform.json`
- Create: `tests/test_authored_corpus.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: the authored scan root `corpus/authored`, and fixtures the later tasks read for expected findings.

**Why three IAM policies and not two:** two pairs per factor is the coverage target, and three cases ordered narrow < moderate < broad give two pairs (narrow/moderate, moderate/broad) from three cases rather than four.

- [ ] **Step 1: Author the IAM privilege cases.** Three `aws_iam_policy` resources differing **only** in the breadth of their policy document — same name shape, same tags, same everything else:

```hcl
resource "aws_iam_policy" "narrow_scope" {
  name   = "s2-narrow-scope"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::s2-fixture-bucket/readonly/*"
    }]
  })
}

resource "aws_iam_policy" "moderate_scope" {
  name   = "s2-moderate-scope"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = "arn:aws:s3:::s2-fixture-bucket/*"
    }]
  })
}

resource "aws_iam_policy" "broad_scope" {
  name   = "s2-broad-scope"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
}
```

- [ ] **Step 2: Author the severity cases.** Two resources of one type whose findings land in **one shared issue class at different severities**. `storage-key-management-cmk` spans severity 2–4 in corpus v0, so target that class:

```hcl
resource "aws_ebs_volume" "unencrypted_scratch" {
  availability_zone = "us-west-2a"
  size              = 1
  encrypted         = false
}

resource "aws_s3_bucket" "no_cmk" {
  bucket = "s2-fixture-no-cmk"
}
```

**These two are a starting point, not a guarantee.** Which rules fire and at what severity is the scanners' decision, and Step 4 is where you find out. If the scan does not produce two findings sharing one issue class at differing severities, adjust the resources and re-scan until it does — the authored case is what is wrong in that situation, never the scanner.

- [ ] **Step 3: Declare the scan root in `tools/corpus.lock.json`.** Append to `cases`, matching the existing records' key order exactly (`id`, `platform`, `category`, `path`, `scan_root`, optional `note`):

```json
{
  "id": "authored-iam-privilege",
  "platform": "terraform",
  "category": "iam",
  "path": "corpus/authored/iam_privilege.tf",
  "scan_root": "corpus/authored",
  "note": "Hand-crafted. Three aws_iam_policy resources differing only in policy breadth. Corpus v0 cannot form a privilege pair: every genuine IAM policy type in it is single-instance (S2 design section 1)."
},
{
  "id": "authored-storage-severity",
  "platform": "terraform",
  "category": "storage",
  "path": "corpus/authored/storage_severity.tf",
  "scan_root": "corpus/authored",
  "note": "Hand-crafted. Corpus v0 has zero resource pairs sharing an identical issue-class set while differing in maximum severity, because severity co-varies with which rule fires (S2 design section 1)."
}
```

Leave the top-level `note` alone; it already says pairs and scenarios are authored in S2.

- [ ] **Step 4: Scan the authored root, and only the authored root.**

Build the invocations with S3a's committed `iacrisk.scanners.invoke`, which resolves binaries from `tools/resolved.json` and never from PATH. Write the raw JSON to `tests/harvest/fixtures/authored/<scanner>-terraform.json`.

**Do not** run `tools/capture_fixtures.ps1` — it overwrites corpus v0's golden fixtures, which are the experimental control. **Do not** run `tools/bootstrap.ps1`. All three scanners apply to Terraform per `tools/scanners.lock.json`'s platform matrix; read it rather than hardcoding the three names.

Expect non-zero exit codes: all three scanners exit non-zero **when they find misconfigurations**, which is the normal path.

- [ ] **Step 5: Write `tests/test_authored_corpus.py`**, asserting against the new fixtures — driven from the fixtures, never restating a literal:

- every authored `aws_iam_policy` resource appears in at least one finding, so no case is silently unscanned;
- the three privilege cases are distinguishable: the set of issue classes or the count of findings differs across `narrow_scope`, `moderate_scope`, `broad_scope`;
- **two findings exist that share one `issue_class` and carry different integer `severity_level`s** — the property the severity pair rests on. Assert the property, not the specific class;
- corpus v0's five fixture files are byte-identical to their committed state (`git diff --quiet -- tests/harvest/fixtures/*.json` equivalent, or compare against `git show HEAD:<path>`). This is the guard that the one scanning task did not touch the control.

- [ ] **Step 6: Gates and commit.** Subject: `S2: hand-crafted privilege and severity cases`.

---

### Task 3: The `cases` array

Implements spec §2. Authored data; the test is the validator.

**Files:**
- Create: `eval/ground_truth/corpus-v1.json`

**Interfaces:**
- Consumes: `artifacts/pair-candidates.json` (Task 1) and the authored fixtures (Task 2).
- Produces: a document with `cases` populated and `contrastive_pairs`/`scenarios` as empty arrays — it must already load through `eval.ground_truth.load_and_validate`.

- [ ] **Step 1: Write the document skeleton with one complete case**, so the shape is unambiguous:

```json
{
  "schema_version": 1,
  "description": "Corpus v1 - contrastive pairs and scenarios. Authored in S2 before any scoring engine existed; see the design spec section 0.",
  "cases": [
    {
      "case_id": "sg-default-low-exposure",
      "platform": "terraform",
      "domain": "networking",
      "source": {
        "repo": "https://github.com/bridgecrewio/terragoat",
        "commit": "729f8da6",
        "path": "terraform/aws/db-app.tf"
      },
      "declared_context": {
        "aws_security_group.default": { "sensitivity": 3, "criticality": 3 }
      },
      "expected": {
        "findings": [
          {
            "resource_identity": "aws_security_group.default",
            "issue_class": "networking-config-hygiene"
          }
        ]
      }
    }
  ],
  "contrastive_pairs": [],
  "scenarios": []
}
```

- [ ] **Step 2: Confirm it validates.** `eval` is a package at the repository root, so import it as one — `tests/test_ground_truth.py` already does:

```
uv run python -c "from pathlib import Path; from eval.ground_truth import load_and_validate; load_and_validate(Path('eval/ground_truth/corpus-v1.json')); print('valid')"
```

Expect `valid`. An empty `contrastive_pairs`/`scenarios` is schema-valid at this point; Task 7's coverage gates are what reject it.

- [ ] **Step 3: Author the remaining cases.** Every `resource_identity` and `issue_class` must be copied from real adapter output — run the adapters and read them, never invent one. Cases needed:

| Cases | For | `source` |
|---|---|---|
| `aws_security_group.default` / `.web-node` | exposure pair 1 | terragoat pin |
| `aws_security_group_rule.egress` / `.ingress` | exposure pair 2 | terragoat pin |
| `aws_s3_bucket.logs` / `.data` | encryption pair 1 | terragoat pin |
| `aws_s3_bucket.logs` / `.financials` | encryption pair 2 | terragoat pin |
| `aws_s3_bucket.financials` twice, `sensitivity` 5 vs 1, `criticality` held equal | sensitivity pair 1 | terragoat pin |
| `aws_s3_bucket.operations` twice, `sensitivity` 4 vs 1, `criticality` held equal | sensitivity pair 2 | terragoat pin |
| `aws_s3_bucket.data` twice, `criticality` 5 vs 1, `sensitivity` held equal | criticality pair 1 | terragoat pin |
| `aws_s3_bucket.data_science` twice, `criticality` 4 vs 1, `sensitivity` held equal | criticality pair 2 | terragoat pin |
| `aws_iam_policy.{narrow,moderate,broad}_scope` | privilege pairs 1–2 | `"hand-crafted"` |
| the two severity resources | severity pairs 1–2 | `"hand-crafted"` |

`aws_s3_bucket.logs` appears in two encryption pairs; one case may serve several pairs, and reusing it is better than authoring near-duplicates.

**The sensitivity and criticality pairs deliberately use the same underlying resource on both sides.** Two cases with distinct `case_id`s point at the same `resource_identity` with the same `expected.findings`, differing *only* in one declared-context value — the other held equal. That is not a mistake to be tidied up: it is the cleanest possible isolation of a declared factor, since the code, the findings and the other five factors are literally identical. The validator forbids `case_high == case_low` (the same **case**), not two cases over one resource.

- [ ] **Step 4: Exercise both explicit-state fields**, which the Task 7 gates require:

- at least one case sets a `declared_context` value to `null` and lists the corresponding factor in that finding's `defaulted_factors` (Q4's missing-declared-value);
- at least one expected finding lists a code-derived factor in `unresolved_factors` (Q9's extractor failure). Choose a resource whose exposure genuinely cannot be resolved from literals — a security group referencing a variable rather than a literal CIDR is the natural case.

These two fields are **never** both used for the same situation. Q4 is an absent declaration; Q9 is a failed extraction.

- [ ] **Step 5: Validate and commit.** Subject: `S2: corpus v1 cases`.

---

### Task 4: The twelve contrastive pairs

Implements spec §3's authored half and §6's coverage target.

**Files:**
- Modify: `eval/ground_truth/corpus-v1.json`

**Interfaces:**
- Consumes: Task 3's `cases`; `artifacts/pair-candidates.json` for each pair's recorded class difference.
- Produces: 12 `contrastive_pairs`, two per `factor_key`.

- [ ] **Step 1: Author one pair completely**, as the template for the rest:

```json
{
  "pair_id": "exposure-security-group",
  "factor_under_test": "exposure",
  "case_high": "sg-web-node-high-exposure",
  "case_low": "sg-default-low-exposure",
  "expected_rank_order": "high_above_low",
  "expected_score_delta_sign": "positive",
  "rationale": "Both are aws_security_group resources sharing networking-config-hygiene. web-node additionally carries networking-ingress-exposure and networking-egress-exposure; default carries neither. Both added classes bear on exposure and nothing else differs, so the pair isolates exposure. Class difference recorded in artifacts/pair-candidates.json; purity is an authored judgement, not a machine-proven property (design spec section 3)."
}
```

`expected_rank_order` and `expected_score_delta_sign` are schema **constants** — `"high_above_low"` and `"positive"`. Authoring a pair means choosing which case is `case_high`, not choosing a direction. Getting the orientation backwards produces a valid document that asserts the opposite of what you mean, and no test can catch it — so state the direction in the `rationale` in words as a cross-check on yourself.

- [ ] **Step 2: Author the remaining eleven.** Two per factor: `severity`, `exposure`, `privilege`, `sensitivity`, `criticality`, `encryption`.

Every `rationale` must name the class difference or the declared-context difference the pair rests on, and say why nothing else differs. A rationale that only restates the factor name is a §G3 defect — it claims purity while showing nothing.

- [ ] **Step 3: Check cross-pair consistency by hand before the gate does.** No single class difference may be cited as evidence for two different factors. If `{networking-egress-exposure}` is the basis of an `exposure` pair, it cannot also be the basis of a `severity` pair.

- [ ] **Step 4: Validate and commit.** Subject: `S2: twelve contrastive pairs`.

---

### Task 5: Scenario orderings — draft for approval

Implements spec §5's authoring half. **This task ends with a checkpoint, not a commit.**

**Files:**
- Create: `.superpowers/sdd/2026-09-25-s2-evaluation-corpus/scenario-drafts.md`

**Interfaces:**
- Consumes: Task 3's `cases`.
- Produces: five drafted scenarios — `scenario_id`, `domain`, `expected_ordering`, `rationale` — **not yet written into the ground-truth document**, and **no `oracle`**.

- [ ] **Step 1: Draft five scenarios**, one per `domain`: `storage`, `networking`, `iam`, `compute`, `containers`. Each orders **≥3 cases across ≥2 tiers**. `expected_ordering` is an array of tiers, highest first; cases within a tier are explicitly unordered, so **use a shared tier when you do not believe in a strict order** rather than inventing one.

```json
{
  "scenario_id": "storage-exposure-over-hygiene",
  "domain": "storage",
  "expected_ordering": [
    ["s3-financials-public-unencrypted"],
    ["s3-data-unencrypted", "s3-logs-encrypted-no-cmk"],
    ["s3-operations-lifecycle-only"]
  ],
  "rationale": "..."
}
```

- [ ] **Step 2: Write each rationale in terms of the rubric's factors**, not in terms of a score. "Public exposure on a bucket holding financial data outranks a missing lifecycle policy" is a rubric argument; "this should score 21" is not, and would couple the oracle to the thresholds the sensitivity analysis moves.

- [ ] **Step 3: STOP and hand the drafts to the controller for user approval.** Ground truth is the dissertation's own yardstick and its author is the student, not an implementer. Do not write these into `corpus-v1.json` and do not run the reviewer. Report the draft file path and stop.

---

### Task 6: The blinded oracle review

Implements spec §5's review half. **The agent doing this task must not be the agent that drafted Task 5.**

**Files:**
- Modify: `eval/ground_truth/corpus-v1.json`
- Create: `.superpowers/sdd/2026-09-25-s2-evaluation-corpus/oracle-review.md`

**Interfaces:**
- Consumes: the user-approved scenarios from Task 5.
- Produces: five `scenarios` each with a complete `oracle`, plus the agreement figures.

- [ ] **Step 1: The reviewer receives**, and receives only: the rubric's six factors with their ranges and level definitions (**not** the per-level `source` attribution strings — `rubric.json` carries `citations_audited: false` and nothing unaudited may influence a judgement that reaches the results); each case's IaC; the scanner findings on it; and the declared context.

**The reviewer must not receive:** the author's `expected_ordering`, the author's `rationale`, or any score. It derives its own tiered ordering from the rubric alone.

- [ ] **Step 2: Record the verdict per scenario** — `agree` when the tiers match exactly, `partial` when the ordering differs but no case moves across more than one tier, `disagree` otherwise. Write `disagreement_note` for anything not `agree`, stating what differed.

```json
"oracle": {
  "author": "Jayathissa E.A.T.N. (258243J)",
  "reviewer": "blinded-reviewer:claude-opus-5 (design section 5)",
  "registered_at": "2026-09-25",
  "reviewer_verdict": "agree"
}
```

`author` and `reviewer` must differ — `eval/ground_truth.py` hard-rejects them being equal with *"the oracle would be reviewing itself"*.

- [ ] **Step 3: Compute and record the agreement figures** in `oracle-review.md`: exact-tier agreement across the five scenarios, and a rank correlation for partial credit. **Report them whatever they say.** A low figure is a finding about the oracle, not a reason to redraft the orderings — redrafting after seeing the reviewer disagree is exactly the contamination the blinding exists to prevent.

- [ ] **Step 4: Apply the pre-registered resolution rule.** The author's ordering stands. Every scenario the reviewer marked `disagree` gets `excluded_from_quality_claims: true` on its cases' expected findings, and the exclusion count is reported. `partial` is reported but not excluded.

- [ ] **Step 5: Validate and commit.** Subject: `S2: scenario oracles and blinded review`.

---

### Task 7: The six gates, CLAUDE.md, and the handoff

Implements spec §6 and §7.

**Files:**
- Create: `tests/test_s2_gates.py`
- Modify: `CLAUDE.md`
- Create: `docs/superpowers/specs/2026-09-25-s2-handoff.md`

- [ ] **Step 1: Write the six gates**, each docstring quoting the gate it closes. Each must cover something S1's validator does **not** — it already enforces unique ids, that pair sides and scenario tiers resolve, `case_high != case_low`, and `author != reviewer`, so do not re-implement those.

1. `eval/ground_truth/corpus-v1.json` loads through the committed `load_and_validate` without error.
2. Every one of the six `factor_key` values is the `factor_under_test` of **≥2** pairs.
3. Every one of the five `domain` values has ≥1 scenario, and every scenario orders ≥3 cases across ≥2 tiers.
4. **No orphan cases** — every `case_id` is referenced by ≥1 pair or scenario. The validator checks references resolve; it does not check the converse.
5. **Cross-pair consistency** — for each mined pair, the recorded class difference is still what the adapters produce; and the relation from class-difference to `factor_under_test` is a **function**. Hand-crafted cases carry `source: "hand-crafted"`; mined ones carry a `{repo, commit, path}` triple.
6. Both `defaulted_factors` and `unresolved_factors` are non-empty on ≥1 expected finding each, and every oracle is complete: `reviewer_verdict` in the enum, `reviewer != author`, `registered_at` parsing as a past date.

**Gate 6 does not assert that `registered_at` predates a scoring artifact.** No scoring module exists, so that comparison would be vacuous — it would pass while proving nothing, which is the defect the previous branch shipped three times. The ordering claim rests on git history and is cited that way; the gate gains the comparison when S4 lands.

- [ ] **Step 2: Confirm each gate can fail.** Every gate describes already-authored data, so none can start red. For each, **mutate the data, confirm the gate fails, revert, confirm it passes, and report both exit codes.** A green suite proves the data passes its gates; only a mutation proves the gates could fail.

- [ ] **Step 3: Update `CLAUDE.md`'s Current state** — S2 complete; S3b and S4 next. Add: the corpus v1 counts (cases, 12 pairs, 5 scenarios); that **privilege and severity are hand-crafted because corpus v0 cannot isolate them**, with the one-line reason for each; that the oracle reviewer is a blinded LLM with agreement reported as a number, and the pre-registered rule that `disagree` scenarios are excluded from the headline figure; and that single-factor purity is an **authored judgement**, not machine-proven, because no class-to-factor mapping exists.

- [ ] **Step 4: Write the handoff**, following `docs/superpowers/specs/2026-09-19-s1-handoff.md`'s shape — numbered risks, each with what it costs if ignored. Carry at least: purity being an authored judgement (spec residual risk 1); the reviewer sharing a model family with the author's tooling; the second fixture directory; that `expected_band` is set only on flagged findings so S4's sensitivity analysis must exclude them; and that S1's rubric citation audit is **still outstanding** and blocks quoting any `source` string.

- [ ] **Step 5: Gates and commit.** Subject: `S2: close the six acceptance gates`.
