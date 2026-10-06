"""The one wiring for corpus v0's five real scanner runs (whole-branch review, Finding 4).

`test_dedupe.py`, `test_report.py` and `test_s3a_gates.py` each specified the
identical five `(adapter, fixture, scan-root, index)` tuples independently,
with nothing enforcing that they stayed identical. Edit one copy - add a
sixth run, or wire the Kubernetes index into the wrong run - and the other two
keep measuring a different corpus while all three stay green, so the branch's
headline numbers (1055 findings / 39 Tier-1 collapsed / 207 Tier-2 candidates)
would then depend on which module happened to produce them. This module is
the one place the wiring lives now; `tests/test_corpus_wiring.py::
test_pinned_run_set` is what makes adding a sixth run a deliberate, visible
edit to `RUN_KEYS` rather than a silent one.

Deliberately not a `conftest.py` and deliberately not pytest fixtures: the
three importing modules call these as plain functions, some from inside their
own further-derived helpers (`real_dedupe`, `real_report`), which fixture
injection does not compose with as directly, and each importer wants a
different subset. A leading underscore keeps pytest's default `python_files`
glob (`test_*.py`, `*_test.py`) from collecting this module as a test file of
its own - it carries no tests; `test_corpus_wiring.py` does.

**What stays duplicated on purpose.** The independent raw-record-count
oracles each of the three modules builds by walking the raw fixture JSON
directly (`_raw_checkov_record_count` and its siblings) are NOT moved here.
`tests/test_s3a_gates.py`'s own module docstring states why: each test module
owns its own oracle, so a bug shared between the code under test and one
common oracle cannot mark its own homework across all three at once. Only the
*wiring that produces the input* to those oracles - which adapter, which
fixture, which scan root, which resource index - is the demonstrated hazard
this module closes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iacrisk.dedupe import DedupeResult, deduplicate
from iacrisk.finding import NormalizedFinding
from iacrisk.input import discover
from iacrisk.report import RetentionReport, build_report
from iacrisk.resources import ResourceIndex, build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.checkov import CheckovAdapter
from iacrisk.scanners.tfsec import TfsecAdapter, capture_scan_root
from iacrisk.scanners.trivy import TrivyAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"

RUN_KEYS: tuple[tuple[str, str], ...] = (
    ("checkov", "terraform"),
    ("checkov", "kubernetes"),
    ("trivy", "terraform"),
    ("trivy", "kubernetes"),
    ("tfsec", "terraform"),
)
"""The exact five `(scanner, platform)` runs corpus v0's headline numbers are
measured over. `tests/test_corpus_wiring.py::test_pinned_run_set` pins this
against `real_results()`'s own keys, so a sixth run added to one but not the
other is a failing test rather than a silent divergence."""


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def kubernetes_index() -> ResourceIndex:
    return build_index(discover(KUBERNETES_SCAN_ROOT))


def real_results() -> dict[tuple[str, str], AdapterResult]:
    """The five real adapter runs over the golden fixtures - the one wiring
    every corpus-v0 headline figure this branch reports is measured against.
    """
    index = kubernetes_index()
    # tfsec alone reports absolute paths, so its fixture replays against the root it was
    # captured under rather than wherever this checkout lives (`capture_scan_root`).
    tfsec = load_fixture("tfsec-terraform.json")
    return {
        ("checkov", "terraform"): CheckovAdapter().parse(
            load_fixture("checkov-terraform.json"), TERRAFORM_SCAN_ROOT, None
        ),
        ("checkov", "kubernetes"): CheckovAdapter().parse(
            load_fixture("checkov-kubernetes.json"), KUBERNETES_SCAN_ROOT, index
        ),
        ("trivy", "terraform"): TrivyAdapter().parse(
            load_fixture("trivy-terraform.json"), TERRAFORM_SCAN_ROOT, None
        ),
        ("trivy", "kubernetes"): TrivyAdapter().parse(
            load_fixture("trivy-kubernetes.json"), KUBERNETES_SCAN_ROOT, index
        ),
        ("tfsec", "terraform"): TfsecAdapter().parse(
            tfsec, capture_scan_root(tfsec, TERRAFORM_SCAN_ROOT, REPO_ROOT), None
        ),
    }


def real_unparseable() -> frozenset[str]:
    """The scan-root-relative unparseable path set a real caller already has
    from `ResourceIndex.unparseable` (and `DiscoveryResult.unparseable` for
    the terraform root, empty in corpus v0 but unioned in for generality).
    """
    return frozenset(kubernetes_index().unparseable) | frozenset(
        discover(TERRAFORM_SCAN_ROOT).unparseable
    )


def all_real_findings() -> list[NormalizedFinding]:
    """Every `NormalizedFinding` the three adapters produce over all five
    golden fixture captures, pooled into one list the way a real pipeline
    run would feed `deduplicate`.
    """
    findings: list[NormalizedFinding] = []
    for result in real_results().values():
        findings.extend(result.findings)
    return findings


def real_dedupe() -> DedupeResult:
    return deduplicate(all_real_findings())


def real_report() -> RetentionReport:
    return build_report(real_results(), real_dedupe(), real_unparseable())
