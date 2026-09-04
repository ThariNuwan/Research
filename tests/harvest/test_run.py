"""Orchestration: platform applicability, command construction, attribution, floors.

Every function under test is pure, so none of this needs a scanner installed. The
tests that read `artifacts/` read committed bytes instead - the manifest Task 5
wrote, the fixtures it captured, and the inventory this task emits - so they need no
scanner either.

Numbers here were measured from those committed bytes, never restated from a plan.
The command that measured each table is named above it. Where a document exercises a
shape the corpus does **not** contain, `Unobserved:` marks it, the convention
`tests/harvest/test_walkers.py` established.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.harvest.model import InventoryRow
from tools.harvest.run import (
    NORMALIZATION_RULE,
    UNATTRIBUTED,
    applicable_scanners,
    attribute,
    declared_case_ids,
    match_case,
    normalize_target,
    scan_roots,
    scanner_command,
    with_case_floor,
)
from tools.harvest.walkers import walk

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST = REPO_ROOT / "artifacts" / "scanner-behavior.json"
FIXTURE_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
RAW_DIR = REPO_ROOT / "artifacts" / "raw"
INVENTORY = REPO_ROOT / "artifacts" / "rule-inventory.json"


def _load(path: Path) -> Any:
    """Parse from raw bytes, the way the runner's own reader does. See test_walkers.py."""
    return json.loads(path.read_bytes())


CAPTURES: tuple[dict[str, Any], ...] = tuple(_load(MANIFEST)["captures"])
CAPTURE_IDS = [f"{c['scanner']}-{c['platform']}" for c in CAPTURES]

# Mirrors `tools/scanners.lock.json`'s `platforms` lists rather than reading them:
# a test whose expectation comes from the file its subject reads cannot notice that
# file changing. `tests/test_scanners_lock.py` holds the lockfile itself to these
# same three lists.
LOCK: dict[str, Any] = {
    "scanners": {
        "checkov": {"platforms": ["terraform", "kubernetes"]},
        "trivy": {"platforms": ["terraform", "kubernetes"]},
        "tfsec": {"platforms": ["terraform"]},
    }
}

TERRAFORM_ROOT = "corpus/vendor/terragoat/terraform/aws"
KUBERNETES_ROOT = "corpus/vendor/kubernetes-goat/scenarios"


# The five cases of `tools/corpus.lock.json`, reduced to the three fields
# attribution reads. Four Terraform files sharing one scan root, and one Kubernetes
# directory - which is what makes prefix matching load-bearing for exactly one case.
def _case(case_id: str, platform: str, path: str, scan_root: str) -> dict[str, str]:
    return {"id": case_id, "platform": platform, "path": path, "scan_root": scan_root}


CASES: list[dict[str, str]] = [
    _case("tg-aws-s3", "terraform", f"{TERRAFORM_ROOT}/s3.tf", TERRAFORM_ROOT),
    _case("tg-aws-networking", "terraform", f"{TERRAFORM_ROOT}/elb.tf", TERRAFORM_ROOT),
    _case("tg-aws-iam", "terraform", f"{TERRAFORM_ROOT}/iam.tf", TERRAFORM_ROOT),
    _case("tg-aws-compute", "terraform", f"{TERRAFORM_ROOT}/ec2.tf", TERRAFORM_ROOT),
    _case("kg-scenarios", "kubernetes", KUBERNETES_ROOT, KUBERNETES_ROOT),
]
TERRAFORM_CASES = [case for case in CASES if case["platform"] == "terraform"]
KUBERNETES_CASES = [case for case in CASES if case["platform"] == "kubernetes"]


def test_terraform_uses_all_three_scanners() -> None:
    assert applicable_scanners(LOCK, "terraform") == ["checkov", "tfsec", "trivy"]


def test_kubernetes_excludes_tfsec() -> None:
    """PLAN.md R3-#3: tfsec is Terraform-only. Absence is not a failure."""
    assert applicable_scanners(LOCK, "kubernetes") == ["checkov", "trivy"]


def test_unknown_platform_yields_no_scanners() -> None:
    assert applicable_scanners(LOCK, "cloudformation") == []


def test_applicability_is_data_not_a_branch() -> None:
    """The matrix comes from the lockfile, so a lockfile edit moves the answer.

    A hardcoded `if scanner == "tfsec"` would keep tfsec off Kubernetes no matter
    what the lockfile said, and nothing else in this suite would notice: the three
    tests above assert exactly the answers the real lockfile gives.
    """
    widened = {"scanners": {"tfsec": {"platforms": ["terraform", "kubernetes"]}}}
    assert applicable_scanners(widened, "kubernetes") == ["tfsec"]
    narrowed: dict[str, Any] = {"scanners": {"checkov": {"platforms": []}}}
    assert applicable_scanners(narrowed, "terraform") == []


def test_scanner_with_no_platforms_key_is_applicable_to_nothing() -> None:
    """Unobserved: every scanner in `tools/scanners.lock.json` declares `platforms`."""
    assert applicable_scanners({"scanners": {"nessus": {}}}, "terraform") == []


def test_commands_are_argument_lists_never_shell_strings() -> None:
    """Paths here contain spaces; a shell string would be a quoting bug."""
    for scanner in ("checkov", "trivy", "tfsec"):
        cmd = scanner_command(scanner, "C:\\b\\x.exe", "terraform", "D:\\My Research\\a")
        assert isinstance(cmd, list)
        assert all(isinstance(part, str) for part in cmd)
        assert cmd[0] == "C:\\b\\x.exe"
        assert "D:\\My Research\\a" in cmd


def test_each_command_requests_json() -> None:
    """The proven vectors, not the plan's draft ones.

    checkov takes `--output json`, not `-o json`: `tools/capture_fixtures.ps1` passed
    the long form and `artifacts/scanner-behavior.json` records it, so the short form
    is a spelling no capture ever ran.
    """
    checkov = scanner_command("checkov", "c.exe", "terraform", "t")
    assert "--output" in checkov and "json" in checkov
    trivy = scanner_command("trivy", "t.exe", "terraform", "t")
    assert trivy[1] == "config" and "--format" in trivy and "json" in trivy
    tfsec = scanner_command("tfsec", "s.exe", "terraform", "t")
    assert "--format" in tfsec and "json" in tfsec


def test_the_scan_root_is_the_last_argument() -> None:
    """`tools/capture_fixtures.ps1` appends the root last and checkov's `--directory`
    therefore ends its flag array. A root placed anywhere else would be read as the
    value of whichever flag preceded it."""
    for scanner in ("checkov", "trivy", "tfsec"):
        assert scanner_command(scanner, "x.exe", "terraform", "ROOT")[-1] == "ROOT"


# One flag per scanner that keeps the run offline, so the pinned build decides the
# rules. Dropping any of them makes a scanner fetch remote content mid-run, which
# would put an unpinned rule set into a pinned toolchain's inventory.
OFFLINE_FLAGS = {
    "checkov": "--skip-download",
    "trivy": "--skip-check-update",
    "tfsec": "--no-module-downloads",
}


@pytest.mark.parametrize(("scanner", "flag"), sorted(OFFLINE_FLAGS.items()))
def test_every_scanner_is_told_not_to_fetch_remote_content(scanner: str, flag: str) -> None:
    assert flag in scanner_command(scanner, "x.exe", "terraform", "t")


def test_unknown_scanner_command_raises() -> None:
    with pytest.raises(KeyError):
        scanner_command("nessus", "n.exe", "terraform", "t")


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_command_reproduces_the_argv_task_5_proved(capture: dict[str, Any]) -> None:
    """Every flag, in order, that produced the committed fixtures.

    `artifacts/scanner-behavior.json` records the exact vector each capture ran, with
    the scan root last and this checkout's path replaced by `<repo>`. Comparing the
    whole list rather than probing for flags is what makes a dropped
    `--disable-telemetry` or a reordered `config` fail: six membership assertions
    would all still pass.

    The exe is not in the manifest's `argv` - the manifest records arguments only -
    so it is supplied here and asserted as element 0.
    """
    target = "D:\\anywhere\\a root"
    expected = ["x.exe", *capture["argv"][:-1], target]
    built = scanner_command(capture["scanner"], "x.exe", capture["platform"], target)
    assert built == expected, (
        f"{capture['scanner']} on {capture['platform']} would run {built}, not the "
        f"{expected} that produced {capture['fixture']}"
    )


def test_scan_roots_deduplicate_the_four_terraform_cases() -> None:
    """Five cases, two roots. Scanning per case would count Terraform findings four
    times over - the inflation `tools/corpus.lock.json`'s `attribution` rule forbids
    in writing and `tools/capture_fixtures.ps1` avoids the same way."""
    roots = scan_roots({"cases": CASES})
    assert [(root["platform"], root["scan_root"]) for root in roots] == [
        ("kubernetes", KUBERNETES_ROOT),
        ("terraform", TERRAFORM_ROOT),
    ]
    terraform = next(root for root in roots if root["platform"] == "terraform")
    assert [case["id"] for case in terraform["cases"]] == [
        "tg-aws-compute",
        "tg-aws-iam",
        "tg-aws-networking",
        "tg-aws-s3",
    ]


def test_two_roots_under_one_platform_stay_two_roots() -> None:
    """Unobserved: corpus v0 declares one scan root per platform. Deduplication is on
    the (platform, scan_root) pair, so a second Terraform root would be scanned too
    rather than collapsed into the first."""
    cases = [
        {"id": "a", "platform": "terraform", "path": "x/a.tf", "scan_root": "x"},
        {"id": "b", "platform": "terraform", "path": "y/b.tf", "scan_root": "y"},
    ]
    assert [root["scan_root"] for root in scan_roots({"cases": cases})] == ["x", "y"]


def _row(target: str, scanner: str = "checkov") -> InventoryRow:
    """A row as `walk()` hands it over: `case_id` already the unattributed state."""
    return InventoryRow(
        scanner=scanner,
        rule_id="CKV_AWS_1",
        native_severity=None,
        target=target,
        case_id=UNATTRIBUTED,
    )


# The four path spellings the three scanners actually emit, measured off the six
# fixtures. checkov contradicts itself inside one run - `\ec2.tf` in its `terraform`
# block, `/ec2.tf` in the `secrets` block of the same document - so both spellings
# have to reach the same case.
#
#   uv run python -c "import json, pathlib; \
#     d = json.loads(pathlib.Path('tests/harvest/fixtures/checkov-terraform.json').read_bytes()); \
#     print({b['check_type']: sorted({c['file_path'] for c in b['results']['failed_checks']}) \
#     for b in d})"
SPELLINGS = [
    ("checkov terraform backslash", "\\ec2.tf", TERRAFORM_ROOT, "tg-aws-compute"),
    ("checkov terraform forward slash", "/ec2.tf", TERRAFORM_ROOT, "tg-aws-compute"),
    ("checkov kubernetes mixed", "/batch-check\\job.yaml", KUBERNETES_ROOT, "kg-scenarios"),
    ("trivy root-relative", "s3.tf", TERRAFORM_ROOT, "tg-aws-s3"),
    ("trivy nested", "resources/Dockerfile", TERRAFORM_ROOT, UNATTRIBUTED),
    (
        "tfsec drive-absolute",
        "D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\iam.tf",
        TERRAFORM_ROOT,
        "tg-aws-iam",
    ),
    ("terraform file no case claims", "\\rds.tf", TERRAFORM_ROOT, UNATTRIBUTED),
]


@pytest.mark.parametrize(
    ("target", "scan_root", "expected"),
    [(t, r, e) for _, t, r, e in SPELLINGS],
    ids=[name for name, *_ in SPELLINGS],
)
def test_every_reported_path_spelling_reaches_its_case(
    target: str, scan_root: str, expected: str
) -> None:
    cases = TERRAFORM_CASES if scan_root == TERRAFORM_ROOT else KUBERNETES_CASES
    (row,) = attribute([_row(target)], cases, scan_root)
    assert row.case_id == expected


@pytest.mark.parametrize(
    ("target", "scan_root"),
    [(t, r) for _, t, r, e in SPELLINGS if e != UNATTRIBUTED],
    ids=[name for name, _, _, e in SPELLINGS if e != UNATTRIBUTED],
)
def test_raw_targets_match_nothing_without_the_normalizer(target: str, scan_root: str) -> None:
    """Measured over all six fixtures: 0 of 1055 rows attribute on the raw path.

    Not "most" - none. Every spelling that does reach a case above reaches it only
    through the normalizer, so a prefix match against `corpus/vendor/...` on the
    reported string attributes nothing at all. This is the assertion that fails if
    the normalizer is ever quietly removed as redundant.
    """
    cases = TERRAFORM_CASES if scan_root == TERRAFORM_ROOT else KUBERNETES_CASES
    assert match_case(target, cases) is None


def test_no_path_reports_no_case() -> None:
    """Unobserved: `target == ""` - the walkers' no-path-reported state - is produced
    by no row any fixture yields. An empty path is unattributable, never case one."""
    assert normalize_target("", TERRAFORM_ROOT) == ""
    (row,) = attribute([_row("")], TERRAFORM_CASES, TERRAFORM_ROOT)
    assert row.case_id == UNATTRIBUTED


def test_attribution_rewrites_only_the_case() -> None:
    """`InventoryRow` is frozen, so attribution replaces rows rather than mutating
    them. Every other field has to survive the replacement byte for byte - `target`
    above all, which S1's canonical-identity spec is written from."""
    original = _row("\\s3.tf", scanner="trivy")
    (attributed,) = attribute([original], TERRAFORM_CASES, TERRAFORM_ROOT)
    assert original.case_id == UNATTRIBUTED
    assert attributed.case_id == "tg-aws-s3"
    for field in ("scanner", "rule_id", "native_severity", "target"):
        assert getattr(attributed, field) == getattr(original, field)


def test_a_directory_case_claims_only_paths_under_it() -> None:
    """Prefix matching is on a path boundary, not on a string prefix. Unobserved:
    corpus v0 has no sibling directory sharing a case path's prefix, so nothing in
    the real corpus exercises this - which is why it is asserted rather than left to
    the corpus to reveal."""
    cases = [_case("kg", "kubernetes", "corpus/vendor/kg/scenarios", "corpus/vendor/kg")]
    assert match_case("corpus/vendor/kg/scenarios/a.yaml", cases) == "kg"
    assert match_case("corpus/vendor/kg/scenarios-old/a.yaml", cases) is None


def test_the_most_specific_case_wins() -> None:
    """Unobserved: no row in corpus v0 matches two cases - the four Terraform cases
    are distinct files and the one Kubernetes case is the whole root. A file case
    nested inside a directory case would match both, and the longer path is the
    honest answer; without a tie-break the answer would depend on case order."""
    cases = [
        _case("dir", "kubernetes", KUBERNETES_ROOT, KUBERNETES_ROOT),
        _case("file", "kubernetes", f"{KUBERNETES_ROOT}/batch-check/job.yaml", KUBERNETES_ROOT),
    ]
    assert match_case(f"{KUBERNETES_ROOT}/batch-check/job.yaml", cases) == "file"
    assert match_case(f"{KUBERNETES_ROOT}/other.yaml", cases) == "dir"


def test_declared_cases_come_from_the_platform_matrix() -> None:
    """The case universe per scanner, and the reason it cannot come from the rows.

    tfsec never runs on the Kubernetes root, so `kg-scenarios` is not a case it
    could have found nothing in - it is a case that never ran. Seeding the universe
    from observed rows would report the two as one thing.
    """
    declared = declared_case_ids(LOCK, {"cases": CASES})
    assert declared["tfsec"] == [
        "tg-aws-compute",
        "tg-aws-iam",
        "tg-aws-networking",
        "tg-aws-s3",
    ]
    assert (
        declared["checkov"]
        == declared["trivy"]
        == [
            "kg-scenarios",
            "tg-aws-compute",
            "tg-aws-iam",
            "tg-aws-networking",
            "tg-aws-s3",
        ]
    )


def test_zero_row_case_is_reported_as_zero() -> None:
    """`tally()` builds `cases` from rows, so a case that fired nothing is absent.

    Absent and zero are different claims, and only this layer knows the difference,
    because only this layer reads the declared case list. Remove the floor and this
    assertion fails on the missing key rather than on a wrong count.
    """
    by_scanner = {"tfsec": {"cases": {"tg-aws-s3": 40}}}
    floored = with_case_floor(by_scanner, declared_case_ids(LOCK, {"cases": CASES}))
    assert floored["tfsec"]["cases"] == {
        "tg-aws-compute": 0,
        "tg-aws-iam": 0,
        "tg-aws-networking": 0,
        "tg-aws-s3": 40,
    }


def test_the_floor_never_invents_a_case_the_matrix_excludes() -> None:
    """tfsec on Kubernetes is not a zero, it is a run that the matrix prevented."""
    floored = with_case_floor({"tfsec": {"cases": {}}}, declared_case_ids(LOCK, {"cases": CASES}))
    assert "kg-scenarios" not in floored["tfsec"]["cases"]


def test_the_floor_keeps_the_unattributed_state() -> None:
    """`unattributed` is a state the rows carry, not a declared case. The floor adds
    declared cases and removes nothing, so a count against it has to survive."""
    floored = with_case_floor(
        {"trivy": {"cases": {UNATTRIBUTED: 59, "tg-aws-s3": 1}}},
        declared_case_ids(LOCK, {"cases": CASES}),
    )
    assert floored["trivy"]["cases"][UNATTRIBUTED] == 59
    assert list(floored["trivy"]["cases"]) == sorted(floored["trivy"]["cases"])


def test_a_scanner_the_matrix_does_not_name_keeps_its_own_counts() -> None:
    """Unobserved: every scanner that produces rows is in `tools/scanners.lock.json`.
    The floor is a floor, so an unnamed scanner is left exactly as tallied."""
    floored = with_case_floor({"nessus": {"cases": {"x": 3}}}, {})
    assert floored["nessus"]["cases"] == {"x": 3}


# ---------------------------------------------------------------------------
# The emitted artifact. Committed bytes only - `artifacts/raw/`, the documents this
# task's harvest wrote, against `tests/harvest/fixtures/`, the documents Task 5
# captured, and against the inventory built from them. No scanner runs here.
# ---------------------------------------------------------------------------

ON_MATRIX_RUNS = (
    "checkov-kubernetes",
    "checkov-terraform",
    "tfsec-terraform",
    "trivy-kubernetes",
    "trivy-terraform",
)
OFF_MATRIX_FIXTURE = "tfsec-kubernetes"
VOLATILE_TRIVY_KEYS = ("CreatedAt", "ReportID")


def _canonical(value: Any) -> str:
    """JSON text with every mapping key-sorted and every list sorted by its own text.

    An order-insensitive form, and only order-insensitive: it moves elements, never drops,
    merges or coerces one, so two documents with equal canonical text hold exactly the same
    leaf values in exactly the same structure.
    """

    def rebuild(node: Any) -> Any:
        if isinstance(node, dict):
            return {key: rebuild(node[key]) for key in sorted(node)}
        if isinstance(node, list):
            return sorted((rebuild(item) for item in node), key=lambda item: json.dumps(item))
        return node

    return json.dumps(rebuild(value), sort_keys=True)


def test_raw_output_holds_exactly_the_on_matrix_runs() -> None:
    """Five documents, one per (scanner, platform) the matrix allows - not six, not fourteen.

    `tfsec-kubernetes` is the fixture with no raw counterpart:
    `artifacts/scanner-behavior.json` flags that capture `off_matrix`, so Task 5 recorded
    what a Terraform-only scanner does with Kubernetes input while the harvest never
    dispatches it. Fourteen would mean the runner had gone back to scanning per case.
    """
    assert sorted(path.name for path in RAW_DIR.iterdir()) == [f"{s}.json" for s in ON_MATRIX_RUNS]
    off_matrix = next(c for c in CAPTURES if c["fixture"].endswith(f"{OFF_MATRIX_FIXTURE}.json"))
    assert off_matrix["off_matrix"] is True
    assert not (RAW_DIR / f"{OFF_MATRIX_FIXTURE}.json").exists()


@pytest.mark.parametrize("stem", ON_MATRIX_RUNS)
def test_raw_output_holds_the_same_findings_as_the_fixture(stem: str) -> None:
    """This toolchain reproduces Task 5's evidence - as a multiset, because it must be.

    What the pins are for, tested: `artifacts/raw/` and `tests/harvest/fixtures/` are two
    records of one fact, captured two days apart by two different callers (trivy's
    `CreatedAt` dates them), and nothing else asserts they agree.

    Byte equality is available for **no** scanner here, which is measured rather than
    assumed. Not one leaf value differs; every difference is the order of elements inside a
    list, and the lists it has been seen in are checkov's `failed_checks`, `passed_checks`
    and individual `check_result.evaluated_keys`, trivy's `Results[].Misconfigurations`, and
    tfsec's single `results`. How many reorder varies run to run, which is why no count is
    asserted here and why this comparison is order-insensitive rather than byte-exact.

    tfsec is what settles that. It matched its fixture byte for byte on this harvest's first
    run and permuted five adjacent `AVD-AWS-0038` findings on `eks.tf:118` on the second -
    same 119-element multiset, same byte length - so a byte assertion for tfsec passes or
    fails by luck. `_canonical` moves elements and cannot drop or alter one, which
    `test_the_order_insensitive_comparison_still_catches_a_changed_value` proves rather than
    claims.

    checkov's framework-block order is stable (`terraform`, `dockerfile`, `secrets` both
    times), so the instability is inside the blocks, not between them - the opposite of what
    a reader would guess. trivy's `CreatedAt` and `ReportID` are dropped because they are
    wall-clock and a fresh UUID, and the two sides differ in both. `CreatedAt` is also why
    even byte *length* is not a safe proxy: Go trims trailing zeros from RFC3339Nano
    fractional seconds, so one re-run came back a single byte shorter than its fixture.
    """
    raw = json.loads((RAW_DIR / f"{stem}.json").read_bytes())
    fixture = json.loads((FIXTURE_DIR / f"{stem}.json").read_bytes())
    if isinstance(raw, dict) and isinstance(fixture, dict):
        for key in VOLATILE_TRIVY_KEYS:
            raw.pop(key, None)
            fixture.pop(key, None)
    assert _canonical(raw) == _canonical(fixture)


def test_the_order_insensitive_comparison_still_catches_a_changed_value() -> None:
    """`_canonical` is order-insensitive and nothing else - the guard on the test above.

    That comparison is the only thing tying the committed artifact to Task 5's evidence, and
    it is order-insensitive because no scanner here reproduces its own list order, not to
    make a failing assertion pass. This is the difference, on committed bytes: reversing a
    list must not be visible, while changing one severity string or dropping one finding
    must be. If this test ever passes trivially, the comparison above has stopped testing
    anything.
    """
    fixture = _load(FIXTURE_DIR / "tfsec-terraform.json")
    findings = fixture["results"]
    assert len(findings) > 1

    assert _canonical({"results": list(reversed(findings))}) == _canonical(fixture)
    assert _canonical({"results": findings[:-1]}) != _canonical(fixture)

    mutated = json.loads(json.dumps(fixture))
    mutated["results"][0]["severity"] = "UNOBSERVED"
    assert _canonical(mutated) != _canonical(fixture)


def test_the_inventory_reproduces_the_row_counts_the_fixtures_yield() -> None:
    """The deliverable's headline numbers, re-derived from the fixtures through the walkers.

    Both sides are committed bytes, so this is reproducible without a scanner, and it ties
    the artifact to the evidence rather than to itself. Measured across the five on-matrix
    documents: 1055 rows, 789 attributed, 266 unattributed - `kg-scenarios` 600,
    `tg-aws-s3` 103, `tg-aws-compute` 67, `tg-aws-iam` 14, `tg-aws-networking` 5. The
    off-matrix `tfsec-kubernetes` fixture is left out because the harvest never dispatches
    it; it yields 0 rows either way, so including it would hide rather than test that.

    `tg-aws-networking` at 5 is the corpus's thinnest legitimate case, not a defect: `elb.tf`
    is the only networking-only file at this pin, which `tools/corpus.lock.json` records in
    the case's own note. A gate that demanded a round number here would fail the corpus.
    """
    counts: dict[str, int] = {}
    for stem in ON_MATRIX_RUNS:
        scanner, platform = stem.split("-", 1)
        cases = TERRAFORM_CASES if platform == "terraform" else KUBERNETES_CASES
        scan_root = TERRAFORM_ROOT if platform == "terraform" else KUBERNETES_ROOT
        rows = walk(scanner, _load(FIXTURE_DIR / f"{stem}.json"), UNATTRIBUTED)
        for row in attribute(rows, cases, scan_root):
            counts[row.case_id] = counts.get(row.case_id, 0) + 1

    inventory = _load(INVENTORY)
    attribution = inventory["corpus"]["attribution"]
    assert attribution["rows_per_case"] == {
        case_id: count for case_id, count in sorted(counts.items()) if case_id != UNATTRIBUTED
    }
    assert attribution["unattributed_rows"] == counts[UNATTRIBUTED]
    assert attribution["attributed_rows"] == sum(counts.values()) - counts[UNATTRIBUTED]
    assert inventory["totals"]["rows"] == sum(counts.values())
    assert attribution["normalization_rule"] == NORMALIZATION_RULE


def test_the_inventory_case_universe_comes_from_the_matrix() -> None:
    """Every declared case present per scanner, and no case the matrix excludes.

    Two claims, and the second is the one that is easy to get wrong. tfsec's `cases` holds
    the four Terraform cases and **not** `kg-scenarios`: on this corpus every declared
    (scanner, case) pair produces rows, so the floor adds nothing here and only the unit test
    above can catch its removal - but a universe seeded from rows would look identical while
    being one edit away from reporting `kg-scenarios` as a case tfsec ran and found nothing
    in. It is a case tfsec never saw.

    `unattributed` is present as well, and is not a declared case: it is the state the rows
    carry, counted beside them as `tools/corpus.lock.json`'s `attribution` rule requires.
    """
    inventory = _load(INVENTORY)
    declared = declared_case_ids(LOCK, {"cases": CASES})
    for scanner, entry in inventory["by_scanner"].items():
        assert set(entry["cases"]) - {UNATTRIBUTED} == set(declared[scanner]), scanner
    assert "kg-scenarios" not in inventory["by_scanner"]["tfsec"]["cases"]
    assert inventory["by_scanner"]["tfsec"]["cases"][UNATTRIBUTED] == 52


def test_every_run_is_recorded_with_the_exit_code_task_5_measured() -> None:
    """One record per dispatched run, and a non-zero exit is data rather than a failure.

    checkov and tfsec exit 1 because they have findings; trivy exits 0 while carrying 447 of
    them. Comparing against `artifacts/scanner-behavior.json` rather than against literals
    keeps this a cross-check between two independent runs of the same pinned build.

    `error` absent on every record is the assertion that a timeout or a non-JSON document
    cannot pass silently: `harvest()` records one and keeps going, so the artifact is the
    only place that would show it.
    """
    inventory = _load(INVENTORY)
    runs = {f"{r['scanner']}-{r['platform']}": r for r in inventory["runs"]}
    assert sorted(runs) == list(ON_MATRIX_RUNS)
    for capture in CAPTURES:
        stem = f"{capture['scanner']}-{capture['platform']}"
        if stem not in runs:
            continue
        assert runs[stem]["exit_code"] == capture["exit_code"], stem
        assert "error" not in runs[stem], runs[stem].get("error")
        assert runs[stem]["argv"] == [*capture["argv"][:-1], f"<repo>/{runs[stem]['scan_root']}"]
        assert str(REPO_ROOT) not in json.dumps(runs[stem])
    assert sum(record["rows"] for record in inventory["runs"]) == inventory["totals"]["rows"]
