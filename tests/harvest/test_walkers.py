"""Walkers turn each scanner's own JSON shape into InventoryRows.

Two layers of test: hand-written minimal documents that pin the contract, and a
golden-fixture test that runs the walkers over the real captured bytes, so schema
drift between pinned versions is caught (PLAN.md risk: scanner schema drift).

Every number and every literal in the golden tables below was measured from
`tests/harvest/fixtures/` and from nothing else; the command that measured them is
named above each table. Where a hand-written document exercises a shape the corpus
does **not** contain, the test says so - `Unobserved:` in its docstring is the
marker - because a test that reads like observed scanner behaviour and is not is
the defect class this module exists to refuse. The four such cases here are
trivy's null `Results`, tfsec's null `results`, checkov's single-object document,
and the `UNKNOWN` / `NONE` / `NULL` severity strings.

Deliberately not asserted here: the manifest-to-fixture correspondence, the byte
sizes, the BOM, and the capture count. `tests/harvest/test_fixtures.py` owns those
and a second copy could disagree with it silently. This module reads the manifest
only to drive its parametrization and to quote `stdout_is_json` /
`stdout_parse_error` in a failure message.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.harvest.walkers import WALKERS, _clean, walk

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
MANIFEST = REPO_ROOT / "artifacts" / "scanner-behavior.json"
SCANNER_LOCK = REPO_ROOT / "tools" / "scanners.lock.json"


def _load(path: Path) -> Any:
    """Parse from raw bytes, the way a walker's caller will. See test_fixtures.py's `_load`."""
    return json.loads(path.read_bytes())


CAPTURES: tuple[dict[str, Any], ...] = tuple(_load(MANIFEST)["captures"])
CAPTURE_IDS = [f"{c['scanner']}-{c['platform']}" for c in CAPTURES]

# The three golden tables were measured over the committed fixtures, with the
# walkers under test, by:
#
#   uv run python -c "import collections, json, pathlib; \
#     from tools.harvest.walkers import walk; \
#     [print(p.name, len(r := walk(p.stem.split('-')[0], json.loads(p.read_bytes()), p.stem)), \
#     sorted({x.native_severity for x in r}, key=str)) \
#     for p in sorted(pathlib.Path('tests/harvest/fixtures').iterdir())]"
#
# Re-run it after touching any walker: a moved field path moves a count.

# How many InventoryRows each fixture's bytes produce. Exact counts, not a
# lower bound, and not `assert rows` - a walker that returned [] would satisfy the
# brief's `for row in rows: assert ...` loop vacuously for all six fixtures.
# tfsec-kubernetes is 0 by measurement, which turns the off-matrix emptiness into
# an asserted fact rather than an accident nobody would notice.
EXPECTED_ROWS: dict[str, int] = {
    "checkov-terraform.json": 221,
    "checkov-kubernetes.json": 268,
    "trivy-terraform.json": 115,
    "trivy-kubernetes.json": 332,
    "tfsec-terraform.json": 119,
    "tfsec-kubernetes.json": 0,
}

# The complete `native_severity` vocabulary each fixture yields. Set equality, so a
# value arriving that is not listed fails - which is what makes "no fixture contains
# UNKNOWN" a mechanically enforced fact instead of a note in a docstring. `None` is
# checkov's only entry because checkov emitted null on all 1600 of its checks; a
# walker that defaulted an absent severity to a level would fail here on 489 rows.
EXPECTED_SEVERITIES: dict[str, set[str | None]] = {
    "checkov-terraform.json": {None},
    "checkov-kubernetes.json": {None},
    "trivy-terraform.json": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    "trivy-kubernetes.json": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    "tfsec-terraform.json": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    "tfsec-kubernetes.json": set(),
}

# How many rows' `target` carry which separators. This is the table that fails if a
# walker ever starts normalizing a path: on Windows `Path(t).as_posix()` turns
# `\ec2.tf` into `/ec2.tf` and `/batch-check\job.yaml` into `/batch-check/job.yaml`,
# so `backslash-only` and `mixed` both collapse into `forward-only` and `neither`
# (a bare filename) is the only kind a round-trip leaves alone. The three scanners
# disagree three ways over the same two scan roots, which is the whole argument for
# recording `target` verbatim.
EXPECTED_TARGET_KINDS: dict[str, dict[str, int]] = {
    "checkov-terraform.json": {"backslash-only": 215, "mixed": 2, "forward-only": 4},
    "checkov-kubernetes.json": {"mixed": 268},
    "trivy-terraform.json": {"neither": 113, "forward-only": 2},
    "trivy-kubernetes.json": {"forward-only": 332},
    "tfsec-terraform.json": {"backslash-only": 119},
    "tfsec-kubernetes.json": {},
}


def _separator_kind(target: str) -> str:
    """Which separators a target string contains. Substring tests only, no path parsing.

    Deliberately not `Path`-based: the point is to observe the raw string, and any
    path type would answer this question about its own normalization instead.
    """
    has_backslash = "\\" in target
    has_slash = "/" in target
    if has_backslash and has_slash:
        return "mixed"
    if has_backslash:
        return "backslash-only"
    if has_slash:
        return "forward-only"
    return "neither"


def test_unknown_scanner_raises() -> None:
    """KeyError, and a KeyError that says what would have worked.

    `WALKERS[scanner]` alone raises with the bare key as its whole message, which
    tells a caller nothing about the registry it missed. The type is kept so the
    dispatch stays a mapping lookup in spirit; only the message is added to.
    """
    with pytest.raises(KeyError) as excinfo:
        walk("nessus", {}, "case-1")
    message = str(excinfo.value)
    assert "nessus" in message
    for registered in WALKERS:
        assert registered in message, f"the KeyError does not name {registered}: {message}"


def test_every_scanner_in_the_registry_has_a_walker() -> None:
    """The scanner matrix is read from the lockfile, never restated here.

    A second copy of the matrix in test code is a correctness problem, not a style
    one, and the fixtures say why: tfsec over Kubernetes returns exit 0 and a
    well-formed empty result set, with the same 365 stderr bytes as its successful
    Terraform run. Nothing at runtime distinguishes "scanned and clean" from "cannot
    read this platform", so a hardcoded set that drifted from the lockfile would
    produce a silent false negative that no test of scanner *output* could catch.

    This does not contradict `tests/test_scanners_lock.py`, which hardcodes the same
    three names on purpose: its job is to detect the pin changing, so it must not
    read the pin from the file under test. The claim here is different - a
    *correspondence* between the registry and the matrix - and correspondence has to
    read both sides.
    """
    scanners = _load(SCANNER_LOCK)["scanners"]
    # Without this, an emptied lockfile plus an emptied registry would satisfy the
    # set equality below by both sides being empty.
    assert scanners, "tools/scanners.lock.json declares no scanners at all"
    assert set(WALKERS) == set(scanners), (
        f"the walker registry {sorted(WALKERS)} and the pinned scanner matrix "
        f"{sorted(scanners)} disagree"
    )


def test_every_captured_fixture_names_a_scanner_with_a_walker() -> None:
    """The six captures and the registry line up, so the golden test cannot be vacuous.

    An empty `captures` array would make the parametrized golden test collect zero
    cases and report green having walked nothing; the emptiness assertion here is
    what refuses that. The count itself belongs to
    `tests/harvest/test_fixtures.py::test_manifest_and_directory_name_the_same_six_fixtures`
    and is not restated.
    """
    captured = {capture["scanner"] for capture in CAPTURES}
    assert captured, "artifacts/scanner-behavior.json records no captures"
    assert captured <= set(WALKERS), (
        f"captured scanners with no walker: {sorted(captured - set(WALKERS))}"
    )


def test_checkov_failed_checks_become_rows() -> None:
    """Only `failed_checks`, severity untouched, `file_path` byte for byte.

    Both `file_path` values are real strings from `checkov-terraform.json`:
    `\\s3.tf` is what the `terraform` block reports for CKV_AWS_18, and
    `/resources\\Dockerfile` is what the `dockerfile` block of the *same run*
    reports - a mixed-separator path, the shape 1262 of 1262 kubernetes checks
    carry, and the shape a `Path(...).as_posix()` normalization silently rewrites.

    `severity: None` on the first check is the observed case: checkov emitted null
    on all 1600 of its checks at this pin. **Unobserved:** the `"HIGH"` on the
    second. No checkov check in this corpus carries a severity string; that row
    tests `_clean`'s obligation to pass a non-blank value through, not something
    checkov did here.

    `CKV_AWS_99` in `passed_checks` is deliberately an id that appears in no
    fixture. Its only job is to be absent from the result, and a real failed id
    reused there would make the exclusion unobservable.
    """
    doc = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "severity": None,
                    "file_path": "\\s3.tf",
                    "resource": "aws_s3_bucket.data",
                },
                {
                    "check_id": "CKV_AWS_21",
                    "severity": "HIGH",
                    "file_path": "/resources\\Dockerfile",
                    "resource": "aws_s3_bucket.data",
                },
            ],
            "passed_checks": [
                {"check_id": "CKV_AWS_99", "file_path": "\\x.tf", "resource": "r"}
            ],
        },
    }
    rows = walk("checkov", doc, "tg-aws-s3")

    # Pinned first, and as a list: it fixes both the count and the order, so the
    # `all(...)` below cannot pass over an empty sequence.
    assert [r.rule_id for r in rows] == ["CKV_AWS_18", "CKV_AWS_21"], (
        "passed checks are not findings"
    )
    assert rows[0].native_severity is None, "absent severity stays None, never defaulted"
    assert rows[1].native_severity == "HIGH"
    assert rows[0].target == "\\s3.tf", "path separators preserved verbatim"
    assert rows[1].target == "/resources\\Dockerfile", "mixed separators preserved verbatim"
    assert all(r.scanner == "checkov" and r.case_id == "tg-aws-s3" for r in rows)


def test_checkov_accepts_a_list_of_run_documents() -> None:
    """checkov emits a JSON array - one block per framework detected in one scan root.

    Measured: the terraform root produced three blocks (`terraform`, `dockerfile`,
    `secrets`) and the kubernetes root two (`kubernetes`, `secrets`). The document
    below mirrors the terraform capture's block set rather than pairing terraform
    with kubernetes: no capture scanned both roots at once, so the array is not a
    per-platform structure - it is framework detection inside a single root.

    What this pins is that `check_type` is never filtered on. The `dockerfile` and
    `secrets` blocks carry 8 of the 489 failed checks across the two fixtures, and a
    walker that kept only the block matching the platform it thought it had scanned
    would drop them without changing anything a caller could see.

    All three ids and all three `file_path` values are real strings from
    `checkov-terraform.json`.
    """
    doc = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_18",
                        "severity": None,
                        "file_path": "\\s3.tf",
                        "resource": "aws_s3_bucket.data",
                    }
                ]
            },
        },
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_2",
                        "severity": None,
                        "file_path": "/resources\\Dockerfile",
                        "resource": "/resources/Dockerfile.",
                    }
                ]
            },
        },
        {
            "check_type": "secrets",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_SECRET_2",
                        "severity": None,
                        "file_path": "/ec2.tf",
                        "resource": "6b8b0f5b...",
                    }
                ]
            },
        },
    ]
    rows = walk("checkov", doc, "mixed")

    assert [r.rule_id for r in rows] == ["CKV_AWS_18", "CKV_DOCKER_2", "CKV_SECRET_2"], (
        "every framework block is walked, in document order"
    )
    assert [_separator_kind(r.target) for r in rows] == [
        "backslash-only",
        "mixed",
        "forward-only",
    ], "one checkov run spells its paths three different ways; all three are kept as-is"
    assert {r.case_id for r in rows} == {"mixed"}


def test_checkov_also_accepts_a_bare_object_document() -> None:
    """Unobserved: both checkov captures recorded `stdout_top_level: "array"`.

    The single-object branch is defence, not observation. It is tested so that the
    branch is not dead code, and named here so nobody reads it as evidence that
    checkov emitted an object for this corpus - it did not, in either capture.
    """
    doc = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {"check_id": "CKV_AWS_18", "severity": None, "file_path": "\\s3.tf"}
            ]
        },
    }
    rows = walk("checkov", doc, "tg-aws-s3")
    assert [r.rule_id for r in rows] == ["CKV_AWS_18"]


def test_trivy_misconfigurations_become_rows() -> None:
    """`Results[].Misconfigurations[].ID`, and a `Results` entry with no findings key.

    The ids are the observed ones. **At this pin trivy's `ID` is not AVD-prefixed**:
    measured, the literal `AVD-` appears zero times in either trivy fixture and no
    `AVDID` key appears on any of the 447 records. `AWS-0028` is a real terraform id;
    `KSV-0001` is the kubernetes form.

    The second `Results` entry - `"Target": "."` with no `Misconfigurations` key at
    all - is observed, not invented: it is the per-directory summary entry, and its
    two kubernetes counterparts are ordinary manifest targets that simply produced
    nothing.

    `resources/Dockerfile` is trivy's real spelling of the file checkov spells
    `/resources\\Dockerfile`. Both are kept verbatim, which is the disagreement S1
    has to reconcile and this layer must not hide.
    """
    doc = {
        "Results": [
            {
                "Target": "ec2.tf",
                "Misconfigurations": [
                    {"ID": "AWS-0028", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "AWS-0026", "Severity": "LOW", "Status": "FAIL"},
                ],
            },
            {"Target": ".", "MisconfSummary": {"Successes": 66, "Failures": 0}},
            {
                "Target": "resources/Dockerfile",
                "Misconfigurations": [{"ID": "KSV-0001", "Severity": "MEDIUM", "Status": "FAIL"}],
            },
        ]
    }
    rows = walk("trivy", doc, "tg-aws-s3")

    assert [r.rule_id for r in rows] == ["AWS-0028", "AWS-0026", "KSV-0001"], (
        "a Results entry carrying no Misconfigurations key contributes no rows"
    )
    assert [r.native_severity for r in rows] == ["HIGH", "LOW", "MEDIUM"]
    assert rows[0].target == "ec2.tf"
    assert rows[2].target == "resources/Dockerfile"
    assert all(r.scanner == "trivy" and r.case_id == "tg-aws-s3" for r in rows)


def test_trivy_tolerates_a_null_results_key() -> None:
    """Unobserved: `Results` is a populated list in both trivy captures.

    Kept as defence, and labelled rather than dressed up as behaviour: nothing in
    this corpus shows what trivy emits when it finds nothing scannable, so this test
    asserts only that the walker does not raise on either shape. The observed
    zero-finding shape trivy *did* produce is a `Results` entry with no
    `Misconfigurations` key, which `test_trivy_misconfigurations_become_rows` covers.
    """
    assert walk("trivy", {"Results": None}, "empty") == []
    assert walk("trivy", {}, "empty") == []


def test_tfsec_results_become_rows() -> None:
    """`results[].rule_id`, `results[].location.filename`, and never `long_id`.

    The literals are the first record of `tfsec-terraform.json`. Two measured facts
    the shape makes visible:

    `rule_id` is the AVD id `AVD-AWS-0099`; `long_id` is a different identifier in a
    different namespace, `aws-ec2-add-description-to-security-group`. Both are
    present on all 119 results, so the document below carries both and the assertion
    discriminates: a walker falling back to `long_id`, or reading it by mistake,
    fails here rather than quietly filling the `rule_id` column with the other
    namespace at an unchanged row count.

    `location.filename` is an **absolute native path** on all 119 - not the
    scan-root-relative form checkov reports and not trivy's forward slashes. Third
    of three spellings for one scan root, recorded verbatim.
    """
    doc = {
        "results": [
            {
                "rule_id": "AVD-AWS-0099",
                "long_id": "aws-ec2-add-description-to-security-group",
                "severity": "LOW",
                "status": 0,
                "resource": "aws_security_group.default",
                "location": {
                    "filename": "D:\\Research\\corpus\\vendor\\terragoat"
                    "\\terraform\\aws\\db-app.tf",
                    "start_line": 117,
                    "end_line": 134,
                },
            }
        ]
    }
    rows = walk("tfsec", doc, "tg-aws-s3")

    assert len(rows) == 1
    assert rows[0].rule_id == "AVD-AWS-0099", "the rule id is rule_id, never long_id"
    assert rows[0].rule_id != "aws-ec2-add-description-to-security-group"
    assert rows[0].native_severity == "LOW"
    assert rows[0].target == (
        "D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\db-app.tf"
    ), "the absolute native path tfsec reports, unmodified"
    assert rows[0].scanner == "tfsec"
    assert rows[0].case_id == "tg-aws-s3"


def test_tfsec_empty_results_array_is_the_observed_off_platform_shape() -> None:
    """The shape tfsec actually produced over Kubernetes YAML: `{"results": []}`.

    19 bytes, an empty **array** and not null, at exit 0, with the same 365 stderr
    bytes as the Terraform run that found 119 things. That is the whole point: this
    document is indistinguishable from a clean Terraform scan, so "empty" here can
    never be read as "clean" or as "unparseable" - two conditions that must not be
    named as one, because a scanner that cannot read its input looks exactly like a
    scanner with nothing to report.

    This walker's job stops at returning no rows. What stops Kubernetes manifests
    from being routed to tfsec at all is the `platforms` list in
    `tools/scanners.lock.json`, asserted by
    `tests/harvest/test_fixtures.py::test_off_platform_capture_is_empty_exit_zero_and_undeclared`.
    """
    assert walk("tfsec", {"results": []}, "kg-scenarios") == []


def test_tfsec_tolerates_a_null_results_key() -> None:
    """Unobserved: tfsec emitted `{"results": []}`, never null, in either capture.

    Kept as defence against a shape a future pin might produce, and labelled so the
    brief's original claim - that tfsec emits null "on a clean or unparseable target"
    - is not preserved by accident. It emitted an empty array, and the two conditions
    are not one condition.
    """
    assert walk("tfsec", {"results": None}, "empty") == []
    assert walk("tfsec", {}, "empty") == []


# The severity key omitted entirely, as distinct from present-and-null. Only a
# document with the key missing can test the guard `InventoryRow.native_severity`
# hands to this task: "a walker that defaulted an absent severity to LOW would
# still be passing a str", so nothing in the model can catch it and nothing but a
# walker fed key-less JSON can prove it.
_ABSENT = object()

# tfsec's real spelling for one corpus file, reused by the minimal documents below.
TFSEC_FILENAME = "D:\\Research\\corpus\\vendor\\terragoat\\terraform\\aws\\db-app.tf"


def _one_finding(scanner: str, severity: Any) -> Any:
    """A one-finding document for `scanner`; `_ABSENT` omits the severity key entirely.

    Each shape is the minimum the corresponding walker reads, in that scanner's own
    key spelling and nesting - checkov's array of blocks, trivy's `Results` /
    `Misconfigurations`, tfsec's flat `results`. An unrecognized scanner raises
    rather than returning something walkable, so adding a fourth walker without
    adding its document fails loudly instead of silently skipping the matrix.
    """
    if scanner == "checkov":
        check: dict[str, Any] = {"check_id": "CKV_AWS_18", "file_path": "\\s3.tf"}
        if severity is not _ABSENT:
            check["severity"] = severity
        return [{"check_type": "terraform", "results": {"failed_checks": [check]}}]
    if scanner == "trivy":
        misconf: dict[str, Any] = {"ID": "AWS-0028", "Status": "FAIL"}
        if severity is not _ABSENT:
            misconf["Severity"] = severity
        return {"Results": [{"Target": "ec2.tf", "Misconfigurations": [misconf]}]}
    if scanner == "tfsec":
        result: dict[str, Any] = {
            "rule_id": "AVD-AWS-0099",
            "location": {"filename": TFSEC_FILENAME},
        }
        if severity is not _ABSENT:
            result["severity"] = severity
        return {"results": [result]}
    raise AssertionError(f"no minimal document defined for scanner {scanner!r}")


@pytest.mark.parametrize("scanner", sorted(WALKERS))
def test_an_absent_severity_key_becomes_none_for_every_walker(scanner: str) -> None:
    """PLAN.md R3-#4, enforced where it can be: absent severity is None, never a level.

    This is the guard `tools/harvest/model.py` names as Task 6's. The row count is
    asserted first, because a walker that dropped the finding for want of a severity
    would otherwise satisfy an emptiness-tolerant check on the severity itself.
    """
    rows = walk(scanner, _one_finding(scanner, _ABSENT), "tg-aws-s3")
    assert len(rows) == 1, f"{scanner} dropped a finding that carried no severity key"
    assert rows[0].native_severity is None, (
        f"{scanner} substituted {rows[0].native_severity!r} for a severity key that "
        "was not in the document"
    )


# (severity as it appears in the document, what `native_severity` must become).
# `None` -> None and `"UNKNOWN"` -> `"UNKNOWN"` are the two rows that matter: the
# first is what checkov emits on 100% of its checks, and the second is the one the
# brief folded away. Folding it would make *the scanner said UNKNOWN* and *the
# scanner said nothing* the same fact, and S3's normalization spec - not yet
# written - has to be able to score them differently.
SEVERITY_CONTRACT: list[tuple[Any, str | None]] = [
    (None, None),
    ("", None),
    ("   ", None),
    ("UNKNOWN", "UNKNOWN"),
    ("HIGH", "HIGH"),
]


@pytest.mark.parametrize(("value", "expected"), SEVERITY_CONTRACT, ids=repr)
@pytest.mark.parametrize("scanner", sorted(WALKERS))
def test_every_walker_routes_severity_through_the_same_contract(
    scanner: str, value: Any, expected: str | None
) -> None:
    """One severity policy, applied identically by all three walkers.

    **Unobserved:** `""`, `"   "` and `"UNKNOWN"` appear in no severity field of any
    fixture, and `None` appears only in checkov's. The measured vocabulary across all
    1600 checkov checks, 447 trivy misconfigurations and 119 tfsec results is
    null / CRITICAL / HIGH / MEDIUM / LOW and nothing else - `UNKNOWN` included in
    the nothing. This is a contract test over values trivy's own vocabulary permits,
    not a record of anything a scanner did here.
    """
    rows = walk(scanner, _one_finding(scanner, value), "tg-aws-s3")
    assert len(rows) == 1, f"{scanner} dropped a finding whose severity was {value!r}"
    assert rows[0].native_severity == expected, (
        f"{scanner} turned severity {value!r} into {rows[0].native_severity!r}, "
        f"not {expected!r}"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        *SEVERITY_CONTRACT,
        ("\t\n", None),
        ("NONE", "NONE"),
        ("NULL", "NULL"),
        ("unknown", "unknown"),
        (" HIGH ", "HIGH"),
    ],
    ids=repr,
)
def test_clean_folds_absent_and_blank_only(value: Any, expected: str | None) -> None:
    """None means absent or blank. It never means "the scanner said something unhelpful".

    The strings `"UNKNOWN"`, `"NONE"` and `"NULL"` are all preserved: they are things
    a scanner said, and S0's job is to record what was said so S3 can decide what it
    scores. Case is preserved too - `"unknown"` stays lowercase - because normalizing
    case here would be a second undocumented policy in the same function.

    Whitespace-only input is the one string that folds, and ` HIGH ` shows why the
    fold is a strip rather than a special case.
    """
    assert _clean(value) == expected


def test_walk_stamps_the_case_id_it_is_given_without_interpretation() -> None:
    """`walk()` never infers a case from a path; the caller owns attribution.

    The document below carries three findings over two files that belong to two
    *different* corpus cases - `s3.tf` to tg-aws-s3, `ec2.tf` to tg-aws-compute -
    because the four Terraform cases share one `scan_root` and are scanned once
    between them. A single `case_id` that contradicts all three paths is stamped onto
    all three rows anyway, unchanged.

    That is deliberate: rows out of a walker are **not attributed rows**. Attribution
    is the `attribution` rule in `tools/corpus.lock.json`, and it belongs to the task
    that walks the corpus - which has a real problem waiting there. checkov's
    kubernetes `file_path` values carry no corpus prefix at all, so prefix-matching
    them against `corpus/vendor/...` matches none of the 1262.
    """
    doc = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {"check_id": "CKV_AWS_18", "severity": None, "file_path": "\\s3.tf"},
                    {"check_id": "CKV_AWS_21", "severity": None, "file_path": "\\ec2.tf"},
                ]
            },
        },
        {
            "check_type": "secrets",
            "results": {
                "failed_checks": [
                    {"check_id": "CKV_SECRET_2", "severity": None, "file_path": "/ec2.tf"}
                ]
            },
        },
    ]
    rows = walk("checkov", doc, "unattributed")

    assert len(rows) == 3
    assert [r.case_id for r in rows] == ["unattributed"] * 3, (
        "walk() stamps the case_id it was given, whatever the paths say"
    )
    assert {r.target for r in rows} == {"\\s3.tf", "\\ec2.tf", "/ec2.tf"}, (
        "and it does not touch the paths it declined to interpret"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_walker_handles_the_real_captured_output(capture: dict[str, Any]) -> None:
    """Golden fixture: the pinned versions' real bytes must still yield the measured rows.

    The schema-drift tripwire PLAN.md names as the mitigation for scanner
    output-schema change between pinned versions. It **asserts rather than skips** in
    both directions the brief left as `pytest.skip` - an empty fixture and an
    unparseable one are precisely the inputs this test exists to catch, so skipping
    would disarm the tripwire on the only evidence it would ever get. The manifest's
    own verdict is quoted in each failure message, so a real schema drift and a
    corrupted checkout are distinguishable without opening the file.

    The row count is exact, not a floor. The brief's `for row in rows: assert ...`
    passes vacuously over an empty list, which is exactly what a moved field path
    produces - so an unasserted count would have made this test green on the drift it
    was written for.
    """
    name = Path(capture["fixture"]).name
    case_id = Path(capture["fixture"]).stem
    assert name in EXPECTED_ROWS, f"no golden row count recorded for {name}"
    raw = (REPO_ROOT / capture["fixture"]).read_bytes()
    assert raw.strip(), (
        f"{name} is empty or whitespace on disk; the manifest recorded "
        f"stdout_bytes={capture['stdout_bytes']} and "
        f"stdout_is_json={capture['stdout_is_json']}"
    )
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"{name} no longer parses as JSON ({exc}); the manifest recorded "
            f"stdout_is_json={capture['stdout_is_json']} and "
            f"stdout_parse_error={capture['stdout_parse_error']!r}"
        )

    scanner = capture["scanner"]
    rows = walk(scanner, doc, case_id)

    assert len(rows) == EXPECTED_ROWS[name], (
        f"{scanner} produced {len(rows)} rows from {name}, not the "
        f"{EXPECTED_ROWS[name]} measured at this pin - a field path has moved, or the "
        "fixture has"
    )
    for row in rows:
        assert row.rule_id, f"empty rule_id in {name}"
        assert row.scanner == scanner
        assert row.case_id == case_id
    assert {row.native_severity for row in rows} == EXPECTED_SEVERITIES[name], (
        f"{name} yields severities "
        f"{sorted({row.native_severity for row in rows}, key=str)}, not the measured "
        f"{sorted(EXPECTED_SEVERITIES[name], key=str)}"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_no_walker_normalizes_the_target_it_records(capture: dict[str, Any]) -> None:
    """The separator vocabulary each fixture's rows carry, counted exactly.

    `target` is a verbatim record of what the scanner said, and this is the assertion
    that holds a walker to it. One `Path(t).as_posix()` anywhere in a walker turns
    `\\ec2.tf` into `/ec2.tf` and `/batch-check\\job.yaml` into
    `/batch-check/job.yaml` on this host, collapsing 215 + 2 + 268 rows into
    `forward-only` and failing here - and *only* here, because every rule id, every
    severity and every row count would be untouched by it.

    The three scanners spell the same two scan roots three ways: checkov relative with
    a leading separator and mixed separators, trivy relative with forward slashes,
    tfsec absolute with backslashes. Reconciling them is S1's canonical-identity spec;
    keeping the evidence that they need reconciling is this layer's whole
    contribution to it.
    """
    name = Path(capture["fixture"]).name
    assert name in EXPECTED_TARGET_KINDS, f"no golden target shape recorded for {name}"
    doc = _load(REPO_ROOT / capture["fixture"])
    rows = walk(capture["scanner"], doc, Path(capture["fixture"]).stem)

    observed: dict[str, int] = {}
    for row in rows:
        kind = _separator_kind(row.target)
        observed[kind] = observed.get(kind, 0) + 1
    assert observed == EXPECTED_TARGET_KINDS[name], (
        f"{name} target separators are {observed}, not the measured "
        f"{EXPECTED_TARGET_KINDS[name]}; a walker is normalizing a path it was "
        "supposed to record"
    )
