"""Walkers turn each scanner's own JSON shape into InventoryRows.

Two layers of test: hand-written minimal documents that pin the contract, and a
golden-fixture test that runs the walkers over the real captured bytes, so schema
drift between pinned versions is caught (PLAN.md risk: scanner schema drift).

Every number and every literal in the golden tables below was measured from
`tests/harvest/fixtures/` and from nothing else; the command that measured them is
named above each table. Where a hand-written document exercises a shape or a value
the corpus does **not** contain, the test says so - `Unobserved:` in its docstring
or beside the literal is the marker - because a test that reads like observed
scanner behaviour and is not is the defect class this module exists to refuse.
**The markers themselves are the index of those cases, not this paragraph.** Grep
for `Unobserved` rather than trusting an enumeration here: a count is one edit away
from being false, which is the same defect in the record that the marker exists to
prevent in the tests. They run from whole document shapes (trivy's null `Results`,
tfsec's null `results`, checkov's single-object document) through single values
(the `UNKNOWN` / `NONE` / `NULL` / `""` / `"   "` severity strings, the `"HIGH"` on
a checkov check, one scanner's id namespace on another's target) to absent keys (a
finding with no severity key, a finding with no path key, a tfsec result with no
`location` object).

Deliberately not asserted here: the manifest-to-fixture correspondence, the byte
sizes, the BOM, and the capture count. `tests/harvest/test_fixtures.py` owns those
and a second copy could disagree with it silently. This module reads the manifest
only to drive its parametrization and to quote `stdout_is_json` /
`stdout_parse_error` in a failure message.
"""

from __future__ import annotations

import json
from collections import Counter
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

# Three of the five golden tables below - `EXPECTED_SEVERITIES`,
# `EXPECTED_DISTINCT_RULE_IDS` and `EXPECTED_ID_PREFIXES` - were measured over the
# committed fixtures, with the walkers under test, by:
#
#   uv run python -c "import collections, json, pathlib; \
#     from tools.harvest.walkers import walk; \
#     [print(p.name, len(r := walk(p.stem.split('-')[0], json.loads(p.read_bytes()), p.stem)), \
#     collections.Counter(x.native_severity for x in r), len({x.rule_id for x in r}), \
#     collections.Counter(x.rule_id.rstrip('0123456789') for x in r)) \
#     for p in sorted(pathlib.Path('tests/harvest/fixtures').iterdir())]"
#
# `EXPECTED_ID_PREFIXES` is keyed by scanner, so it is the union of that scanner's two
# lines. `EXPECTED_TARGET_KINDS` comes from the same walk through `_separator_kind`
# and carries its own note, and `EXPECTED_ROWS` is no longer a total, so it has its
# own command below. Re-run them after touching any walker: a moved field path moves
# a count.

# How many InventoryRows each fixture's bytes produce, cut by the partition the document
# itself declares rather than as one total per fixture. The checkov entries were measured
# with the walker under test, one block at a time, by:
#
#   uv run python -c "import json, pathlib; \
#     from tools.harvest.walkers import walk_checkov; \
#     [print(p.name, {b['check_type']: len(walk_checkov([b], p.stem)) \
#     for b in json.loads(p.read_bytes())}) \
#     for p in sorted(pathlib.Path('tests/harvest/fixtures').glob('checkov-*.json'))]"
#
# The trivy and tfsec entries are the whole-document totals the header's command prints.
# checkov is the only scanner here with a partition to cut: its top-level array is one
# block per framework it detected *inside one scan root* - three over the Terraform root,
# two over the Kubernetes one - so `terraform`/`dockerfile`/`secrets` and
# `kubernetes`/`secrets` are keys the fixture bytes supply, not names invented here.
# trivy's `Results` and tfsec's `results` are single flat arrays, so each has one entry,
# keyed by the array's own name and covering the whole document.
#
# The cut is what buys this table a failure mode of its own, and as a total it had none:
# `Counter(row.native_severity for row in rows)` sums to `len(rows)` by construction, so
# `EXPECTED_SEVERITIES` implied every total below. For checkov it implied it twice over -
# null is checkov's whole severity column, so that Counter is one number wearing a dict.
# Per block, 215/2/4 and 266/2 can move against each other while both the sum and the
# Counter hold, which is exactly the shape of a walker that filtered, doubled or
# misattributed one `check_type`. For trivy and tfsec the implication stands and is left
# standing: one bucket, one number, and no partition in the document to cut it by.
#
# Exact counts, not a lower bound, and not `assert rows` - a walker that returned []
# would satisfy the brief's `for row in rows: assert ...` loop vacuously for all six
# fixtures. tfsec-kubernetes is 0 by measurement, which turns the off-matrix emptiness
# into an asserted fact rather than an accident nobody would notice.
EXPECTED_ROWS: dict[str, dict[str, int]] = {
    "checkov-terraform.json": {"dockerfile": 2, "secrets": 4, "terraform": 215},
    "checkov-kubernetes.json": {"kubernetes": 266, "secrets": 2},
    "trivy-terraform.json": {"Results": 115},
    "trivy-kubernetes.json": {"Results": 332},
    "tfsec-terraform.json": {"results": 119},
    "tfsec-kubernetes.json": {"results": 0},
}


def _findings_blocks(scanner: str, doc: Any) -> dict[str, Any]:
    """The document's own partition of its findings: one walkable sub-document per key.

    checkov's top-level array is one block per detected framework, so each block is a
    one-element array the walker accepts unchanged - that is what makes a per-block row
    count measurable with the real walker rather than with a reimplementation of it.

    Any other scanner gets one bucket holding the whole document, keyed by the name of
    the array its rows come from. That default is deliberate rather than merely
    convenient: a fourth walker arriving with a partition nobody has looked at yet gets
    the weaker single-number expectation and no silent per-block claim, and
    `EXPECTED_ROWS` is compared by equality, so its key has to be written down for the
    test to pass at all.
    """
    if scanner == "checkov":
        # Unobserved: both checkov captures are arrays (`stdout_top_level` in the
        # manifest), and `walk_checkov` itself wraps a bare object - so a non-list here
        # would be a fixture that changed shape, and the KeyError/TypeError that follows
        # is the report.
        return {block["check_type"]: [block] for block in doc}
    return {"Results" if scanner == "trivy" else "results": doc}


# The exact `native_severity` **distribution** each fixture yields - counts, not just
# the vocabulary. A set comparison was the earlier form and it was too weak to be the
# tripwire this file claims: a pin bump that re-rated 30 trivy rules from HIGH to
# MEDIUM moves no row count, no separator kind and no vocabulary, so it passed. The
# distribution is what S0 exists to hand S3 (PLAN.md R3-#4 makes the missing-severity
# *rate* a reported metric), so the counts are what is pinned. Equality still enforces
# the vocabulary as a side effect - "no fixture contains UNKNOWN" fails here the moment
# one does. `None` is checkov's entire column, 221 + 268 = 489 rows, because checkov
# emitted null on all 1600 of its checks; a walker that defaulted an absent severity to
# a level fails here on both checkov fixtures.
EXPECTED_SEVERITIES: dict[str, Counter[str | None]] = {
    "checkov-terraform.json": Counter({None: 221}),
    "checkov-kubernetes.json": Counter({None: 268}),
    "trivy-terraform.json": Counter({"HIGH": 61, "MEDIUM": 26, "LOW": 22, "CRITICAL": 6}),
    "trivy-kubernetes.json": Counter({"LOW": 168, "MEDIUM": 100, "HIGH": 63, "CRITICAL": 1}),
    "tfsec-terraform.json": Counter({"HIGH": 72, "MEDIUM": 21, "LOW": 17, "CRITICAL": 9}),
    "tfsec-kubernetes.json": Counter(),
}

# How many *distinct* rule ids each fixture's rows carry. One integer per fixture, and
# the cheapest thing that notices rule-id membership drift at all: nothing else in this
# module derives an id from fixture bytes, so a re-captured fixture that merged two
# rules, split one in two, or renamed one into an id already present would move no row
# count, no severity count and no separator kind. It moves these. What it still cannot
# see is a change that preserves the count - two rules swapping ids, or a merge and a
# split that net to zero - and, deliberately, no id table is held here: 255 literals
# would couple this suite to bytes Task 8 re-derives for a rule inventory anyway.
EXPECTED_DISTINCT_RULE_IDS: dict[str, int] = {
    "checkov-terraform.json": 98,
    "checkov-kubernetes.json": 30,
    "trivy-terraform.json": 49,
    "trivy-kubernetes.json": 30,
    "tfsec-terraform.json": 48,
    "tfsec-kubernetes.json": 0,
}

# The id-prefix vocabulary each scanner's rows carry, over both of that scanner's
# captures: a rule id with its trailing digit run removed (`_id_prefix`). This is the
# guard for a **re-prefixing**, the most likely id drift here and the one a distinct-id
# count cannot see: `walk_trivy` records that at this pin trivy's ids are *not*
# AVD-prefixed, so if a later pin restores it, all 447 trivy ids change while every
# count in this module holds. Measured, no id in any fixture lacks a trailing digit and
# none is all digits, so every prefix below is a non-empty namespace label.
EXPECTED_ID_PREFIXES: dict[str, set[str]] = {
    "checkov": {"CKV_AWS_", "CKV2_AWS_", "CKV_K8S_", "CKV2_K8S_", "CKV_SECRET_", "CKV_DOCKER_"},
    "trivy": {"AWS-", "DS-", "KSV-"},
    "tfsec": {"AVD-AWS-"},
}

# How many rows' `target` carry which separators, and the table that fails if a walker
# ever starts normalizing a path. Measured on this host: `Path(t).as_posix()` turns
# `\ec2.tf` into `/ec2.tf` and `/batch-check\job.yaml` into `/batch-check/job.yaml`, so
# `backslash-only` and `mixed` collapse into `forward-only` - but **two of the four
# kinds are fixed points, not one**: `forward-only` and `neither` both come back
# byte-identical (`batch-check/job.yaml` and `ec2.tf` do), the empty string being the
# one `neither` value it rewrites, to `.`, and no fixture produces one.
#
# That is a hole in this table, and it is trivy-shaped. `trivy-terraform.json` is
# {neither: 113, forward-only: 2} and `trivy-kubernetes.json` is {forward-only: 332},
# so **all 447 trivy rows sit in the two fixed-point kinds**: a `Path(t).as_posix()`
# planted in `walk_trivy` moves no target, no count, no severity and no kind here. It
# holds tfsec's 119 rows and 485 of checkov's 489 to a verbatim `target` - the other 4
# are `forward-only`, so fixed points as well - but against the very normalization this
# comment names, it holds trivy to nothing. What makes the hole trivy-shaped is that for
# trivy it is *every* row. The only assertion in the module that would notice is
# `test_an_absent_path_key_becomes_an_empty_target_for_every_walker`, and only via
# `Path("").as_posix() == "."` - not through any row a fixture produces. Worth stating
# because trivy is the scanner whose paths a reader is likeliest to assume are already
# normalized: they are, and that is exactly why this table cannot vouch for them.
#
# The three scanners disagree three ways over the same two scan roots, which is the
# whole argument for recording `target` verbatim.
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


def _id_prefix(rule_id: str) -> str:
    """The namespace label of a rule id: the id with its trailing digit run removed.

    `CKV_AWS_18` -> `CKV_AWS_`, `CKV2_K8S_6` -> `CKV2_K8S_`, `AWS-0026` -> `AWS-`,
    `AVD-AWS-0099` -> `AVD-AWS-`. Measured over all 1055 rows: every id ends in a
    digit and none is all digits, so this never returns the whole id and never returns
    `""`. Digits inside an id are safe - the `2` in `CKV2_` and the `8` in `K8S_` are
    followed by a non-digit, so the strip stops before them.
    """
    return rule_id.rstrip("0123456789")


def _levels(counts: Counter[str | None]) -> list[tuple[str | None, int]]:
    """Severity counts ordered by level name, so two failure messages line up by eye."""
    return sorted(counts.items(), key=lambda item: str(item[0]))


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
            "passed_checks": [{"check_id": "CKV_AWS_99", "file_path": "\\x.tf", "resource": "r"}],
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
            "failed_checks": [{"check_id": "CKV_AWS_18", "severity": None, "file_path": "\\s3.tf"}]
        },
    }
    rows = walk("checkov", doc, "tg-aws-s3")
    assert [r.rule_id for r in rows] == ["CKV_AWS_18"]


def test_trivy_misconfigurations_become_rows() -> None:
    """`Results[].Misconfigurations[].ID`, and a `Results` entry with no findings key.

    The ids are the observed ones, and so is each one's severity. **At this pin trivy's
    `ID` is not AVD-prefixed**: measured, the literal `AVD-` appears zero times in
    either trivy fixture and no `AVDID` key appears on any of the 447 records.
    `AWS-0028` occurs twice in `trivy-terraform.json`, on `db-app.tf` and `ec2.tf`,
    both at `HIGH`; `AWS-0026` occurs once, on `ec2.tf`, at `HIGH`; `KSV-0001` occurs
    18 times in `trivy-kubernetes.json`, every one at `MEDIUM`.

    **Unobserved:** this one document merges two captures' namespaces. `AWS-` and
    `KSV-` ids never share a document in the corpus - `trivy-terraform.json` carries
    `AWS-` and `DS-`, `trivy-kubernetes.json` carries `KSV-` and nothing else - and the
    real ids on `resources/Dockerfile` are `DS-0002` and `DS-0026`, not a `KSV-` id.
    The merge is here so one document covers both id shapes; nothing about it is a
    record of what trivy emitted.

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
                    {"ID": "AWS-0026", "Severity": "HIGH", "Status": "FAIL"},
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
    assert [r.native_severity for r in rows] == ["HIGH", "HIGH", "MEDIUM"]
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


def _one_finding(scanner: str, severity: Any, *, omit_path: bool = False) -> Any:
    """A one-finding document for `scanner`; `_ABSENT` omits the severity key entirely.

    Each shape is the minimum the corresponding walker reads, in that scanner's own
    key spelling and nesting - checkov's array of blocks, trivy's `Results` /
    `Misconfigurations`, tfsec's flat `results`. An unrecognized scanner raises
    rather than returning something walkable, so adding a fourth walker without
    adding its document fails loudly instead of silently skipping the matrix.

    `omit_path=True` drops the path key that walker reads - checkov's `file_path`,
    trivy's `Target`, tfsec's `location.filename` - which is the same absent-key
    distinction `_ABSENT` draws for severity, on the other recorded column. In tfsec's
    case the `location` object then keeps the real sibling keys `start_line` and
    `end_line` from the first record of `tfsec-terraform.json`, so it stays present and
    truthy: that isolates the `filename` fallback from the `location` fallback, which
    `test_tfsec_target_is_empty_when_the_location_object_is_absent` covers on its own.
    """
    if scanner == "checkov":
        check: dict[str, Any] = {"check_id": "CKV_AWS_18"}
        if not omit_path:
            check["file_path"] = "\\s3.tf"
        if severity is not _ABSENT:
            check["severity"] = severity
        return [{"check_type": "terraform", "results": {"failed_checks": [check]}}]
    if scanner == "trivy":
        misconf: dict[str, Any] = {"ID": "AWS-0028", "Status": "FAIL"}
        if severity is not _ABSENT:
            misconf["Severity"] = severity
        entry: dict[str, Any] = {"Misconfigurations": [misconf]}
        if not omit_path:
            entry["Target"] = "ec2.tf"
        return {"Results": [entry]}
    if scanner == "tfsec":
        location: dict[str, Any] = {"start_line": 117, "end_line": 134}
        if not omit_path:
            location = {"filename": TFSEC_FILENAME}
        result: dict[str, Any] = {"rule_id": "AVD-AWS-0099", "location": location}
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


@pytest.mark.parametrize("scanner", sorted(WALKERS))
def test_an_absent_path_key_becomes_an_empty_target_for_every_walker(scanner: str) -> None:
    """Unobserved: the path key is present and non-empty on every record in the corpus.

    checkov `file_path` 489/489, trivy `Target` on all 32 `Results` entries, tfsec
    `location.filename` 119/119 - so the `or ""` at each of the four sites in
    `walkers.py` fires on no fixture, and `target == ""` is a state no committed byte
    produces. This is the counterpart of the absent-severity test above: `target` folds
    three document states - key absent, JSON null, blank string - onto `""` exactly as
    `_clean` folds them onto `None`, and until this test existed nothing held the
    walkers to folding them at all.

    `""` rather than `None` and rather than a raise, by ruling: no scanner in this
    corpus has emitted the state, so widening `InventoryRow.target` would push a new
    state through two unwritten tasks to carry it, and a raise would contradict the
    per-element skips the same walkers already use. What this pins is that the row still
    arrives - a walker that dropped the finding, or raised, would be inventing the error
    policy Task 6 deliberately does not have.
    """
    rows = walk(scanner, _one_finding(scanner, None, omit_path=True), "tg-aws-s3")
    assert len(rows) == 1, f"{scanner} dropped a finding that carried no path key"
    assert rows[0].target == "", (
        f"{scanner} turned a path key that was not in the document into {rows[0].target!r}, not ''"
    )


def test_tfsec_target_is_empty_when_the_location_object_is_absent() -> None:
    """Unobserved: `location` is present and non-empty on all 119 tfsec results.

    tfsec is the one walker reading a path two levels down, so it has two fallbacks
    where checkov and trivy have one - `location or {}`, then `filename or ""`. The
    object going missing is therefore a different branch from the filename going
    missing, which the parametrized test above covers for tfsec. Same ruling, same two
    assertions: the result still becomes a row, and its target is `""`.
    """
    doc = {"results": [{"rule_id": "AVD-AWS-0099", "severity": "LOW"}]}
    rows = walk("tfsec", doc, "tg-aws-s3")
    assert len(rows) == 1, "tfsec dropped a result that carried no location object"
    assert rows[0].target == "", f"tfsec invented {rows[0].target!r} for an absent location"
    assert rows[0].rule_id == "AVD-AWS-0099", "the row lost the id the document carried"


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
        f"{scanner} turned severity {value!r} into {rows[0].native_severity!r}, not {expected!r}"
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

    Three golden tables are checked per fixture: the row counts, per block of the
    document's own partition and then summed; the severity **distribution**, a `Counter`
    rather than a vocabulary set, so a level moving from one id to another inside the same
    vocabulary still fails; and the number of distinct rule ids, which moves when ids
    merge or split under an unchanged row count.
    `test_the_rule_id_namespaces_each_scanner_emits` adds a fourth, on the prefix
    vocabulary.

    The row-count table used to be one total per fixture, and this docstring used to
    record that it therefore could not fail alone: `Counter(row.native_severity for row in
    rows)` totals `len(rows)` by construction, so `EXPECTED_SEVERITIES` implied every
    total. Task 8 re-cut it. For checkov's two fixtures the counts are now per
    `check_type` block, so a row migrating between blocks - a walker that filtered,
    doubled or misattributed one framework - fails here while both the sum and the
    `Counter` hold. For trivy and tfsec, single flat arrays with no partition to cut, the
    implication still stands and the table says so.

    The two row assertions are independent of each other as well: the first walks each
    block alone and the second walks the document whole, so a walker that carried state
    across blocks satisfies one and fails the other. The other two pairings are
    independent, measured on `trivy-terraform.json`: re-rating one rule (`AWS-0079`, 9
    rows, HIGH -> MEDIUM) moves only the `Counter` (HIGH 61 -> 52, MEDIUM 26 -> 35), and
    folding one id into another (`AWS-0026` -> `AWS-0028`) moves only the distinct-id
    count (49 -> 48).
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

    expected = EXPECTED_ROWS[name]
    per_block = {
        key: len(walk(scanner, block, case_id))
        for key, block in _findings_blocks(scanner, doc).items()
    }
    assert per_block == expected, (
        f"{scanner} produced {per_block} from {name}, not the {expected} measured at this "
        "pin - a field path has moved, a framework block has, or the fixture has"
    )
    assert len(rows) == sum(expected.values()), (
        f"{scanner} yields {len(rows)} rows walked as one document but "
        f"{sum(expected.values())} walked block by block - the walker is not additive "
        "over the partition it reads"
    )
    for row in rows:
        assert row.rule_id, f"empty rule_id in {name}"
        assert row.scanner == scanner
        assert row.case_id == case_id
    observed = Counter(row.native_severity for row in rows)
    assert observed == EXPECTED_SEVERITIES[name], (
        f"{name} yields severity counts {_levels(observed)}, not the measured "
        f"{_levels(EXPECTED_SEVERITIES[name])}"
    )
    distinct = {row.rule_id for row in rows}
    assert len(distinct) == EXPECTED_DISTINCT_RULE_IDS[name], (
        f"{name} yields {len(distinct)} distinct rule ids across {len(rows)} rows, not the "
        f"{EXPECTED_DISTINCT_RULE_IDS[name]} measured at this pin - two ids merging into one, "
        "or one splitting into two, leaves the row count exactly where it was"
    )


@pytest.mark.parametrize("scanner", sorted(WALKERS))
def test_the_rule_id_namespaces_each_scanner_emits(scanner: str) -> None:
    """The id-namespace vocabulary per scanner, read off both of that scanner's captures.

    Parametrized over the **registry**, like the two absent-key tests above, not over
    `EXPECTED_ID_PREFIXES`. Over the table it would have produced no case at all for a
    fourth walker - a guardrail vanishing exactly when a new scanner arrives; over
    `WALKERS` a missing table entry is a `KeyError` in the body instead. The two sets are
    equal today (`['checkov', 'tfsec', 'trivy']`), so this pins the same three cases.

    The rule id is the join key every later stage matches on, and nothing else in this
    file constrains its *shape*: `EXPECTED_ROWS` counts rows and
    `EXPECTED_DISTINCT_RULE_IDS` counts ids, so a walker that read a different id field,
    or re-prefixed every id it read, moves neither number. Two such changes are one
    rename away in this schema - `long_id` sits beside `rule_id` on all 119 tfsec results
    carrying an identifier from a different namespace
    (`aws-ec2-add-description-to-security-group`), and prefixing trivy's ids with the
    `AVD-` that appears 0 times in either trivy fixture would look like a fix - and both
    land here as a changed prefix set.

    Scanner-wide rather than per-fixture, because `CKV_K8S_` appears in one checkov
    capture and not the other: a per-fixture table would pin which platform was scanned,
    not which namespaces the scanner emits.

    What this cannot see is a swap *within* one namespace. Rewriting `AWS-0026` to
    `AWS-0028` in `walk_trivy` leaves this prefix set and the row count untouched: of the
    golden tables only `EXPECTED_DISTINCT_RULE_IDS` moves (trivy-terraform 49 -> 48), and
    `test_trivy_misconfigurations_become_rows` catches it too only because this file
    happens to hand-write both ids. A pure two-way *exchange* is caught by nothing here -
    measured, swapping `AWS-0030` and `AWS-0042` inside `walk_trivy` fails no test in the
    suite: row count, severity counts, distinct-id count and prefix set all hold. That is
    the acknowledged edge of this tripwire, not an oversight.
    """
    prefixes: set[str] = set()
    seen = 0
    for capture in CAPTURES:
        if capture["scanner"] != scanner:
            continue
        fixture = REPO_ROOT / capture["fixture"]
        rows = walk(scanner, _load(fixture), fixture.stem)
        prefixes.update(_id_prefix(row.rule_id) for row in rows)
        seen += len(rows)
    assert seen, f"no {scanner} rows to read ids from; the captures are {CAPTURE_IDS}"
    assert prefixes == EXPECTED_ID_PREFIXES[scanner], (
        f"{scanner} emits id namespaces {sorted(prefixes)} across {seen} rows, not the "
        f"measured {sorted(EXPECTED_ID_PREFIXES[scanner])}"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_no_walker_normalizes_the_target_it_records(capture: dict[str, Any]) -> None:
    """The separator vocabulary each fixture's rows carry, counted exactly.

    `target` is a verbatim record of what the scanner said, and this is the assertion
    that holds a walker to it. One `Path(t).as_posix()` anywhere in a walker turns
    `\\ec2.tf` into `/ec2.tf` and `/batch-check\\job.yaml` into `/batch-check/job.yaml`
    on this host - measured, that moves **604 of the 1055 rows** the six fixtures
    produce: checkov's 217 backslash-or-mixed terraform rows, its 268 kubernetes rows,
    and tfsec's 119 absolute-native ones. The remaining 451 are `as_posix()` fixed
    points, and they are not all trivy's: trivy's 447 - **every row that walker
    produces** - plus 4 of checkov's. Those 4 are the `forward-only` rows the clause
    above leaves out of `checkov-terraform.json`'s 221, recorded in
    `EXPECTED_TARGET_KINDS` as `forward-only: 4`; they come from checkov's secrets
    framework block, which spells its paths `/ec2.tf` where the same document's terraform
    block spells them `\\ec2.tf`. The consequence stays attached to trivy, because it
    follows from *all* of a walker's rows being fixed points and not from a handful:
    this table cannot vouch for `walk_trivy` at all, which is what the comment above it
    says, while checkov's 4 cost it nothing - the other 217 hold that walker.

    Not the only test such a change fails, and this docstring used to claim it was.
    Measured by planting `Path(...).as_posix()` on `walk_checkov`'s `target` and running
    the suite bare: **6 cases across 5 test functions** fail -
    `test_checkov_failed_checks_become_rows`,
    `test_checkov_accepts_a_list_of_run_documents`,
    `test_an_absent_path_key_becomes_an_empty_target_for_every_walker[checkov]`,
    `test_walk_stamps_the_case_id_it_is_given_without_interpretation`, and this test on
    both checkov captures. What *is* untouched by it is every rule id, every severity
    and every row count - the three golden tables in
    `test_walker_handles_the_real_captured_output` all hold, so this table and the
    hand-written target assertions are the whole of the coverage.

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
