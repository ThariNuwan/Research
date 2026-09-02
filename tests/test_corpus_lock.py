"""Corpus v0 must be pinned, licensed, and span all five tested categories.

Structurally a sibling of `tests/test_scanners_lock.py`, and split the way that
file's review demanded: assertions that check the lockfile's *shape* - it carries
the fields `tools/vendor_corpus.ps1` reads - are kept apart from assertions that
check its *content* - the pins are the values the plan fixed, every case path
exists on disk, and the upstream license text really is vendored beside each
tree. Shape alone would let a wrong pin or an unvendored license pass green.

Two properties of the `cases` array are asserted here rather than left for a
consumer to discover: every case's `path` lies inside its own `scan_root`, and the
four Terraform cases share one scan root. The lockfile's `attribution` paragraph
is the rule that makes that collapse safe to consume - scan each root once,
attribute by `path`, and give a finding under no case's path an explicit
`unattributed` state.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "tools" / "corpus.lock.json"
VENDOR_DIR = REPO_ROOT / "corpus" / "vendor"
SOURCES_MD = VENDOR_DIR / "SOURCES.md"
VENDOR_SCRIPT = REPO_ROOT / "tools" / "vendor_corpus.ps1"

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DRIVE_RE = re.compile(r"^[A-Za-z]:")
UTF8_BOM = b"\xef\xbb\xbf"
CATEGORIES = {"storage", "networking", "iam", "compute", "containers"}

# The scan root the four Terraform cases share, and how many of them there are,
# as module-level literals for the same reason `EXPECTED_CASE_IDS` is one: a count
# derived from `cases` agrees with an emptied `cases` array.
#
# The collapse is a property of upstream's layout, not a mistake: all four files
# live in one directory and `elb.tf` references `aws_subnet.web_subnet`,
# `aws_security_group.web-node` and `aws_instance.web_host` from `ec2.tf`, so the
# directory is the unit that actually resolves. The lockfile's `attribution` rule
# is what makes that safe to consume; these assertions pin the fact it rests on.
TERRAFORM_SCAN_ROOT = "corpus/vendor/terragoat/terraform/aws"
TERRAFORM_CASE_COUNT = 4
# `.tf` files in that scan root at this pin: fourteen, not four. Ten are named by
# no case at all, which is why the attribution rule needs an explicit
# `unattributed` state rather than a default category.
TERRAFORM_SCAN_ROOT_TF_FILES = 14

# What the *declared* license's text must contain. Keyed by the lockfile's license
# string so a tree that ships the wrong license file fails, not merely one that
# ships no license file: a zero-byte `LICENSE` satisfies `is_file()`, and an
# Apache tree carrying MIT text satisfies every other assertion here.
LICENSE_TEXT_MARKERS = {
    "Apache-2.0": ("Apache License", "Version 2.0"),
    "MIT": ("Permission is hereby granted, free of charge",),
}
# Both real files are far above this (11 357 B Apache, 1 068 B MIT). The floor is
# not a size check on a known file; it is the assertion that *some* text is there.
LICENSE_MIN_BYTES = 500

# The file extensions each platform's scanners can read. tfsec is Terraform-only
# and Trivy/Checkov read manifests, so a `.tf` case declared `kubernetes` (or the
# reverse) would be handed to a tool that cannot parse it.
PLATFORM_SUFFIXES = {
    "terraform": {".tf"},
    "kubernetes": {".yaml", ".yml"},
}

# `$LicenseCandidates` as `tools/vendor_corpus.ps1` declares it. Parsed out of the
# script rather than trusted to stay in step by hand: adding `LICENCE` to the
# script would otherwise leave `LICENSE_CANDIDATES` below silently stale.
PS_LICENSE_CANDIDATES_RE = re.compile(r"^\$LicenseCandidates\s*=\s*@\(([^)]*)\)", re.MULTILINE)
PS_SINGLE_QUOTED_RE = re.compile(r"'([^']+)'")

# The pins from the plan's Global Constraints, hardcoded for the same reason
# `tests/test_scanners_lock.py:32` hardcodes the scanner digests: this test's job
# is to detect the pin *changing*, so it must not read the pin from the file it
# is checking. A well-formed but wrong SHA passes `SHA1_RE` and then vendors a
# different tree than the dissertation cites.
EXPECTED_COMMITS = {
    "terragoat": "729f8da62c6a85ce4af5ad3d123de97776d954c4",
    "kubernetes-goat": "723a0db478f050d173d23b4ce5044b65bce0bdd0",
}

# Redistribution terms. A silently changed value here would misstate the license
# under which this repository ships third-party code.
EXPECTED_LICENSES = {"terragoat": "Apache-2.0", "kubernetes-goat": "MIT"}

# Population floor. A module-level literal, NOT derived from the lockfile: every
# test below that loops over `cases` passes trivially on an empty array, so
# without this the four loop guards would all report green having checked
# nothing. Same instrument as `RELEASE_SCANNERS` at
# `tests/test_scanners_lock.py:23`.
EXPECTED_CASE_IDS = {
    "tg-aws-s3",
    "tg-aws-networking",
    "tg-aws-iam",
    "tg-aws-compute",
    "kg-scenarios",
}

# Every field `tools/vendor_corpus.ps1` reads out of a source entry.
# `Set-StrictMode -Version Latest` turns a dropped field into a runtime throw,
# but on the next machine to vendor rather than here where it belongs.
REQUIRED_SOURCE_FIELDS = (
    "url",
    "commit",
    "ref",
    "license",
    "retrieved_utc",
    "pin_verified_utc",
    "subtree",
)

# The candidates `tools/vendor_corpus.ps1` searches, in order. It matches them
# case-insensitively against the real filenames in the clone root and vendors the
# name it actually found.
LICENSE_CANDIDATES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md")

# The date the two commit pins were checked against upstream, recorded separately
# from `retrieved_utc` (the date the trees were actually vendored) so that neither
# field describes an event that did not happen.
PIN_VERIFIED_UTC = "2026-08-24"


def _lock() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(LOCK.read_text(encoding="utf-8"))
    return data


def test_sources_pinned_to_a_commit_and_licensed() -> None:
    sources = _lock()["sources"]
    assert set(sources) == {"terragoat", "kubernetes-goat"}
    for name, entry in sources.items():
        assert SHA1_RE.match(entry["commit"]), f"{name} commit is not a full SHA"
        assert entry["license"], f"{name} license not recorded"
        assert entry["url"].startswith("https://github.com/"), f"{name} url"


def test_sources_pin_the_exact_commits_and_licenses_the_plan_fixed() -> None:
    """Content, not shape: `SHA1_RE` accepts any forty hex digits.

    The commit is what makes the corpus reproducible and is copied into the
    dissertation's provenance block, so a changed pin must fail here rather than
    quietly vendor a different tree than the one cited.
    """
    sources = _lock()["sources"]
    for name, commit in EXPECTED_COMMITS.items():
        assert sources[name]["commit"] == commit, (
            f"{name} is pinned to {sources[name]['commit']!r}, not to the plan's "
            f"{commit!r}; re-verify against upstream before changing this literal"
        )
        assert sources[name]["license"] == EXPECTED_LICENSES[name], (
            f"{name} license is {sources[name]['license']!r}, expected "
            f"{EXPECTED_LICENSES[name]!r}"
        )


def test_source_entries_declare_every_field_the_vendor_script_reads() -> None:
    """`vendor_corpus.ps1` hard-depends on seven fields; assert all seven.

    Mirrors `test_checkov_entry_declares_the_uv_tool_launcher_contract`
    (`tests/test_scanners_lock.py:141`): a dropped field throws at vendoring time
    on the next machine instead of failing here, where it belongs.

    `pin_verified_utc` is asserted by value and `retrieved_utc` only by shape and
    ordering, because the latter legitimately changes every time the corpus is
    re-vendored. The ordering clause is the content half: a retrieval cannot
    precede the pin verification the plan recorded.

    Carries its own floor: this loop is satisfied by `"sources": {}` and the set
    comparison that would refuse that lives in another test.
    """
    checked: set[str] = set()
    for name, entry in _lock()["sources"].items():
        for field in REQUIRED_SOURCE_FIELDS:
            assert field in entry, f"{name} entry has no {field!r}"
            assert entry[field], f"{name} {field} is empty"
        for field in ("retrieved_utc", "pin_verified_utc"):
            assert ISO_DATE_RE.match(entry[field]), f"{name} {field} is not an ISO date"
        assert entry["pin_verified_utc"] == PIN_VERIFIED_UTC, (
            f"{name} pin_verified_utc is {entry['pin_verified_utc']!r}, expected "
            f"{PIN_VERIFIED_UTC!r}"
        )
        assert date.fromisoformat(entry["retrieved_utc"]) >= date.fromisoformat(
            entry["pin_verified_utc"]
        ), f"{name} retrieved_utc precedes pin_verified_utc, which cannot have happened"
        checked.add(name)
    assert checked == set(EXPECTED_COMMITS), (
        f"checked source entries {sorted(checked)}, expected {sorted(EXPECTED_COMMITS)}"
    )


def test_cases_declare_a_platform_and_category() -> None:
    """Shape: the fields exist, are non-empty, and are repo-relative POSIX paths.

    Carries its own population floor. `test_every_expected_case_is_present` is the
    test that *names* a missing id, but a floor in another function does not stop
    this loop from reporting green over `"cases": []` - which is how
    `tests/test_scanners_lock.py:86` and `:116` came to keep their floors inside
    the looping test.
    """
    checked: set[str] = set()
    for case in _lock()["cases"]:
        assert case["platform"] in {"terraform", "kubernetes"}
        assert case["category"] in CATEGORIES, f"{case['id']} bad category"
        for field in ("path", "scan_root"):
            assert field in case, f"{case['id']} has no {field!r}"
            value = case[field]
            assert value, f"{case['id']} {field} is empty"
            # Repo-relative forward-slash, so `REPO_ROOT / value` means the same
            # thing on every host and cannot escape the repository.
            assert "\\" not in value, f"{case['id']} {field} must use forward slashes: {value!r}"
            assert not value.startswith("/"), f"{case['id']} {field} is absolute: {value!r}"
            assert not DRIVE_RE.match(value), f"{case['id']} {field} is absolute: {value!r}"
            assert ".." not in value.split("/"), f"{case['id']} {field} escapes upward: {value!r}"
        checked.add(case["id"])
    assert checked >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - checked)}, so "
        "the loop above checked nothing for them"
    )


def test_every_expected_case_is_present() -> None:
    """The population floor the four loop guards in this file rest on.

    Compared against `EXPECTED_CASE_IDS`, a literal. A set derived from the
    lockfile cannot detect the lockfile losing an entry, and an empty `cases`
    array satisfies every loop guard here by absence.
    """
    ids = {case["id"] for case in _lock()["cases"]}
    assert ids >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - ids)}; "
        "the loop guards in this file pass vacuously without them"
    )


def test_case_ids_are_unique() -> None:
    ids = [c["id"] for c in _lock()["cases"]]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    # `0 == 0` holds on an empty array, so this test needs the floor too, not only
    # `test_every_expected_case_is_present`.
    assert set(ids) >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - set(ids))}; "
        "uniqueness over an empty array is vacuous"
    )


def test_all_five_categories_are_represented() -> None:
    """PLAN.md Q6 requires coverage across all five domains."""
    covered = {c["category"] for c in _lock()["cases"]}
    assert covered == CATEGORIES, f"missing categories: {sorted(CATEGORIES - covered)}"


def test_containers_come_from_kubernetes() -> None:
    containers = [c for c in _lock()["cases"] if c["category"] == "containers"]
    # Floor before constraint: the loop below is satisfied by absence, so a corpus
    # that lost its containers case would pass it and take the platform rule with
    # it. tfsec is Terraform-only, so a containers case declared `terraform` would
    # be scanned by a tool that cannot read a manifest.
    assert containers, "no containers case in the corpus; the platform rule below is vacuous"
    for case in containers:
        assert case["platform"] == "kubernetes", f"{case['id']} containers must be k8s"


def test_every_case_path_exists_on_disk() -> None:
    """A pinned case that is not vendored would silently drop a category.

    Content, and it reads bytes to earn that label. `(REPO_ROOT / case["path"])
    .exists()` alone is shape wearing content's clothes three ways: `Path.cwd() /
    ""` is the repository root and exists, so `"path": ""` passes; a zero-byte
    `s3.tf` passes; and a *directory* named `s3.tf` passes. The corpus could be
    gutted to empty files with that assertion still green.
    """
    problems: list[str] = []
    checked: set[str] = set()
    for case in _lock()["cases"]:
        checked.add(case["id"])
        declared = case["path"]
        # Refused before it is joined: the empty string resolves to REPO_ROOT.
        if not declared:
            problems.append(f"{case['id']}: declares an empty path")
            continue
        target = REPO_ROOT / declared
        if not target.exists():
            problems.append(f"{case['id']}: {declared} does not exist")
        elif target.is_dir():
            if not any(child.is_file() for child in target.rglob("*")):
                problems.append(f"{case['id']}: {declared} is a directory holding no files")
        elif target.stat().st_size == 0:
            problems.append(f"{case['id']}: {declared} is a zero-byte file")
    assert problems == [], (
        f"vendored case paths are not usable: {problems}; run tools/vendor_corpus.ps1 "
        "and correct tools/corpus.lock.json to match the real upstream layout"
    )
    assert checked >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - checked)}; "
        "`problems == []` is satisfied by an empty `cases` array"
    )


def test_every_scan_root_is_a_directory_on_disk() -> None:
    """Content: `scan_root` is what a scanner is pointed at, so it must be a dir.

    Non-empty first, again because `REPO_ROOT / ""` is the repository root and is
    itself a directory - the emptiest possible `scan_root` would otherwise pass.
    """
    checked: set[str] = set()
    for case in _lock()["cases"]:
        declared = case["scan_root"]
        assert declared, f"{case['id']} declares an empty scan_root"
        root = REPO_ROOT / declared
        assert root.is_dir(), (
            f"{case['id']} scan_root {declared} is not a directory on disk; a scanner "
            "is pointed at it, so a file or a missing path cannot be scanned"
        )
        checked.add(case["id"])
    assert checked >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - checked)}"
    )


def test_every_case_path_lies_inside_its_own_scan_root() -> None:
    """Content, and the only assertion that catches a mismatched pair.

    `path` and `scan_root` are independently plausible strings: each exists on
    disk, each is repo-relative. Nothing else here would notice `tg-aws-s3`
    pointing at the TerraGoat file while naming the kubernetes-goat scan root -
    and a consumer following the `attribution` rule would then attribute that
    file's findings to no case at all, silently marking them `unattributed`.
    """
    checked: set[str] = set()
    for case in _lock()["cases"]:
        assert case["path"] and case["scan_root"], f"{case['id']} has an empty path pair"
        root = (REPO_ROOT / case["scan_root"]).resolve()
        target = (REPO_ROOT / case["path"]).resolve()
        assert target == root or root in target.parents, (
            f"{case['id']} path {case['path']} is not inside its scan_root "
            f"{case['scan_root']}, so scanning that root would never report this "
            "case's file and the finding would be attributed to no case"
        )
        checked.add(case["id"])
    assert checked >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - checked)}"
    )


def test_the_four_terraform_cases_share_one_scan_root() -> None:
    """Content: asserted as the known, deliberate fact it is.

    Upstream keeps all four Terraform case files in one directory, so a
    directory-oriented scanner (tfsec takes a directory; Trivy config scanning is
    directory-first) sees one scan root, not four. Recording it here means a later
    task cannot discover it by accident and cannot quietly scan per case - which
    would report the same finding set four times under four category labels.

    Counts compared against module-level literals, so an emptied `cases` array
    cannot satisfy them: `len([]) == 0` would agree with a derived count.
    """
    terraform = [case for case in _lock()["cases"] if case["platform"] == "terraform"]
    assert len(terraform) == TERRAFORM_CASE_COUNT, (
        f"expected {TERRAFORM_CASE_COUNT} terraform cases, found {len(terraform)}: "
        f"{sorted(case['id'] for case in terraform)}"
    )
    roots = {case["scan_root"] for case in terraform}
    assert roots == {TERRAFORM_SCAN_ROOT}, (
        f"the terraform cases declare scan roots {sorted(roots)}, expected the single "
        f"{TERRAFORM_SCAN_ROOT!r} they share on disk"
    )
    tf_files = sorted(p.name for p in (REPO_ROOT / TERRAFORM_SCAN_ROOT).glob("*.tf"))
    assert len(tf_files) == TERRAFORM_SCAN_ROOT_TF_FILES, (
        f"{TERRAFORM_SCAN_ROOT} holds {len(tf_files)} .tf files, expected "
        f"{TERRAFORM_SCAN_ROOT_TF_FILES} at this pin: {tf_files}. Scanning that root "
        f"reports findings for all of them, not only the {TERRAFORM_CASE_COUNT} a case "
        "names, which is what the lockfile's `attribution` rule exists to handle"
    )


def test_the_attribution_rule_is_recorded_in_the_lockfile() -> None:
    """Shape, deliberately, and it must not be read as more.

    This asserts that the rule is *written down* - that `attribution` exists, is
    non-empty, and names the `unattributed` state. It cannot assert that any
    consumer obeys it; the consumer is Task 5 and does not exist yet. Its value is
    that a later task cannot silently invent a different rule, and that deleting
    the paragraph fails a test instead of losing a design decision.
    """
    attribution = _lock()["attribution"]
    assert isinstance(attribution, str), "attribution must be a string"
    assert attribution.strip(), "attribution is empty; the scan-and-attribute rule is gone"
    assert "unattributed" in attribution, (
        "attribution does not name the `unattributed` state, which is the clause that "
        "keeps a finding under a scan root no case claims from being dropped or given "
        "a default category"
    )
    assert "scan_root" in attribution, "attribution does not explain what `scan_root` is for"


def test_recorded_utc_is_not_earlier_than_the_events_it_records() -> None:
    """Content: the top-level date was the one date no test read.

    It sat a week before the file existed, describing neither the pin verification
    nor the vendoring. Both orderings are asserted, and the second is the
    load-bearing one: `recorded_utc >= pin_verified_utc` alone is satisfied by the
    stale value that prompted this (`2026-08-24 >= 2026-08-24`), while
    `recorded_utc >= retrieved_utc` refuses it - a retrieval cannot be recorded
    before it happens.

    Lower bound only. The upper bound is its own test below, named for what it
    asserts, because a `recorded_utc` of `2099-01-01` satisfies every assertion
    here.
    """
    lock = _lock()
    recorded = lock["recorded_utc"]
    assert ISO_DATE_RE.match(recorded), f"recorded_utc {recorded!r} is not an ISO date"
    recorded_date = date.fromisoformat(recorded)
    checked: set[str] = set()
    for name, entry in lock["sources"].items():
        for field in ("pin_verified_utc", "retrieved_utc"):
            assert recorded_date >= date.fromisoformat(entry[field]), (
                f"recorded_utc {recorded} precedes {name}'s {field} {entry[field]}, so it "
                "describes neither event and would date the corpus before it existed"
            )
        checked.add(name)
    # Floor from a literal: an emptied `sources` map satisfies the loop above.
    assert checked == set(EXPECTED_COMMITS), (
        f"checked {sorted(checked)}, expected {sorted(EXPECTED_COMMITS)}"
    )


def test_recorded_utc_is_not_in_the_future() -> None:
    """Content: the other half of the bound, which `2099-01-01` walked through.

    Its sibling above bounds `recorded_utc` from below - not earlier than the pin
    verification or the retrieval it records - and nothing bounded it from above,
    so any date at all in the future satisfied every assertion in this file. A
    record cannot have been made after the moment it is read.

    The horizon is computed at test time, never a literal that would rot. One day
    of skew is tolerated deliberately: the field is a UTC calendar date but is
    written by a human reading a local clock, which sits up to a day either side
    of UTC on some hosts. That tolerance cannot hide the failure this refuses - a
    stale or fabricated date is out by months or years, not by hours.
    """
    recorded = _lock()["recorded_utc"]
    assert ISO_DATE_RE.match(recorded), f"recorded_utc {recorded!r} is not an ISO date"
    horizon = datetime.now(UTC).date() + timedelta(days=1)
    assert date.fromisoformat(recorded) <= horizon, (
        f"recorded_utc {recorded} is in the future (UTC today plus one day of "
        f"timezone skew is {horizon.isoformat()}); the corpus cannot have been "
        "recorded after the moment this test reads it"
    )


def test_license_candidates_stay_in_step_with_the_vendor_script() -> None:
    """Content: the duplicated list is tied to its original, not just commented.

    `LICENSE_CANDIDATES` here and `$LicenseCandidates` at `tools/vendor_corpus.ps1:36`
    (a reader's pointer; the assertion finds it by regex) are the same five names in
    the same order, and the order matters - the script takes the first match. Adding
    `LICENCE` to the script would otherwise leave this file checking a stale list and
    reporting green.
    """
    script = VENDOR_SCRIPT.read_text(encoding="utf-8")
    match = PS_LICENSE_CANDIDATES_RE.search(script)
    assert match, (
        f"no `$LicenseCandidates = @(...)` assignment found in {VENDOR_SCRIPT}; if the "
        "script renamed it, retarget this test rather than deleting it - the two lists "
        "are otherwise unlinked"
    )
    parsed = tuple(PS_SINGLE_QUOTED_RE.findall(match.group(1)))
    assert parsed, f"parsed no candidate names out of {match.group(1)!r}"
    assert parsed == LICENSE_CANDIDATES, (
        f"tools/vendor_corpus.ps1 searches {list(parsed)} but this file checks "
        f"{list(LICENSE_CANDIDATES)}; the script's list is the one that runs"
    )


def test_each_case_path_matches_the_platform_that_selects_its_scanners() -> None:
    """Content: nothing else ties `platform` to what is actually on disk.

    `test_cases_declare_a_platform_and_category` accepts a `.tf` file declared
    `kubernetes` and the `scenarios/` directory declared `terraform`. Since
    `platform` is what selects the scanner set, either would hand a file to a tool
    that cannot read it - tfsec is Terraform-only
    (`tests/test_scanners_lock.py:122`).
    """
    checked: set[str] = set()
    for case in _lock()["cases"]:
        platform = case["platform"]
        assert platform in PLATFORM_SUFFIXES, f"{case['id']} unknown platform {platform!r}"
        suffixes = PLATFORM_SUFFIXES[platform]
        # Refused before it is joined, as at `:286` and `:339`. `REPO_ROOT / ""` is
        # REPO_ROOT, which `is_dir()` is true of, so the `rglob` below would then
        # match `.tf` files anywhere in the repository and this test would report
        # green on precisely the input it exists to reject.
        assert case["path"], f"{case['id']} declares an empty path"
        target = REPO_ROOT / case["path"]
        if target.is_dir():
            matching = [p for p in target.rglob("*") if p.is_file() and p.suffix in suffixes]
            assert matching, (
                f"{case['id']} is declared {platform} but its directory {case['path']} "
                f"holds no {sorted(suffixes)} file"
            )
        else:
            assert target.suffix in suffixes, (
                f"{case['id']} is declared {platform} but {case['path']} has suffix "
                f"{target.suffix!r}, not one of {sorted(suffixes)}"
            )
        checked.add(case["id"])
    assert checked >= EXPECTED_CASE_IDS, (
        f"corpus.lock.json is missing cases {sorted(EXPECTED_CASE_IDS - checked)}"
    )


def test_each_vendored_tree_retains_its_upstream_license_text() -> None:
    """Redistribution obligation, asserted rather than left to a script's output.

    This repository ships TerraGoat (Apache-2.0) and kubernetes-goat (MIT)
    verbatim. A vendored tree with no license text beside it is an actual
    licensing failure, not a cosmetic gap. `vendor_corpus.ps1` dies on it, but
    that check runs only when someone re-vendors and nothing re-reads its output.

    Content, and it reads the file to earn that: `is_file()` is satisfied by a
    zero-byte `LICENSE`, so the docstring's claim above was previously asserted by
    nothing at all. The marker check goes further than a size floor - it fails a
    tree whose license file holds the *wrong* license, which is the same claim the
    dissertation makes when it names the redistribution terms.

    Iterates `EXPECTED_COMMITS`, a literal, so it cannot go vacuous by the
    lockfile losing a source.
    """
    sources = _lock()["sources"]
    for name in EXPECTED_COMMITS:
        tree = VENDOR_DIR / name
        assert tree.is_dir(), f"{name} is not vendored at {tree}"
        found = [candidate for candidate in LICENSE_CANDIDATES if (tree / candidate).is_file()]
        assert found, (
            f"{name} is vendored with no license text; looked for "
            f"{list(LICENSE_CANDIDATES)} in {tree}"
        )
        license_file = tree / found[0]
        size = license_file.stat().st_size
        assert size >= LICENSE_MIN_BYTES, (
            f"{name}'s {found[0]} is {size} bytes, below the {LICENSE_MIN_BYTES}-byte "
            "floor: a file that holds no license text does not discharge the "
            "redistribution obligation any more than a missing one does"
        )
        declared = sources[name]["license"]
        assert declared in LICENSE_TEXT_MARKERS, (
            f"{name} declares license {declared!r}, for which this test knows no text "
            "marker; add one rather than letting an unrecognised license skip the check"
        )
        text = license_file.read_text(encoding="utf-8")
        for marker in LICENSE_TEXT_MARKERS[declared]:
            assert marker in text, (
                f"{name} declares {declared} but {found[0]} does not contain {marker!r}; "
                "the vendored license text is not the license the lockfile claims"
            )


def _sources_md_sections() -> dict[str, str]:
    """`SOURCES.md` split into its per-source `## <name>` bodies.

    Section-scoped rather than whole-file: both sources carry the same
    `pin_verified_utc`, so a whole-file `in text` check would let one section's
    date stand in for the other's.
    """
    sections: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for line in SOURCES_MD.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            if current is not None:
                sections[current] = "\n".join(body)
            current = line[3:].strip()
            body = []
        elif current is not None:
            body.append(line)
    if current is not None:
        sections[current] = "\n".join(body)
    return sections


def test_sources_md_attributes_every_pinned_commit() -> None:
    """The attribution artifact must name the same commits as the lockfile.

    `corpus/vendor/SOURCES.md` is the copy a reader of the dissertation sees, so
    it is the copy that can drift from the pin. Also asserted BOM-free: PS 5.1's
    `Out-File -Encoding utf8` and `Set-Content -Encoding utf8` both emit a UTF-8
    BOM, and a BOM in a provenance file is a silent corruption rather than a
    crash.

    The license is matched as a whole token after being refused when empty:
    `"" in text` is `True` for any text, so `entry["license"] in text` was shape
    dressed as content, and a bare substring match would also accept
    `Apache-2.0-only` or `MIT-0` standing in for the declared terms.

    Carries its own floor over `sources` rather than borrowing
    `test_sources_pinned_to_a_commit_and_licensed`'s: a floor in another function
    does not stop this loop from reporting green on an empty map.
    """
    assert SOURCES_MD.is_file(), f"{SOURCES_MD} was not generated"
    assert not SOURCES_MD.read_bytes().startswith(UTF8_BOM), (
        "corpus/vendor/SOURCES.md starts with a UTF-8 BOM; write it with "
        "[System.IO.File]::WriteAllText(..., New-Object System.Text.UTF8Encoding $false)"
    )
    text = SOURCES_MD.read_text(encoding="utf-8")
    checked: set[str] = set()
    for name, entry in _lock()["sources"].items():
        assert entry["commit"] in text, f"SOURCES.md does not record {name}'s pinned commit"
        license_value = entry["license"]
        assert license_value, f"{name} declares an empty license, which `in text` accepts"
        token = re.compile(rf"(?<![\w.\-]){re.escape(license_value)}(?![\w.\-])")
        assert token.search(text), (
            f"SOURCES.md does not record {name}'s license {license_value!r} as a whole "
            "token"
        )
        assert entry["url"] in text, f"SOURCES.md does not record {name}'s upstream url"
        checked.add(name)
    assert checked == set(EXPECTED_COMMITS), (
        f"SOURCES.md was checked against {sorted(checked)}, expected "
        f"{sorted(EXPECTED_COMMITS)}"
    )


def test_sources_md_census_matches_the_vendored_trees_on_disk() -> None:
    """Content: the counts and dates in the attribution file are recomputed here.

    `tools/vendor_corpus.ps1` writes a file count, a byte total and two dates into
    `SOURCES.md`, and nothing kept them true: a partial re-vendor or a hand edit
    under `corpus/` would leave the census describing a tree that no longer exists,
    in the file a dissertation reader sees. The byte total is stable across hosts
    because `.gitattributes:16` checks `corpus/**` out as LF everywhere.
    """
    sections = _sources_md_sections()
    assert set(sections) >= set(EXPECTED_COMMITS), (
        f"SOURCES.md has sections {sorted(sections)}, missing "
        f"{sorted(set(EXPECTED_COMMITS) - set(sections))}"
    )
    checked: set[str] = set()
    for name, entry in _lock()["sources"].items():
        section = sections[name]
        files = [p for p in (VENDOR_DIR / name).rglob("*") if p.is_file()]
        assert files, f"{name} is vendored with no files at {VENDOR_DIR / name}"
        total = sum(p.stat().st_size for p in files)
        census = (
            f"- Vendored tree: `corpus/vendor/{name}/` ({len(files)} files, "
            f"{total} bytes, license text included)"
        )
        assert census in section, (
            f"SOURCES.md's census for {name} disagrees with the tree on disk "
            f"({len(files)} files, {total} bytes); expected the line {census!r}. "
            "Re-run tools/vendor_corpus.ps1 rather than editing SOURCES.md by hand"
        )
        for label, field in (
            ("Pin verified against upstream", "pin_verified_utc"),
            ("Retrieved (vendored)", "retrieved_utc"),
        ):
            expected = f"- {label}: {entry[field]}"
            assert expected in section, (
                f"SOURCES.md's {name} section does not carry {expected!r}; the "
                "provenance dates it publishes have drifted from the lockfile"
            )
        checked.add(name)
    assert checked == set(EXPECTED_COMMITS), (
        f"census checked {sorted(checked)}, expected {sorted(EXPECTED_COMMITS)}"
    )

