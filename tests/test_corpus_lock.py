"""Corpus v0 must be pinned, licensed, and span all five tested categories.

Structurally a sibling of `tests/test_scanners_lock.py`, and split the way that
file's review demanded: assertions that check the lockfile's *shape* - it carries
the fields `tools/vendor_corpus.ps1` reads - are kept apart from assertions that
check its *content* - the pins are the values the plan fixed, every case path
exists on disk, and the upstream license text really is vendored beside each
tree. Shape alone would let a wrong pin or an unvendored license pass green.
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK = REPO_ROOT / "tools" / "corpus.lock.json"
VENDOR_DIR = REPO_ROOT / "corpus" / "vendor"
SOURCES_MD = VENDOR_DIR / "SOURCES.md"

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UTF8_BOM = b"\xef\xbb\xbf"
CATEGORIES = {"storage", "networking", "iam", "compute", "containers"}

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
    """
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


def test_cases_declare_a_platform_and_category() -> None:
    for case in _lock()["cases"]:
        assert case["platform"] in {"terraform", "kubernetes"}
        assert case["category"] in CATEGORIES, f"{case['id']} bad category"
        assert case["path"], f"{case['id']} missing path"


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
    """A pinned case that is not vendored would silently drop a category."""
    missing = [
        case["id"] for case in _lock()["cases"] if not (REPO_ROOT / case["path"]).exists()
    ]
    assert missing == [], (
        f"vendored paths missing for {missing}; run tools/vendor_corpus.ps1 "
        "and correct tools/corpus.lock.json to match the real upstream layout"
    )


def test_each_vendored_tree_retains_its_upstream_license_text() -> None:
    """Redistribution obligation, asserted rather than left to a script's output.

    This repository ships TerraGoat (Apache-2.0) and kubernetes-goat (MIT)
    verbatim. A vendored tree with no license text beside it is an actual
    licensing failure, not a cosmetic gap. `vendor_corpus.ps1` dies on it, but
    that check runs only when someone re-vendors and nothing re-reads its output.

    Iterates `EXPECTED_COMMITS`, a literal, so it cannot go vacuous by the
    lockfile losing a source.
    """
    for name in EXPECTED_COMMITS:
        tree = VENDOR_DIR / name
        assert tree.is_dir(), f"{name} is not vendored at {tree}"
        found = [candidate for candidate in LICENSE_CANDIDATES if (tree / candidate).is_file()]
        assert found, (
            f"{name} is vendored with no license text; looked for "
            f"{list(LICENSE_CANDIDATES)} in {tree}"
        )


def test_sources_md_attributes_every_pinned_commit() -> None:
    """The attribution artifact must name the same commits as the lockfile.

    `corpus/vendor/SOURCES.md` is the copy a reader of the dissertation sees, so
    it is the copy that can drift from the pin. Also asserted BOM-free: PS 5.1's
    `Out-File -Encoding utf8` and `Set-Content -Encoding utf8` both emit a UTF-8
    BOM, and a BOM in a provenance file is a silent corruption rather than a
    crash.

    Not vacuous on an empty `sources` map: `test_sources_pinned_to_a_commit_and_
    licensed` pins that map to exactly the two expected keys.
    """
    assert SOURCES_MD.is_file(), f"{SOURCES_MD} was not generated"
    assert not SOURCES_MD.read_bytes().startswith(UTF8_BOM), (
        "corpus/vendor/SOURCES.md starts with a UTF-8 BOM; write it with "
        "[System.IO.File]::WriteAllText(..., New-Object System.Text.UTF8Encoding $false)"
    )
    text = SOURCES_MD.read_text(encoding="utf-8")
    for name, entry in _lock()["sources"].items():
        assert entry["commit"] in text, f"SOURCES.md does not record {name}'s pinned commit"
        assert entry["license"] in text, f"SOURCES.md does not record {name}'s license"
        assert entry["url"] in text, f"SOURCES.md does not record {name}'s upstream url"
