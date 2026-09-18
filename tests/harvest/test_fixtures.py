"""The six captured fixtures must still be the bytes `artifacts/scanner-behavior.json` describes.

`tools/capture_fixtures.ps1` observed these files once. Every later task reads them
instead of re-running a scanner, so from Task 6 onwards they are the evidence, and
nothing until now checked that what is on disk is still what was observed. The
failure that matters is silent: a fixture truncated by a bad merge, given CRLF by a
checkout on a host that ignored `.gitattributes`, or given a UTF-8 BOM by an editor,
still looks like a JSON file to a reader - and a BOM'd one still parses on the bytes
path, so only the byte-level assertions below see it at all.

Every assertion here is content, in the §G1 sense `tests/test_corpus_lock.py` uses:
each one compares bytes on disk against a specific value the manifest or a lockfile
wrote down. There is no shape assertion in this module, and the absence is deliberate
rather than an oversight - shape would mean checking that the manifest carries the
fields these tests read, and a manifest missing one of them fails at collection,
naming the field, before any assertion runs.

Deliberately absent: any assertion that a fixture equals a stored copy of itself, and
any assertion that a finding sits at a given index. The fixtures are not
byte-reproducible - re-running checkov returns the same multiset of findings in a
different order - so an equality or index assertion would pass today and fail on the
next capture for a reason that is not a regression. Appendix A.1 of
docs/superpowers/specs/2026-08-24-implementation-phase0-design.md records the
measurement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
MANIFEST = REPO_ROOT / "artifacts" / "scanner-behavior.json"
SCANNER_LOCK = REPO_ROOT / "tools" / "scanners.lock.json"
CORPUS_LOCK = REPO_ROOT / "tools" / "corpus.lock.json"

UTF8_BOM = b"\xef\xbb\xbf"

# Three scanners x the two distinct scan roots the corpus declares. A module-level
# literal for the same reason `tests/test_corpus_lock.py` keeps `TERRAFORM_CASE_COUNT`
# as one: the count derived from the lockfiles below is compared against a number
# written down here, so an emptied `scanners` object or an emptied `cases` array
# cannot satisfy "every capture is accounted for" by there being no captures.
EXPECTED_CAPTURE_COUNT = 6

# The prefix every `fixture` field must carry, so the field is directly usable as a
# path from the repository root. Forward slashes: the capture script writes them even
# though it runs on Windows.
FIXTURE_PREFIX = "tests/harvest/fixtures/"

# The off-matrix capture, named once. tfsec is pinned terraform-only; this run exists
# to record what it does with Kubernetes YAML rather than to assume it refuses.
OFF_MATRIX_FIXTURE = "tfsec-kubernetes.json"
# Its on-matrix sibling, for the contrast that makes "empty" mean something.
ON_MATRIX_SIBLING = "tfsec-terraform.json"

# The only two top-level shapes any scanner here produces, and the Python type each
# word names. A `stdout_top_level` outside this mapping raises KeyError rather than
# quietly matching nothing.
TOP_LEVEL_TYPES: dict[str, type] = {"array": list, "object": dict}


def _load(path: Path) -> Any:
    """Parse with `json.loads` over raw bytes, which is what Task 6 will do.

    Bytes rather than `read_text`: `read_text("utf-8-sig")` would strip a BOM before
    the parser saw it, and the locale-default `read_text()` would mis-decode any
    non-ASCII byte on this host. Neither this path nor that one makes a BOM *fail* -
    measured, `json.loads` over bytes takes `json.detect_encoding`, which reports
    utf-8-sig and parses BOM-led input happily. That is why the BOM has its own
    byte-level test below rather than being left to this one.
    """
    return json.loads(path.read_bytes())


CAPTURES: tuple[dict[str, Any], ...] = tuple(_load(MANIFEST)["captures"])
CAPTURE_IDS = [f"{c['scanner']}-{c['platform']}" for c in CAPTURES]


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_every_fixture_parses_under_strict_json_load(capture: dict[str, Any]) -> None:
    """Content: Python's parser, not the capture script's, decides these are JSON.

    The manifest's `stdout_is_json` was decided at capture time by a validator the
    capture script launched. This is the independent second opinion, and it is the
    one that matters: every consumer from Task 6 on reaches these bytes through
    `json.load`, which rejects a raw control character inside a string literal where
    the `JavaScriptSerializer` the capture script first used accepted one.

    It does not reject a BOM - see `_load` - so this test would pass over a BOM'd
    fixture. That gap is the whole reason the next test exists.
    """
    path = REPO_ROOT / capture["fixture"]
    doc = _load(path)
    assert doc is not None, f"{capture['fixture']} parsed to JSON null"
    assert capture["stdout_is_json"] is True, (
        f"the manifest records {capture['fixture']} as not JSON, but json.loads read it"
    )
    assert capture["stdout_parse_error"] is None, (
        f"the manifest records a parse error for {capture['fixture']}: "
        f"{capture['stdout_parse_error']}"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_no_fixture_carries_a_utf8_bom(capture: dict[str, Any]) -> None:
    """Content, stated separately from parsing because the cause is specific.

    An editor that saves as "UTF-8" on Windows adds a leading BOM and shows the file
    unchanged afterwards, and nothing else in this module notices: measured, the
    bytes path every test here uses accepts a BOM, while a consumer that opens the
    file as text - `open(path, encoding="utf-8")` - raises "Unexpected UTF-8 BOM".
    So this is the only assertion standing between a BOM and Task 6. The manifest
    recorded `stdout_has_bom` at capture time; both sides are checked so a BOM
    arriving after the capture is a failure here and not a disagreement nobody reads.
    """
    path = REPO_ROOT / capture["fixture"]
    head = path.read_bytes()[: len(UTF8_BOM)]
    assert head != UTF8_BOM, f"{capture['fixture']} begins with a UTF-8 BOM"
    assert capture["stdout_has_bom"] is False, (
        f"the manifest records a BOM for {capture['fixture']}"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_each_fixture_is_the_size_the_manifest_recorded(capture: dict[str, Any]) -> None:
    """Content: on-disk bytes against the byte count observed at capture time.

    The comparison is only valid because these paths hold no CRLF. `.gitattributes`
    normalizes `*.json` to LF in the index, so a fixture that had contained CRLF when
    it was measured would be committed with fewer bytes than the number recorded, and
    this assertion would fail for a reason that is not corruption. `stdout_crlf_pairs`
    is asserted zero first, which is both the precondition for the size check and the
    thing that would have to be revisited if a future scanner emitted CRLF.

    This is the assertion that catches a truncated or partially written fixture, which
    every other test in this module can pass.
    """
    path = REPO_ROOT / capture["fixture"]
    assert capture["stdout_crlf_pairs"] == 0, (
        f"{capture['fixture']} was captured with {capture['stdout_crlf_pairs']} CRLF "
        "pairs, so its committed size cannot be compared with stdout_bytes directly"
    )
    assert path.stat().st_size == capture["stdout_bytes"], (
        f"{capture['fixture']} is {path.stat().st_size} bytes on disk but the manifest "
        f"recorded {capture['stdout_bytes']}"
    )


@pytest.mark.parametrize("capture", CAPTURES, ids=CAPTURE_IDS)
def test_each_fixture_parses_to_the_top_level_type_recorded(capture: dict[str, Any]) -> None:
    """Content: the manifest's `stdout_top_level` word against the parsed document.

    Not decoration. checkov's top level is an **array** of per-framework blocks while
    trivy's and tfsec's are objects, so a walker that assumes one shape for all three
    is wrong for exactly one scanner. This pins the word each walker will branch on.
    """
    word = capture["stdout_top_level"]
    expected = TOP_LEVEL_TYPES[word]
    doc = _load(REPO_ROOT / capture["fixture"])
    assert isinstance(doc, expected), (
        f"the manifest records {capture['fixture']} as a JSON {word} but it parsed to "
        f"{type(doc).__name__}"
    )


def test_manifest_and_directory_name_the_same_six_fixtures() -> None:
    """Content: the capture matrix is complete, and nothing else lives in the directory.

    Three parts of one claim. The count is derived from the two lockfiles - scanners
    times distinct scan roots - and then checked against `EXPECTED_CAPTURE_COUNT`, so
    an emptied lockfile cannot make the rest of this test pass by producing zero
    expected captures. The manifest must carry exactly that many records. And the
    directory must hold exactly those files: `iterdir`, not `glob("*.json")`, because a
    stray file of any name in a fixtures directory is worth failing on, and because a
    glob that matched nothing would make a subset test vacuous.
    """
    scanners = _load(SCANNER_LOCK)["scanners"]
    scan_roots = {case["scan_root"] for case in _load(CORPUS_LOCK)["cases"]}
    derived = len(scanners) * len(scan_roots)
    assert derived == EXPECTED_CAPTURE_COUNT, (
        f"{len(scanners)} scanners x {len(scan_roots)} distinct scan roots is {derived} "
        f"captures, not the {EXPECTED_CAPTURE_COUNT} this module expects; if the matrix "
        "really changed, re-run tools/capture_fixtures.ps1 and update the literal"
    )
    assert len(CAPTURES) == EXPECTED_CAPTURE_COUNT, (
        f"the manifest carries {len(CAPTURES)} capture records, not {EXPECTED_CAPTURE_COUNT}"
    )

    declared: set[str] = set()
    for capture in CAPTURES:
        field = capture["fixture"]
        assert field.startswith(FIXTURE_PREFIX), (
            f"the manifest's fixture path {field!r} is not under {FIXTURE_PREFIX!r}, so it "
            "cannot be resolved against the repository root"
        )
        declared.add(field[len(FIXTURE_PREFIX) :])
    assert len(declared) == EXPECTED_CAPTURE_COUNT, (
        f"the manifest's {EXPECTED_CAPTURE_COUNT} records name only {len(declared)} "
        "distinct fixtures, so two captures overwrote one file"
    )

    on_disk = {entry.name for entry in FIXTURE_DIR.iterdir() if entry.is_file()}
    assert on_disk == declared, (
        f"the fixtures directory and the manifest disagree: only on disk "
        f"{sorted(on_disk - declared)}, only in the manifest {sorted(declared - on_disk)}"
    )


def test_off_platform_capture_is_empty_exit_zero_and_undeclared() -> None:
    """Content: the three halves of spec A.2, which only mean anything together.

    Separately they are three unremarkable facts: tfsec returns an empty result set
    over Kubernetes YAML; it exits 0 doing so; and `tools/scanners.lock.json` pins it
    terraform-only. The finding is that the first two are *indistinguishable from a
    clean scan* - a caller inspecting output or exit status cannot tell "nothing wrong
    here" from "this scanner cannot read this input at all" - which is why the third
    has to exist and has to be enforced before the process is launched.

    One test, not three, because three could be broken apart: delete the lockfile
    assertion and two green tests still say tfsec is quiet about Kubernetes, which is
    the exact conclusion A.2 exists to refuse.

    The emptiness is asserted against the same key in the on-matrix sibling, which
    holds 119 of them at this pin. Without that contrast, "the result list is empty" would also be
    satisfied by reading a key that does not exist the way this test thinks it does.
    """
    off = [c for c in CAPTURES if c["fixture"].endswith(OFF_MATRIX_FIXTURE)]
    assert len(off) == 1, f"expected one {OFF_MATRIX_FIXTURE} record, found {len(off)}"
    flagged = [c["fixture"] for c in CAPTURES if c["off_matrix"]]
    assert flagged == [off[0]["fixture"]], (
        f"off_matrix should flag {OFF_MATRIX_FIXTURE} and nothing else, but flags {flagged}"
    )

    sibling = _load(FIXTURE_DIR / ON_MATRIX_SIBLING)
    assert len(sibling["results"]) > 0, (
        f"{ON_MATRIX_SIBLING} has no results either, so an empty result set in "
        f"{OFF_MATRIX_FIXTURE} would say nothing about platform applicability"
    )

    doc = _load(FIXTURE_DIR / OFF_MATRIX_FIXTURE)
    assert doc["results"] == [], (
        f"{OFF_MATRIX_FIXTURE} carries {len(doc['results'])} results; A.2 records that "
        "tfsec reports nothing over Kubernetes YAML rather than refusing"
    )
    assert off[0]["exit_code"] == 0, (
        f"{OFF_MATRIX_FIXTURE} was captured with exit code {off[0]['exit_code']}; A.2 "
        "rests on tfsec exiting 0, the same code a clean Terraform scan would use"
    )

    platforms = _load(SCANNER_LOCK)["scanners"]["tfsec"]["platforms"]
    assert "terraform" in platforms, (
        f"tfsec declares {platforms}, so the assertion below would hold for a lockfile "
        "that declares no platforms at all"
    )
    assert "kubernetes" not in platforms, (
        f"tfsec declares {platforms}, which includes kubernetes - the capture above is "
        "then on-matrix and the framework would route Kubernetes manifests to a scanner "
        "that silently reports nothing"
    )
