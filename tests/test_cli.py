"""`iacrisk.cli`: one command from a folder of IaC files to a ranked report.

Until this module existed nothing joined live scanner invocation to the pipeline, and every
result in the dissertation came from replayed captures. The command is that join. It adds
no layer and changes no score, so what these tests protect is the composition: that the
command reaches the numbers the evaluated path reaches, says what it could not do, and
never reports a ranking built on fewer scanners than it was asked to run.

**How the scanners are stood in for.** Most tests must run on a machine with no scanner
installed, so the one slow, external step - launching the scanners - is replaced, and
nothing else is. The stand-in returns the committed captures under
`tests/harvest/fixtures/`: real scanner output, for the same folders, recorded when the
corpus was built. Everything downstream of the launch is the real code. tfsec's capture is
rewritten to this checkout's paths first, because tfsec reports absolute paths and a live
run here would report this host's; that is the only edit made to a capture.

**Where the expected values come from.** Not from calling the pipeline a second time.
Scores are literals taken from the dissertation's own tables, or are read from the
committed per-case record.

Two tests run the real scanners. They are skipped, and reported as skipped, where
`tools/bootstrap.ps1` has not installed them.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import sys
from collections import Counter
from collections.abc import Mapping
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import pytest

from eval.ground_truth import load_and_validate
from iacrisk import cli
from iacrisk.input import DiscoveryResult
from iacrisk.scanners import invoke
from iacrisk.scanners.base import rebase_to_scan_root
from iacrisk.scanners.invoke import ScannerTimeoutError, applicable_scanners
from iacrisk.scanners.tfsec import capture_scan_root
from tools.score import run as score_run

REPO_ROOT = Path(__file__).resolve().parent.parent
AUTHORED = REPO_ROOT / "corpus" / "authored"
KUBERNETES = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"
FIXTURES = REPO_ROOT / "tests" / "harvest" / "fixtures"
SCORED_CASES = REPO_ROOT / "artifacts" / "scored-cases-v1.json"
SCORED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0.json"
INFERRED_CORPUS = REPO_ROOT / "artifacts" / "scored-corpus-v0-inferred.json"

DECLARED: dict[str, dict[str, int]] = {
    "aws_iam_policy.s3_bucket_scope": {"sensitivity": 3, "criticality": 3},
    "aws_iam_policy.s3_account_scope": {"sensitivity": 3, "criticality": 3},
    "aws_iam_policy.unrestricted_scope": {"sensitivity": 3, "criticality": 3},
    "aws_s3_bucket.private_baseline": {"sensitivity": 3, "criticality": 3},
    "aws_s3_bucket.public_exposed": {"sensitivity": 3, "criticality": 3},
}
"""What corpus v1 declares for the five hand-crafted resources in `corpus/authored`."""

HAND_CRAFTED_CASES = (
    "iam-s3-bucket-scope",
    "iam-s3-account-scope",
    "iam-unrestricted-scope",
    "s3-private-baseline-not-public",
    "s3-public-exposed",
)


def _as_scanned_here(document: Any, scan_root: Path) -> Any:
    """A tfsec capture with its paths as tfsec would report them for `scan_root` today.

    Absolute, whatever form the folder was given in: that is what tfsec emits."""
    scan_root = scan_root.resolve()
    rewritten = copy.deepcopy(document)
    captured_root = capture_scan_root(rewritten, scan_root, REPO_ROOT)
    for result in rewritten["results"]:
        relative = rebase_to_scan_root(result["location"]["filename"], captured_root)
        result["location"]["filename"] = str(scan_root / relative)
    return rewritten


def _replayed(fixtures: Path) -> cli.Scan:
    """A stand-in for launching the scanners: the committed captures for the folder."""

    def scan(discovery: DiscoveryResult, scan_root: Path) -> Mapping[tuple[str, str], object]:
        raw: dict[tuple[str, str], object] = {}
        for platform in sorted({found.platform for found in discovery.files}):
            for scanner in applicable_scanners(platform):
                document = json.loads((fixtures / f"{scanner}-{platform}.json").read_bytes())
                if scanner == "tfsec":
                    document = _as_scanned_here(document, scan_root)
                raw[(scanner, platform)] = document
        return raw

    return scan


def _row(finding: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        finding["resource_identity"],
        finding["issue_class"],
        finding["scanner"],
        finding["rule_id"],
        finding["score"],
        finding["band"],
        tuple(sorted(finding["contributions"].items())),
    )


def _authored(**options: Any) -> dict[str, Any]:
    return cli.analyse(AUTHORED, scan=_replayed(FIXTURES / "authored"), **options)


# --- the composition reaches the evaluated numbers --------------------------------------


def test_the_authored_folder_scores_exactly_as_the_committed_record_does() -> None:
    """Catches the command composing the layers differently from the path the evaluation
    measured: a collapse skipped, a resource index not built, a declared value not joined."""
    payload = _authored(declared=DECLARED)

    committed = json.loads(SCORED_CASES.read_bytes())["cases"]
    expected = Counter(
        _row(finding)
        for case_id in HAND_CRAFTED_CASES
        for finding in committed[case_id]["findings"]
    )
    scored = Counter(_row(f) for f in payload["findings"] if f["resource_identity"] in DECLARED)

    assert expected, "the committed record holds no hand-crafted findings to compare with"
    assert scored == expected


def test_every_finding_is_accounted_for_from_scanner_to_ranked_list() -> None:
    """Catches a scanner's run being lost, or the exact-duplicate collapse not applied:
    31 from Checkov, 17 from tfsec and 12 from Trivy, of which 6 are exact duplicates."""
    payload = _authored(declared=DECLARED)

    assert payload["population"] == {"findings_in": 60, "tier1_collapsed": 6, "ranked": 54}
    assert {
        run: entry["findings_out"] for run, entry in payload["retention"]["scanners"].items()
    } == {"checkov/terraform": 31, "tfsec/terraform": 17, "trivy/terraform": 12}


def test_a_folder_given_as_a_relative_path_is_analysed_like_the_same_folder_in_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tfsec reports absolute paths. Catches the folder being used as typed, so that every
    tfsec finding fails to be placed under it."""
    monkeypatch.chdir(REPO_ROOT)

    payload = cli.analyse(
        Path("corpus/authored"), declared=DECLARED, scan=_replayed(FIXTURES / "authored")
    )

    assert payload["scan_root"] == str(AUTHORED)
    assert payload["population"] == {"findings_in": 60, "tier1_collapsed": 6, "ranked": 54}


# --- one line per resource --------------------------------------------------------------


def test_each_resource_is_summarised_once_at_its_highest_scoring_finding() -> None:
    """The scores are the ones Chapter 6 reports for these cases: the three IAM policies at
    18, 16 and 15, the public bucket at 17 and the private one at 12."""
    summary = cli.by_resource(_authored(declared=DECLARED))

    assert [(r.identity, r.score, r.band, r.findings) for r in summary.ranked] == [
        ("aws_iam_policy.unrestricted_scope", 18, "High", 7),
        ("aws_s3_bucket.public_exposed", 17, "High", 14),
        ("aws_iam_policy.s3_account_scope", 16, "High", 5),
        ("aws_iam_policy.s3_bucket_scope", 15, "Medium", 2),
        ("aws_s3_bucket_public_access_block.public_exposed", 13, "Medium", 12),
        ("aws_s3_bucket.private_baseline", 12, "Medium", 13),
    ]


def test_a_resource_summary_carries_what_the_scanners_alone_said() -> None:
    """The comparison the framework exists to make. Scanner severity puts every one of
    these resources in High; the framework spreads them over 18 down to 12."""
    summary = cli.by_resource(_authored(declared=DECLARED))

    assert {r.baseline_band for r in summary.ranked} == {"High"}


def test_a_resource_summary_names_the_factors_that_are_defaults() -> None:
    """Catches a default being shown as though it were evidence. The public bucket's
    exposure is read from its public-access block and policy; its encryption state is not
    visible in the source, so that factor - and Checkov's absent severity - are defaults."""
    summary = cli.by_resource(_authored(declared=DECLARED))
    bucket = next(r for r in summary.ranked if r.identity == "aws_s3_bucket.public_exposed")

    assert bucket.contributions["exposure"] == 5
    assert "exposure" not in bucket.defaults
    assert "encryption" in bucket.defaults


def test_a_resource_with_only_unseen_rule_findings_is_listed_apart_and_not_ranked() -> None:
    """The evaluation sets a finding from a rule the taxonomy has never seen aside from any
    quality claim. A resource whose findings are all of that kind has no claimed rank, so it
    must not take a place in the ranked list on the strength of one."""
    summary = cli.by_resource(_authored(declared=DECLARED))
    everything = [*summary.ranked, *summary.informational_only]

    assert [r.identity for r in summary.informational_only] == [
        "aws_s3_bucket_policy.public_exposed"
    ]
    assert sum(r.informational for r in everything) == 8
    assert sum(r.findings for r in everything) == 54


# --- where sensitivity and criticality come from ----------------------------------------


def test_without_any_context_the_two_declared_factors_take_their_defaults() -> None:
    """Catches a missing declaration reading as low. Criticality's default is 4 where the
    declarations say 3, so every resource scores one point higher than when declared."""
    payload = _authored()
    summary = cli.by_resource(payload)

    assert payload["context_mode"] == "defaults"
    assert [r.score for r in summary.ranked] == [19, 18, 17, 16, 14, 13]
    assert all({"sensitivity", "criticality"} <= set(r.defaults) for r in summary.ranked)


def test_declared_context_is_reported_as_the_mode_it_is() -> None:
    assert _authored(declared=DECLARED)["context_mode"] == "declared"


def test_inferred_context_reads_the_registered_conventions() -> None:
    """Catches the flag being accepted and ignored. On the Kubernetes corpus the conventions
    resolve exactly two resources - sensitivity 5 from the word `secret` in a Role's name
    and its binding's - on three findings, as the committed inferred run records."""
    payload = cli.analyse(KUBERNETES, infer_context=True, scan=_replayed(FIXTURES))

    assert payload["context_mode"] == "auto-inference"
    resolved = Counter(
        f["resource_identity"]
        for f in payload["findings"]
        if f["factor_states"].get("sensitivity") == "resolved"
    )
    committed = json.loads(INFERRED_CORPUS.read_bytes())["findings"]
    assert resolved == Counter(
        f["resource_identity"]
        for f in committed
        if f["factor_states"].get("sensitivity") == "resolved"
    )
    assert sum(resolved.values()) == 3
    assert all("secret-reader" in identity for identity in resolved)


# --- what the command refuses, and how it says so ----------------------------------------


def _never_scan(discovery: DiscoveryResult, scan_root: Path) -> Mapping[tuple[str, str], object]:
    raise AssertionError(f"the scanners were launched over {scan_root}")


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _unbootstrapped_checkout(tmp_path: Path) -> Path:
    """A stand-in repository root holding the scanner lockfile and nothing resolved."""
    root = tmp_path / "checkout"
    (root / "tools").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "tools" / "scanners.lock.json", root / "tools" / "scanners.lock.json")
    return root


def test_a_folder_that_does_not_exist_is_an_error_and_not_an_empty_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches a mistyped path coming back as "nothing to fix"."""
    missing = tmp_path / "no-such-folder"

    assert cli.main([str(missing)], scan=_never_scan) == 2
    captured = capsys.readouterr()
    assert str(missing) in captured.err
    assert captured.out == ""


def test_a_folder_with_no_iac_files_is_an_error_and_not_an_empty_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "README.md", "nothing to scan here\n")

    assert cli.main([str(tmp_path)], scan=_never_scan) == 2
    captured = capsys.readouterr()
    assert "Terraform" in captured.err and "Kubernetes" in captured.err
    assert captured.out == ""


def test_a_folder_mixing_terraform_and_kubernetes_is_refused_before_any_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each adapter reads the platform off a whole scanner run, so one run over a mixed
    folder would be read as a single platform and its other half misattributed. Refusing
    is the only honest output until the adapters can split a run."""
    _write(tmp_path / "main.tf", 'resource "aws_s3_bucket" "b" {}\n')
    _write(
        tmp_path / "deploy.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers: []\n",
    )

    assert cli.main([str(tmp_path)], scan=_never_scan) == 2
    captured = capsys.readouterr()
    assert "terraform" in captured.err.lower() and "kubernetes" in captured.err.lower()
    assert captured.out == ""


def test_a_declared_context_file_that_cannot_be_read_stops_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches a mistyped file name silently becoming a run with no declared context."""
    missing = tmp_path / "context.json"

    assert cli.main([str(AUTHORED), "--declared", str(missing)], scan=_never_scan) == 2
    assert str(missing) in capsys.readouterr().err

    not_an_object = _write(tmp_path / "list.json", "[1, 2, 3]\n")
    assert cli.main([str(AUTHORED), "--declared", str(not_an_object)], scan=_never_scan) == 2


def test_declared_and_inferred_context_cannot_be_combined() -> None:
    """The two modes are alternatives and are never merged within a run."""
    with pytest.raises(SystemExit) as stopped:
        cli.main([str(AUTHORED), "--declared", "context.json", "--infer"], scan=_never_scan)
    assert stopped.value.code == 2


def test_a_declared_resource_the_folder_does_not_contain_is_reported() -> None:
    """Catches a mistyped identity: its declared values would otherwise be dropped without
    a word and the resource it was meant for scored at the defaults."""
    declared = {**DECLARED, "aws_s3_bucket.no_such_bucket": {"sensitivity": 5, "criticality": 5}}
    payload = _authored(declared=declared)

    assert payload["declared_identities_not_found"] == ["aws_s3_bucket.no_such_bucket"]
    assert _authored(declared=DECLARED)["declared_identities_not_found"] == []


def test_without_installed_scanners_the_command_names_the_bootstrap_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real launch path on a checkout that was never bootstrapped."""
    monkeypatch.setattr(invoke, "REPO_ROOT", _unbootstrapped_checkout(tmp_path))

    assert cli.main([str(AUTHORED)]) == 2
    captured = capsys.readouterr()
    assert "bootstrap.ps1" in captured.err
    assert captured.out == ""


def test_a_scanner_that_returns_no_usable_output_stops_the_run_and_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real launch path with a real process in each scanner's place: the Python
    interpreter, which rejects a scanner's arguments and prints no JSON. Catches the run
    carrying on with the scanners that did answer, which would rank a folder on a fraction
    of its findings and say nothing."""
    root = _unbootstrapped_checkout(tmp_path)
    scanners = json.loads((root / "tools" / "scanners.lock.json").read_bytes())["scanners"]
    _write(
        root / "tools" / "resolved.json",
        json.dumps({name: {"exe": sys.executable} for name in scanners}),
    )
    monkeypatch.setattr(invoke, "REPO_ROOT", root)

    assert cli.main([str(AUTHORED)]) == 1
    captured = capsys.readouterr()
    assert any(name in captured.err for name in scanners)
    assert captured.out == ""


def test_a_scanner_that_times_out_stops_the_run_and_is_named(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def scan(discovery: DiscoveryResult, scan_root: Path) -> Mapping[tuple[str, str], object]:
        raise ScannerTimeoutError("trivy", 900.0)

    assert cli.main([str(AUTHORED)], scan=scan) == 1
    captured = capsys.readouterr()
    assert "trivy" in captured.err
    assert captured.out == ""


# --- what the user is shown --------------------------------------------------------------

RANKED = (
    "aws_iam_policy.unrestricted_scope",
    "aws_s3_bucket.public_exposed",
    "aws_iam_policy.s3_account_scope",
    "aws_iam_policy.s3_bucket_scope",
    "aws_s3_bucket_public_access_block.public_exposed",
    "aws_s3_bucket.private_baseline",
)
INFORMATIONAL_ONLY = ("aws_s3_bucket_policy.public_exposed",)


def _context_file(tmp_path: Path, declared: Mapping[str, Mapping[str, int]] = DECLARED) -> Path:
    return _write(tmp_path / "context.json", json.dumps(declared))


def _run(tmp_path: Path, *options: str, declared: Mapping[str, Any] | None = DECLARED) -> int:
    argv = [str(AUTHORED), *options]
    if declared is not None:
        argv += ["--declared", str(_context_file(tmp_path, declared))]
    return cli.main(argv, scan=_replayed(FIXTURES / "authored"))


def _resource_lines(text: str) -> list[str]:
    """The output lines that end in a resource of the authored folder, in order."""
    known = {*RANKED, *INFORMATIONAL_ONLY}
    return [line for line in text.splitlines() if line.split() and line.split()[-1] in known]


def test_the_summary_shows_each_resource_once_ranked_resources_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches the raw finding list being printed, in which one resource appears up to
    fourteen times, and an informational-only resource taking a place in the ranking."""
    assert _run(tmp_path) == 0
    lines = _resource_lines(capsys.readouterr().out)

    assert [line.split()[-1] for line in lines] == [*RANKED, *INFORMATIONAL_ONLY]


def test_a_ranked_line_carries_the_score_the_band_and_what_the_scanners_said(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(tmp_path) == 0
    lines = {line.split()[-1]: line.split() for line in _resource_lines(capsys.readouterr().out)}

    assert lines["aws_iam_policy.unrestricted_scope"][:3] == ["18", "High", "High"]
    assert lines["aws_s3_bucket.private_baseline"][:3] == ["12", "Medium", "High"]


def test_the_summary_marks_a_default_so_it_cannot_be_read_as_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The public bucket's exposure of 5 was read from its code; its encryption value of 2
    is the default for a state the source does not show."""
    assert _run(tmp_path) == 0
    out = capsys.readouterr().out.splitlines()
    index = next(i for i, line in enumerate(out) if line.endswith("aws_s3_bucket.public_exposed"))
    factors = out[index + 1]

    assert re.search(r"exposure 5(?!\*)", factors)
    assert "encryption 2*" in factors


def test_the_summary_accounts_for_the_findings_at_each_step(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """60 from the scanners, 6 exact duplicates merged, 54 ranked - and where the two
    declared factors came from."""
    assert _run(tmp_path) == 0
    out = capsys.readouterr().out
    header = out[: out.index(RANKED[0])]

    assert {"60", "6", "54"} <= set(re.findall(r"\d+", header))
    assert "declared" in header


def test_top_limits_the_resources_shown_and_says_how_many_are_not(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches a truncated list that looks complete."""
    assert _run(tmp_path, "--top", "2") == 0
    out = capsys.readouterr().out

    assert [line.split()[-1] for line in _resource_lines(out)][:2] == list(RANKED[:2])
    assert RANKED[2] not in out
    assert re.search(r"\b4 more\b", out)


def test_top_must_be_a_positive_number(tmp_path: Path) -> None:
    """A zero or negative limit would slice the list instead of limiting it."""
    with pytest.raises(SystemExit) as stopped:
        _run(tmp_path, "--top", "0")
    assert stopped.value.code == 2


def test_a_declared_resource_that_was_not_found_is_warned_about_and_the_run_completes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    declared = {**DECLARED, "aws_s3_bucket.no_such_bucket": {"sensitivity": 5, "criticality": 5}}

    assert _run(tmp_path, declared=declared) == 0
    assert "aws_s3_bucket.no_such_bucket" in capsys.readouterr().err


def test_a_run_with_no_context_says_the_two_factors_are_defaults(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catches a run with no declared context looking like a run with one."""
    assert _run(tmp_path, declared=None) == 0
    out = capsys.readouterr().out
    header = out[: out.index(RANKED[0])]

    assert "defaults" in header
    assert "declared" not in header.replace("--declared", "")


# --- the report files -------------------------------------------------------------------


def test_out_writes_the_full_report_as_json_and_markdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The terminal shows one line per resource; every finding and every explanation line
    is in the files."""
    out = tmp_path / "report"

    assert _run(tmp_path, "--out", str(out)) == 0
    payload = json.loads((out / "priority-report.json").read_bytes())
    markdown = (out / "priority-report.md").read_text(encoding="utf-8")

    assert len(payload["findings"]) == 54
    assert payload["context_mode"] == "declared"
    assert all(finding["explanation"] for finding in payload["findings"])
    assert all(identity in markdown for identity in RANKED)
    assert str(out) in capsys.readouterr().out


def test_nothing_is_written_unless_out_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches report files appearing in whatever folder the command was run from."""
    context = _context_file(tmp_path / "elsewhere")
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    argv = [str(AUTHORED), "--declared", str(context)]
    assert cli.main(argv, scan=_replayed(FIXTURES / "authored")) == 0
    assert list(workdir.iterdir()) == []


# --- the command as installed, and as run for real --------------------------------------


def test_the_package_installs_the_command_under_its_name() -> None:
    """Catches `uv run iacrisk` not existing, or pointing somewhere other than `main`."""
    (script,) = [e for e in entry_points(group="console_scripts") if e.name == "iacrisk"]
    assert script.load() is cli.main


def _scanners_installed() -> bool:
    resolved = REPO_ROOT / "tools" / "resolved.json"
    if not resolved.exists():
        return False
    entries = json.loads(resolved.read_bytes())
    return all(Path(entry["exe"]).exists() for entry in entries.values())


needs_scanners = pytest.mark.skipif(
    not _scanners_installed(),
    reason="the pinned scanners are not installed on this machine (tools/bootstrap.ps1)",
)


@needs_scanners
def test_live_the_real_scanners_reach_the_scores_the_evaluation_recorded(tmp_path: Path) -> None:
    """Launches Checkov, tfsec and Trivy through the command itself. Everything the
    dissertation reports was replayed from captures; this shows the live path, run as a
    whole, arriving at the same scores for the same folder."""
    out = tmp_path / "report"
    argv = [str(AUTHORED), "--declared", str(_context_file(tmp_path)), "--out", str(out)]

    assert cli.main(argv) == 0
    payload = json.loads((out / "priority-report.json").read_bytes())

    committed = json.loads(SCORED_CASES.read_bytes())["cases"]
    expected = Counter(
        _row(finding)
        for case_id in HAND_CRAFTED_CASES
        for finding in committed[case_id]["findings"]
    )
    scored = Counter(_row(f) for f in payload["findings"] if f["resource_identity"] in DECLARED)
    assert scored == expected


@needs_scanners
def test_live_the_two_corpus_folders_reach_the_committed_corpus_record() -> None:
    """Every corpus-level figure in the dissertation was computed from captures of these two
    folders. This scans them again and requires the same ranked findings back, one for one:
    resource, class, scanner, rule, score, band, the six contributions and their states.

    Catches the live path and the replayed path drifting apart - and would also catch a
    scanner, at its pinned version, no longer reporting what it reported when the corpus
    was captured."""
    declared, _ = score_run.merged_declared(load_and_validate(score_run.GROUND_TRUTH))

    def full_row(finding: Mapping[str, Any]) -> tuple[Any, ...]:
        return (*_row(finding), tuple(sorted(finding["factor_states"].items())))

    live: list[dict[str, Any]] = []
    for name in score_run.CORPUS_V0:
        folder = score_run.ROOTS[name].scan_root
        live += cli.analyse(folder, declared=declared, scan=cli.live_scan)["findings"]
    committed = json.loads(SCORED_CORPUS.read_bytes())["findings"]

    assert len(committed) == 1016
    assert Counter(map(full_row, live)) == Counter(map(full_row, committed))
