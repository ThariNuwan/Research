"""Harvest orchestration and CLI - the only harvest module that runs a process.

Usage:
    uv run python -m tools.harvest.run

Five scanner runs, not fourteen. `tools/corpus.lock.json` declares five cases over two
distinct `(platform, scan_root)` pairs, and its top-level `attribution` rule forbids
per-case scanning in writing: the four Terraform cases share one root, so scanning per
case would report the same finding set four times over and inflate both the deduplication
count and every per-category total. `tools/capture_fixtures.ps1` captured its six fixtures
the same way - one document per scanner per root - which is why they are named
`<scanner>-<platform>`, and `artifacts/raw/` follows that naming rather than inventing a
per-case document that no scanner produces.

Scanning per root is also what makes attribution this module's work. `walk()` stamps one
`case_id` on every row of a document, and a document spanning four cases has no single
right answer to stamp; its docstring says exactly that and hands the `unattributed` state
forward to "the later task that walks the corpus". This is that task. Rows arrive holding
`UNATTRIBUTED` and are re-attributed by path - which cannot be a prefix test on the
reported string, because the three scanners spell one file three incompatible ways and
checkov spells it two ways inside one run (`\\ec2.tf` in its `terraform` block,
`/ec2.tf` in the `secrets` block of the same document). Measured over the six committed
fixtures, 0 of 1055 rows attribute on the reported path as-is, so `normalize_target` is
load-bearing rather than defensive.

Bytes, not text, in both directions - both measured on this host rather than assumed:

- Scanner stdout is captured as bytes and decoded UTF-8 explicitly. `text=True` would
  decode it with the ANSI codepage, cp1252 here, and the 114 non-ASCII characters across
  two fixtures are valid UTF-8 that cp1252 maps without raising - so the corruption would
  be silent. Round-tripped that way, `tests/harvest/fixtures/trivy-kubernetes.json`
  re-encodes 476 bytes larger, every one of them a mangled quotation mark or check mark
  landing in a rule description in the committed inventory.
- The lockfiles are read as bytes, because `json.loads` accepts a UTF-8 BOM in `bytes` and
  raises `Unexpected UTF-8 BOM` on `str`. `tools/resolved.json` is written by
  `tools/bootstrap.ps1` on a PowerShell 5.1 host, where a BOM is one `Set-Content` away.
  `tools/harvest/provenance.py` reads it the same way, for the same reason.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.harvest.model import InventoryRow
from tools.harvest.provenance import build_provenance
from tools.harvest.tally import tally
from tools.harvest.walkers import walk

REPO_ROOT = Path(__file__).resolve().parents[2]

UNATTRIBUTED = "unattributed"
"""The state `tools/corpus.lock.json`'s `attribution` rule defines for a finding under a
scanned root that no case `path` claims: "counted and reported as such, never dropped and
never folded into a default category". Ten of the Terraform root's fourteen `.tf` files are
named by no case, so this is the ordinary state of a large minority of rows - an explicit
state, not a failure and not a fallback for a row whose case is merely hard to find."""

NORMALIZATION_RULE = "separators-to-posix-then-cut-at-or-join-to-scan-root"
"""Named in the artifact beside the counts it produced, the way `tally()` names
`RULE_ID_RECONCILIATION`: a reader who disagrees with the rule can at least see which one
ran, and a change to it shows up as a diff in the deliverable rather than only in code."""

SCANNER_TIMEOUT_SECONDS = 900

WINDOWS_SEPARATOR = "\\"
"""Normalization is a string operation on a path the scanner reported, not on a path this
host has. `PurePath` would resolve `\\ec2.tf` against the running platform's flavour, so on
a POSIX host checkov's separators would survive as filename characters."""

SCANNER_ARGV: dict[str, tuple[str, ...]] = {
    "checkov": ("--output", "json", "--compact", "--skip-download", "--directory"),
    "trivy": (
        "config",
        "--format",
        "json",
        "--quiet",
        "--disable-telemetry",
        "--skip-check-update",
    ),
    "tfsec": ("--format", "json", "--no-colour", "--no-module-downloads"),
}
"""The vectors Task 5 proved, argument for argument, with the scan root appended last.

`artifacts/scanner-behavior.json` records what each capture ran and
`tests/harvest/test_run.py` compares this table against it, so a drifted flag fails a test
rather than quietly producing a document the walkers were never written against.

Three of these flags are pin integrity, not noise: `--skip-download`,
`--skip-check-update` and `--no-module-downloads` are what stop a scanner fetching rules
or modules mid-run, which would put an unpinned rule set into a pinned toolchain's
inventory. `--no-colour` keeps ANSI escapes out of JSON on stdout. `--compact` drops a
verbatim echo of vendored corpus source and removes no key. `tools/capture_fixtures.ps1`
logs the flags it rejected and why - checkov's `--quiet` drops three keys out of `results`,
tfsec's `--soft-fail` forces exit 0 and makes the exit-code observation unanswerable, and
`--framework` is withheld so checkov's own multi-framework detection stays visible. Read
that log before deviating; each rejection was measured, not reasoned."""


def applicable_scanners(lock: Mapping[str, Any], platform: str) -> list[str]:
    """Scanners `tools/scanners.lock.json` declares applicable to `platform`, sorted.

    Applicability is data, never an if-branch here. tfsec's absence from Kubernetes is a
    declared property of tfsec, so widening the lockfile widens the harvest and nothing in
    this module needs to know that tfsec is the Terraform-only one.

    An entry with no `platforms` key is applicable to nothing, which is the safe direction:
    a scanner added to the lockfile without declaring its platforms does not silently get
    pointed at every corpus root.
    """
    return sorted(
        name for name, entry in lock["scanners"].items() if platform in entry.get("platforms", [])
    )


def scanner_command(scanner: str, exe: str, platform: str, target: str) -> list[str]:
    """Build one scanner's argv list. Never a shell string, and the root always last.

    A list is passed straight to `CreateProcess`, so a corpus path containing a space needs
    no quoting and can carry none by accident. `platform` is accepted and unused: what a
    scanner is pointed at is a platform decision, but how it is invoked is not, and a
    per-platform argv branch here would be a second copy of the matrix that
    `tools/scanners.lock.json` already holds.

    Raises `KeyError` for an unknown scanner - the same contract as `walk()`, and for the
    same reason: a scanner this repo has not pinned has no proven invocation, so a run that
    guessed one would produce a document no walker was written against.
    """
    return [exe, *SCANNER_ARGV[scanner], target]


def scan_roots(corpus_lock: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The distinct `(platform, scan_root)` pairs to scan, each carrying its cases.

    Five cases, two roots: this is where the deduplication the `attribution` rule requires
    actually happens. Grouping is on the pair rather than on the root alone, so two roots
    under one platform stay two runs instead of collapsing into one.
    """
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for case in corpus_lock["cases"]:
        grouped.setdefault((case["platform"], case["scan_root"]), []).append(case)
    return [
        {
            "platform": platform,
            "scan_root": scan_root,
            "cases": sorted(cases, key=lambda case: str(case["id"])),
        }
        for (platform, scan_root), cases in sorted(grouped.items())
    ]


def _cut_at_scan_root(slashed: str, scan_root: str) -> str | None:
    """`slashed` from the first occurrence of `scan_root` at a path boundary, else None.

    The boundary test is what separates this from `str.find`: a root of `.../aws` must not
    match inside `.../aws-legacy/main.tf`. Corpus v0 has no such sibling, so nothing here
    exercises it - which is why it is a condition rather than a comment.
    """
    start = 0
    while True:
        index = slashed.find(scan_root, start)
        if index == -1:
            return None
        end = index + len(scan_root)
        starts_at_boundary = index == 0 or slashed[index - 1] == "/"
        ends_at_boundary = end == len(slashed) or slashed[end] == "/"
        if starts_at_boundary and ends_at_boundary:
            return slashed[index:]
        start = index + 1


def normalize_target(target: str, scan_root: str) -> str:
    """One reported path, as a repo-relative POSIX path comparable with a case `path`.

    Two rules, in this order, and both were derived from the six committed fixtures rather
    than from any scanner's documentation:

    1. Separators become `/`. checkov mixes them inside a single value
       (`/batch-check\\job.yaml`) and contradicts itself across framework blocks in one run,
       so a per-scanner rule would still be wrong within one scanner.
    2. A path that already contains the scanned root is cut there - tfsec reports
       drive-absolute (`D:\\Research\\corpus\\vendor\\...`) - and any other path is treated as
       relative to the root with leading separators stripped. That last strip is the subtle
       one: checkov's `/ec2.tf` looks absolute and is root-relative, so testing for a
       leading separator to decide absoluteness attributes it to nothing.

    `""` - the walkers' explicit no-path-reported state - normalizes to `""` and is
    unattributable. Returning the scan root for it would silently attribute a pathless
    finding to whichever case owns the root.
    """
    if not target:
        return ""
    slashed = target.replace(WINDOWS_SEPARATOR, "/")
    cut = _cut_at_scan_root(slashed, scan_root)
    if cut is not None:
        return cut
    return f"{scan_root}/{slashed.lstrip('/')}"


def match_case(target: str, cases: Iterable[Mapping[str, Any]]) -> str | None:
    """The id of the case claiming an already-normalized `target`, or None.

    Takes a normalized path deliberately, so that a test can hand it a raw reported path and
    watch it match nothing: measured over the six fixtures, 0 of 1055 rows attribute without
    `normalize_target` first, so a caller that forgets it gets an all-unattributed inventory
    rather than a subtly wrong one.

    A case `path` claims a target that equals it, or that lies under it on a path boundary.
    Four of corpus v0's five case paths are files, for which the prefix branch is vacuous -
    nothing lives under `s3.tf/` - so one rule covers both file and directory cases without
    asking the filesystem what kind each path is. That matters because attribution runs
    against paths a scanner reported, which may name files this checkout does not have.

    The longest matching path wins. No corpus v0 row matches two cases, so this tie-break is
    unexercised; without it, a file case nested inside a directory case would resolve by
    lockfile order.
    """
    if not target:
        return None
    claims = [
        case for case in cases if target == case["path"] or target.startswith(f"{case['path']}/")
    ]
    if not claims:
        return None
    return str(max(claims, key=lambda case: (len(str(case["path"])), str(case["id"])))["id"])


def attribute(
    rows: Iterable[InventoryRow], cases: Sequence[Mapping[str, Any]], scan_root: str
) -> list[InventoryRow]:
    """Re-stamp `case_id` on rows `walk()` produced for one scanned root.

    `InventoryRow` is frozen, so this replaces rows rather than mutating them, and every
    other field - `target` above all, which S1's canonical-identity work reads - has to
    survive the replacement byte for byte. `dataclasses.replace` gives that for free; a
    hand-built `InventoryRow(...)` would silently reorder or drop a field.

    Pass only the cases declared for this root's platform. A Kubernetes row cannot belong to
    a Terraform case, and feeding the whole case list in would make that depend on paths
    happening not to collide.
    """
    attributed = []
    for row in rows:
        case_id = match_case(normalize_target(row.target, scan_root), cases)
        attributed.append(dataclasses.replace(row, case_id=case_id or UNATTRIBUTED))
    return attributed


def declared_case_ids(
    scanners_lock: Mapping[str, Any], corpus_lock: Mapping[str, Any]
) -> dict[str, list[str]]:
    """Per scanner, the case ids the platform matrix says that scanner covers.

    The universe comes from the two lockfiles crossed, never from the rows, and that is the
    whole point. tfsec never runs on the Kubernetes root, so `kg-scenarios` is not a case
    tfsec found nothing in - it is a case tfsec never saw. Seed the universe from observed
    rows and the two become one indistinguishable silence; seed it from the matrix and
    `kg-scenarios` is simply absent from tfsec's list, which is the true statement.
    """
    declared: dict[str, list[str]] = {}
    for name, entry in scanners_lock["scanners"].items():
        platforms = set(entry.get("platforms", []))
        declared[name] = sorted(
            str(case["id"]) for case in corpus_lock["cases"] if case["platform"] in platforms
        )
    return declared


def with_case_floor(
    by_scanner: Mapping[str, Any], declared: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    """`tally()`'s `by_scanner`, with every declared case present at zero rows or more.

    `tally()` builds its `cases` mapping from the rows it is handed, so a case that produced
    nothing is absent rather than zero - correct for `tally()`, which is not given the case
    universe and cannot invent one, and wrong for a deliverable, where absent and zero are
    different claims. Measured: tfsec's own `cases` arrives as Terraform-only, because tfsec
    on Kubernetes is a run the matrix prevented.

    A floor, not a filter, in both directions: it only ever adds keys, so a count against
    `UNATTRIBUTED` survives even though that is a row state and not a declared case, and a
    scanner the matrix does not name is passed through exactly as tallied.
    """
    floored: dict[str, Any] = {}
    for name, entry in by_scanner.items():
        counts: dict[str, int] = dict(entry["cases"])
        for case_id in declared.get(name, ()):
            counts.setdefault(case_id, 0)
        floored[name] = {**entry, "cases": {key: counts[key] for key in sorted(counts)}}
    return floored


def _read_json(path: Path) -> Any:
    """Parse a lockfile from raw bytes. See the module docstring for why not `read_text`."""
    return json.loads(path.read_bytes())


def _portable(argument: str, repo_root: Path) -> str:
    """One argv element with this checkout's path replaced by `<repo>`.

    `artifacts/scanner-behavior.json` records its captures this way and says so in its
    `argv_note`, so recording the same substitution here keeps the two comparable and keeps
    a machine-specific absolute path out of a committed artifact.
    """
    prefix = str(repo_root)
    if not argument.startswith(prefix):
        return argument
    return "<repo>" + argument[len(prefix) :].replace(WINDOWS_SEPARATOR, "/")


def _run_scanner(cmd: list[str]) -> tuple[bytes, bytes, int | None, str | None]:
    """Run one scanner: `(stdout, stderr, exit_code, error)`.

    A non-zero exit is normal, not a failure - checkov and tfsec exit 1 when they have
    findings, which is the whole point of a deliberately-insecure corpus - so the exit code
    is recorded and never branched on.

    A timeout becomes `("timeout", exit_code None)` and the run continues. Letting
    `TimeoutExpired` propagate would throw away every completed run and write no artifact at
    all because one scanner hung, which is the opposite of what the record is for; whatever
    partial stdout arrived is still written, as evidence of where it stopped.
    """
    try:
        # A fixed argv from SCANNER_ARGV, no shell: the target cannot be read as a flag or
        # as a command, whatever a corpus path contains.
        result = subprocess.run(
            cmd, capture_output=True, timeout=SCANNER_TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        return partial, stderr, None, f"timeout after {SCANNER_TIMEOUT_SECONDS}s"
    return result.stdout, result.stderr, result.returncode, None


def _rows_per_case(rows: Iterable[InventoryRow]) -> dict[str, int]:
    """Counts keyed by `case_id`, key-sorted, `UNATTRIBUTED` included as the state it is."""
    counts = Counter(row.case_id for row in rows)
    return {case_id: counts[case_id] for case_id in sorted(counts)}


def harvest(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Run every applicable scanner over every scan root once, and build the inventory.

    Provenance is built first, before any scanner runs. It is the one step that fails on a
    fresh clone - `tools/resolved.json` is gitignored, so a checkout without
    `.\\tools\\bootstrap.ps1` has no scanner paths - and failing in a second beats failing
    after five scanner runs. It also validates the file this function then reads `exe` out
    of, so there is one error path for a missing bootstrap instead of two.
    """
    provenance = build_provenance(repo_root)
    scanners_lock = _read_json(repo_root / "tools" / "scanners.lock.json")
    corpus_lock = _read_json(repo_root / "tools" / "corpus.lock.json")
    resolved = _read_json(repo_root / "tools" / "resolved.json")

    raw_dir = repo_root / "artifacts" / "raw"
    rows: list[InventoryRow] = []
    runs: list[dict[str, Any]] = []
    dispatched: set[str] = set()

    for root in scan_roots(corpus_lock):
        platform = str(root["platform"])
        scan_root = str(root["scan_root"])
        cases: Sequence[Mapping[str, Any]] = root["cases"]
        case_ids = [str(case["id"]) for case in cases]
        target = str(repo_root / scan_root)

        for scanner in applicable_scanners(scanners_lock, platform):
            dispatched.add(scanner)
            cmd = scanner_command(scanner, str(resolved[scanner]["exe"]), platform, target)
            print(f"==> {scanner} on {scan_root} ({platform})", file=sys.stderr)
            stdout, stderr, exit_code, error = _run_scanner(cmd)

            out_path = raw_dir / f"{scanner}-{platform}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(stdout)

            record: dict[str, Any] = {
                "scanner": scanner,
                "platform": platform,
                "scan_root": scan_root,
                "case_ids": case_ids,
                "argv": [_portable(part, repo_root) for part in cmd[1:]],
                "exit_code": exit_code,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "raw_path": out_path.relative_to(repo_root).as_posix(),
                "rows": 0,
            }
            runs.append(record)
            if error is not None:
                record["error"] = error
                continue

            try:
                # Explicit UTF-8, and a BOM would raise here rather than be tolerated.
                # `artifacts/scanner-behavior.json` records `stdout_has_bom` false on all six
                # captures, so a BOM appearing now is a change in scanner behaviour worth a
                # recorded error and a zero row count, not something to absorb silently.
                doc = json.loads(stdout.decode("utf-8")) if stdout.strip() else None
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                record["error"] = f"non-JSON output: {exc}"
                continue

            root_rows = walk(scanner, doc, UNATTRIBUTED) if doc is not None else []
            case_rows = attribute(root_rows, cases, scan_root)
            rows.extend(case_rows)
            per_run_case = _rows_per_case(case_rows)
            record["rows"] = len(case_rows)
            record["unattributed_rows"] = per_run_case.get(UNATTRIBUTED, 0)
            record["cases"] = {case_id: per_run_case.get(case_id, 0) for case_id in case_ids}

    inventory: dict[str, Any] = tally(rows, scanners=sorted(dispatched))
    # The case floor, applied here and nowhere else: `tally()` is not given the case
    # universe, this function reads it. See `with_case_floor`.
    inventory["by_scanner"] = with_case_floor(
        inventory["by_scanner"], declared_case_ids(scanners_lock, corpus_lock)
    )

    categories = {str(case["id"]): str(case["category"]) for case in corpus_lock["cases"]}
    per_case = _rows_per_case(rows)
    unattributed_rows = per_case.get(UNATTRIBUTED, 0)
    per_category: Counter[str] = Counter()
    for case_id, count in per_case.items():
        if case_id in categories:
            per_category[categories[case_id]] += count

    inventory["corpus"] = {
        "sources": corpus_lock["sources"],
        "case_count": len(corpus_lock["cases"]),
        "categories": sorted(set(categories.values())),
        "scan_roots": [
            {
                "platform": root["platform"],
                "scan_root": root["scan_root"],
                "case_ids": [str(case["id"]) for case in root["cases"]],
            }
            for root in scan_roots(corpus_lock)
        ],
        "attribution": {
            "rule_source": "tools/corpus.lock.json#attribution",
            "normalization_rule": NORMALIZATION_RULE,
            "unattributed_state": UNATTRIBUTED,
            "attributed_rows": len(rows) - unattributed_rows,
            "unattributed_rows": unattributed_rows,
            "rows_per_case": {case_id: per_case.get(case_id, 0) for case_id in sorted(categories)},
            "rows_per_category": {
                category: per_category[category] for category in sorted(set(categories.values()))
            },
        },
    }
    inventory["runs"] = runs
    inventory["provenance"] = provenance
    return inventory


def _pairs(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def main(argv: list[str] | None = None) -> int:
    """Write the inventory, print the figures the gate checks, and report a failed run.

    Returns 1 when any run recorded an error, while still writing the artifact: a hung or
    non-JSON scanner has to be visible in an exit code, and the four runs that worked are
    still evidence. Nothing here formats `missing_severity_rate` - it is `None` when there
    are no rows, and printing that as `0.0` would assert a measurement nobody made.
    """
    parser = argparse.ArgumentParser(description="Harvest the scanner rule-ID inventory.")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "artifacts" / "rule-inventory.json")
    args = parser.parse_args(argv)

    inventory = harvest()
    out_path: Path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys and one trailing newline, written as bytes: the inventory is committed, so
    # it has to diff cleanly and no newline translation may touch it.
    out_path.write_bytes((json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    totals = inventory["totals"]
    attribution = inventory["corpus"]["attribution"]
    print()
    print(
        f"rows={totals['rows']} distinct_rule_ids={totals['distinct_rule_ids']} "
        f"distinct_rules={totals['distinct_rules']} ({totals['rule_id_reconciliation']})"
    )
    print(
        f"missing_severity_rows={totals['missing_severity_rows']} "
        f"missing_severity_rate={totals['missing_severity_rate']}"
    )
    print(
        f"attributed={attribution['attributed_rows']} "
        f"unattributed={attribution['unattributed_rows']} "
        f"({attribution['normalization_rule']})"
    )
    print(f"rows per case:     {_pairs(attribution['rows_per_case'])}")
    print(f"rows per category: {_pairs(attribution['rows_per_category'])}")

    for case_id, count in attribution["rows_per_case"].items():
        if count == 0:
            print(f"WARNING zero-row case: {case_id}")
    failed = [record for record in inventory["runs"] if "error" in record]
    for record in failed:
        print(f"ERROR {record['scanner']}-{record['platform']}: {record['error']}")
    print(f"wrote {out_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
