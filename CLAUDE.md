# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**A framework for risk-aware security misconfiguration detection and prioritization in cloud Infrastructure-as-Code (IaC) environments.**

MSc in Computer Science (Cloud Computing) research project, University of Moratuwa — Jayathissa E.A.T.N. (258243J), November 2026. This is a **design-oriented research** project: the deliverable is a technical artifact (the framework) *plus* its evaluation, not just working code. Design/implementation decisions should trace back to the research questions and objectives below.

### Core idea

Existing rule-based IaC scanners (Checkov, tfsec, Trivy) detect *many* misconfigurations but emit flat, severity-labeled findings with little context — causing alert overload and weak remediation prioritization. This framework **does not replace scanners**; it adds a prioritization layer on top of their output, enriching each finding with cloud context and producing ranked remediation categories (Critical / High / Medium / Low).

The prioritization layer is the **main research contribution**. Keep it separable from detection — it will be evaluated and revised independently.

## Architecture (5 layers)

The framework is a pipeline. Preserve this separation of concerns when implementing:

1. **IaC Input** — accept Terraform files and Kubernetes YAML manifests (CloudFormation / ARM / Helm are conceptually in scope but not the evaluation focus).
2. **Security Scanning** — run existing scanners (Checkov, tfsec, Trivy) to produce baseline findings. This layer has a home as of S0: `tools/harvest/` runs the scanners over the pinned corpus (`run.py` orchestrates, `walkers.py` reads each scanner's JSON) and emits `artifacts/rule-inventory.json`. The S3 adapters land under `src/iacrisk/scanners/`, which does not exist yet. Tool-agnostic: parse each scanner's output into a common finding record (issue id, description, severity, affected resource, file path, remediation suggestion) — with the measured caveat on severity below, which is not present in every scanner's output.
3. **Context Extraction** — enrich each finding with contextual attributes. The two factors not reliably derivable from IaC code (Resource Sensitivity, Environment Criticality) enter via a **declared-context** input on the primary evaluation path; a convention-based **auto-inference** mode is built and evaluated as a second mode. Other factors are parsed from the flagged resource definition **and bounded related resources for a closed list of supported exposure patterns** (literals-only; unresolved values are represented as an explicit `unresolved` state — conservatively scored, excluded from prioritization-quality claims, or sensitivity-analysed — never silently defaulted to low).
4. **Risk Scoring** — apply the transparent weighted additive model (below) to compute a priority score.
5. **Reporting** — rank findings and map scores to remediation priority categories.

## Risk scoring model

**Explainable weighted additive model — NOT machine learning.** Every factor and weight must be inspectable, justifiable, and adjustable. (Learning-based scoring is explicitly future work.)

```
Risk Score = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk
```

Contextual risk factors and their scoring ranges:

| Factor | Range | Meaning |
|---|---|---|
| Scanner severity | 1–5 | Baseline severity from the IaC scanner |
| Public exposure | 0–5 | Reachable from the public internet? |
| IAM privilege scope | 0–5 | Degree of sensitive/administrative permission |
| Resource sensitivity | 0–5 | Business/data sensitivity of the affected asset |
| Environment criticality | 0–5 | production vs staging vs development |
| Encryption risk | 0–3 | Required encryption/data-protection missing? |

The Severity row assumes every finding arrives carrying one. Measured over corpus v0, it does not: 489 of 1055 rows have no severity at all and every one of them is Checkov (*Current state* below has the numbers). What fills that gap is S1/S3's normalization decision, deliberately not fixed here, and it is an `unresolved` value in layer 3's sense — not a silent Low.

Priority mapping (thresholds fixed a priori from the score structure and frozen before evaluation; threshold/weight movement is reported as a *sensitivity analysis*, not tuned to fit the test data):

| Priority | Score | Action |
|---|---|---|
| Critical | ≥ 22 | Block deployment, remediate immediately |
| High | 16–21 | Fix before production / require approval |
| Medium | 9–15 | Schedule in normal sprint/backlog |
| Low | < 9 | Monitor / document / fix when convenient |

Note: the additive model has a max possible score of 28 (5+5+5+5+5+3) and min of 1. If you change any factor range or add a factor, revisit the priority thresholds — they are coupled to the score ceiling.

## Evaluation

The framework is evaluated on **prioritization quality**, not detection accuracy (detection is delegated to the baseline scanners). Baseline = raw scanner severity output — buildable from Trivy and tfsec rows as they stand, and not from Checkov's, which carry no severity in corpus v0; the normalization that closes that gap is S1/S3's to specify and to report. Framework output = the contextually re-ranked list. Test cases cover storage, networking, IAM, compute, and container workloads, built from open-source examples, benchmark repos, and deliberately-insecure configs.

Evaluation metrics: **normalization/retention coverage** (not detection accuracy — that is delegated to the scanners), **prioritization usefulness** (measured against a defined oracle: contrastive-pair pass/fail + scenario-expected ordering), **alert reduction** (reported as two separate numbers — deduplication reduction vs. Critical/High priority-band reduction, never combined), **ranking consistency** (split into auto-inference agreement and model sensitivity), and **baseline comparison** (rank-change table vs. a scanner-severity-normalized baseline, each change justified by contextual factors).

## Scope guardrails

- **In scope:** pre-deployment (static) analysis of IaC. Terraform + Kubernetes primary.
- **Out of scope:** runtime intrusion detection, malware analysis, full cloud-provider monitoring, a complete enterprise CSPM platform, multi-cloud production repos, ML-based scoring. Don't let feature work drift into these — they are named as future work.

## Current state

S0, S1 and S3a complete. S3b is next and takes layer 3 (context extraction). S0
pinned the toolchain and harvested an empirical rule-ID inventory over a
vendored corpus. S1 authored the five specification artifacts the runtime and
the harness are built against:

- `src/iacrisk/data/taxonomy.json` — 28 issue classes over the five tested
  categories, plus one mapping row per observed `(scanner, rule_id)`. All 255
  rule IDs in corpus v0 map; an unseen rule takes an explicit
  `unmapped:<scanner>:<rule_id>` class rather than a guess.
- `src/iacrisk/data/rubric.json` — the six source-anchored factors, the frozen
  1–28 bounds and priority bands, the per-scanner severity-normalization table,
  and the design spec's three structural coherence rules plus its orthogonality
  note, carried as data so the scoring engine enforces them rather than
  reinventing them.
- `eval/ground_truth.schema.json` + `eval/ground_truth.py` — the three
  ground-truth record types and a validator that hard-rejects a malformed case
  rather than skipping it.
- `src/iacrisk/identity.py` — canonical Terraform and Kubernetes identity, path
  normalization, and the dedupe key.

**Factor ranges and priority bands are frozen** as of S1, before any scoring
output exists. Later movement is reported as sensitivity analysis (PLAN Q10),
never tuned to fit the test data. `tests/test_s1_gates.py` holds the five
acceptance gates and the freeze.

**What the freeze does and does not cover.** `rubric.json` asserts
`structure_frozen: true` and `citations_audited: false`, and they are separate
claims on purpose. The structure — six factors, their ranges, the 1–28 bounds,
the bands — was fixed before any scoring output existed, computed rather than
asserted, and is pinned by tests. The per-level `source` strings are **not**
audited: the verification pass behind them ran at design time, and its
corrections sat in spec prose for a month before reaching the artifact. **Do not
quote a `source` string in the dissertation until an audit of all 33 levels
against the primary sources is committed.** A green suite is not that audit —
the anchor test only checks that a standard's *name* appears in the string.

Two sub-projects draw on this. **S2** authors the evaluation corpus and its
ground truth against `eval/ground_truth.schema.json` — gate 4 is met for the
schema and the validator, not for a corpus of real cases, which do not exist
yet. When authoring, use `defaulted_factors` and `unresolved_factors` as the
distinct fields they are: PLAN Q4's missing-declared-value and PLAN Q9's
extractor-failure are reported as separate rates, and merging them makes that
report impossible after the fact. **S3** builds the scanner adapters under
`src/iacrisk/scanners/`, the bounded context extractor, and the scoring engine
that enforces the coherence rules and the exposure precedence rule S1 carries as
data. One trap to carry forward: `normalize_severity` returns `int | str`, where
the string is the explicit `unknown` state — every call site must branch on it
before arithmetic, or an unguarded `+` concatenates or raises rather than
scoring.

`docs/superpowers/specs/2026-09-19-s1-handoff.md` records these and five more
residual risks in full, with what each one costs if ignored. Read it before
starting either sub-project.

**S3a** built layers 1-2 plus Q8 deduplication: file discovery, the Kubernetes
resource index, the three scanner adapters under `src/iacrisk/scanners/`, the
two-tier dedupe (`src/iacrisk/dedupe.py`), the retention-coverage report
(`src/iacrisk/report.py`), and lockfile-driven scanner invocation. Its six
acceptance gates are `tests/test_s3a_gates.py`. A few figures a future session
will get wrong without stating them explicitly:

- **The reported deduplication number is Tier 1 only**: 39 of 1055 findings
  removed (3.7%), from 35 groups, exactly 1 of them cross-scanner.
- **Tier 2 is two numbers that must never be combined.** 207 candidates total,
  splitting into 116 cross-scanner (genuine rule-family overlap between
  scanners) and 91 same-scanner (one scanner raising two or more findings on
  one resource in one class that no fingerprint separates - a limit of this
  method, not scanner overlap). Three mechanisms produce the 91, not two: the
  taxonomy grouping many rule IDs into 28 classes, the absent fingerprint, and
  **one rule firing more than once on one resource** - measured on exactly 3 of
  the 91, which carry a single distinct rule id and so have no taxonomy-grouping
  cause at all (spec §7's 2026-09-25 erratum). Reporting 207 as cross-scanner overlap
  mislabels the 91; the same-scanner figure belongs in the limitations
  discussion, never in the alert-reduction result. By raising scanner the 91
  split trivy 71, checkov 19, tfsec 1 - trivy dominates structurally because
  its fingerprint is `None` on every finding (spec §6).
- **Cross-scanner attribute normalization is named future work** (spec §13):
  a mapping from each scanner's attribute vocabulary to one canonical spelling
  would move most Tier-2 candidates into Tier-1 exact collapses, materially
  raising the measured deduplication number. Not attempted in S3a, S3b, S4 or
  S5 as currently scoped.
- **A pytest trap.** `addopts` already carries `-q --strict-markers -rs`
  (Commands, above), but under those flags a *failing* test prints `F` and a
  traceback and emits no line beginning with `FAILED` - that needs `-rf`/`-ra`.
  So `pytest | grep -c "^FAILED"` returns `0` for a red suite. **Judge pytest
  by its exit code, not by grepping its output.**
- **`findings_in` is derived, not measured.** `ScannerCoverage.findings_in` is
  `findings_out + len(dropped)`, with no independent raw-record count carried
  inside `AdapterResult`. The retention *tests* close the gap by counting raw
  records from the fixtures independently; the *field* itself stays derived.
  Plumbing a real `raw_records_seen` through the adapters is recorded future
  work for S3b or S5.

`docs/superpowers/specs/2026-09-22-s3a-handoff.md` records these and more
residual risks in full, with what each one costs if ignored. Read it before
starting S3b.

Python is pinned to **3.12** by `.python-version`, and `uv run python -V` reports
3.12.13. The pin is Checkov 3.3.12's: its classifiers stop at 3.12. Four
interpreter facts about this host, because they are easy to state backwards:

- **`python3` is the broken Microsoft Store alias** — `where.exe python3` finds
  only `C:\Users\<you>\AppData\Local\Microsoft\WindowsApps\python3.exe`, which is a stub.
- Bare **`python`** resolves to `.venv\Scripts\python.exe` (3.12.13) while the venv is
  ahead of WindowsApps on PATH, and to that same Store stub when it is not.
- A system **3.13.5** is installed at `C:\Python313` and is not on PATH.
- uv manages **3.12.13 and 3.14.0** side by side (`uv python list --only-installed`).

Which is why `.python-version` and `uv run` are load-bearing rather than
decorative: **always `uv run python`**, never bare `python`.

### Commands

```powershell
uv sync                      # install/refresh dependencies
uv run pytest                # full suite; addopts already carries -q --strict-markers -rs
                              # judge by EXIT CODE, not by grepping output for "FAILED" -
                              # under -q a failing test prints F + a traceback with no
                              # "FAILED" line (needs -rf/-ra), so a grep for it returns 0
                              # even on a red suite
uv run pytest tests/harvest  # harvest tests only
uv run ruff check .          # lint
uv run ruff format .         # format (mutating)
uv run ruff format --check . # the gate form; must report 0 files to reformat
uv run mypy                  # type-check - BARE, no path arguments (see below)

.\tools\bootstrap.ps1            # install + checksum-verify the pinned scanners
.\tools\bootstrap.ps1 -Verify    # re-assert the pins without downloading
.\tools\vendor_corpus.ps1        # re-vendor corpus v0 at the pinned commits
.\tools\capture_fixtures.ps1     # re-capture the golden scanner JSON fixtures

uv run python -m tools.harvest.run   # regenerate artifacts/rule-inventory.json + artifacts/raw/
```

**Give `mypy` no path argument.** A path overrides `[tool.mypy] files` entirely:
measured on this tree, `uv run mypy` checks 19 files and `uv run mypy src tools
eval` checks 9 — dropping every test file — and both print `Success`. Bare is the
only form that cannot drift from the config.

**Re-running the harvest dirties `artifacts/raw/`.** `git status` will usually show all
five documents modified with nothing changed in meaning: checkov, trivy and tfsec each
reorder list elements between runs, and trivy also stamps a fresh `CreatedAt` and
`ReportID`. That is why the comparison against the golden fixtures is order-insensitive
(`tests/harvest/test_run.py`) rather than a byte comparison; the derived inventory itself
comes back with identical numbers.

Two notes on the PowerShell scripts. `-Verify` never downloads, but it does
rewrite `tools/resolved.json` unconditionally; that file is gitignored, so the
rewrite is invisible to `git status` (verified byte-identical when re-run against
an already-verified tree). And `capture_fixtures.ps1` overwrites the golden
fixtures under `tests/harvest/fixtures/`, which are the control the harvest is
compared against — re-capture deliberately, not as a habit.

### Pinned versions

Scanners — `tools/scanners.lock.json`: Checkov **3.3.12** (`uv-tool`), Trivy
**0.74.0** and tfsec **1.28.14** (`github-release`, SHA-256 pinned). The
`platforms` list in that file is the platform matrix, and it is data: tfsec
declares `["terraform"]` only, so tfsec-on-Kubernetes is an absence the runner
derives from the lockfile, never an `if` in the code.

Corpus v0 — `tools/corpus.lock.json`: TerraGoat at `729f8da6`
(`terraform/aws` subtree) and Kubernetes-Goat at `723a0db4` (`scenarios`
subtree), five declared cases over two scan roots.

**Checkov is an isolated `uv tool` and must never become a project dependency.**

### Severity in corpus v0, measured

From `artifacts/rule-inventory.json`, 1055 rows: **489 of them (46.4%) carry no
severity at all, and every one of the 489 is Checkov** — 221 on the Terraform
root, 268 on the Kubernetes root. Severity reaches Checkov's JSON only through
the API-key `policyMetadata` path. The other 566 rows (Trivy 447, tfsec 119)
carry exactly four levels: CRITICAL, HIGH, MEDIUM, LOW.

**Corrected 2026-09-25.** This paragraph previously said the public path "fills
`guideline` and `id`". Measured on the committed fixtures: `check_id` is present
on 489 of 489, but **`guideline` is null on 489 of 489** — it is not filled
either, which is what `scanners/checkov.py`'s `_optional_str` docstring already
records. The S3a whole-branch review caught the contradiction between this file
and the fixtures.

Read that as a property of **corpus v0 as measured on this host**, not of the
scanners: Trivy's severity vocabulary carries a fifth level this corpus does not
exercise, so the four observed levels are a corpus observation and not a scanner
contract. Do not pick a numeric mapping for the absent severities here — that is
S1/S3's normalization spec, and spec §5 asked for these facts precisely so that
spec could be written from them.
