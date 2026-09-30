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

S0, S1, S2, S3a and S3b complete. **S4 is next** (the scoring engine and
reporting); **S3c** (convention-based auto-inference of the two declared factors)
was split out of S3b and can run before or after S4. S0 pinned the toolchain and
harvested an empirical rule-ID inventory over a vendored corpus. S1 authored
the five specification artifacts the runtime and the harness are built
against:

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
asserted, and is pinned by tests. The per-level `source` strings are a
**partially audited** artifact, and the flag stays `false` for one reason only.

The citation audit ran on 2026-09-30 and is committed at
`docs/superpowers/specs/2026-09-30-rubric-citation-audit.md`. Measured over the
**86 citation claims** these 33 levels make:

- **69 verified supported.** 62 of those come from four documents that came back
  entirely clean — CVSS v3.1 (26 claims), NIST SP 800-30 Rev.1 (32), the OWASP
  Risk Rating Methodology (2), OWASP A02:2021 (2) — and 7 more sit alongside
  defects in A05, A01 and FIPS 199. Do not conflate the two figures: 62 counts
  *clean documents*, 69 counts *supported claims*.
- **6 found defective**, reworded in commit
  `dddde15`: three A05 mis-locations (the dev/QA/prod parity statement is a *How
  to Prevent* recommendation, not a finding), A01 cited for object storage it
  never mentions, FIPS 199's `criticality` L0 gloss contradicted by its own
  footnote 4 (`NOT APPLICABLE` is confidentiality-only), and **`"OWASP IaC
  Security"`, which names no OWASP resource at all** — deleted, not reworded.
  69 + 6 + 11 = 86; the audit's Erratum 3 records why an earlier 62/13/11 split
  was wrong.
- **11 unverified** — every NSA-CISA Kubernetes Hardening Guidance claim. The
  primary source is unreachable from this host: `media.defense.gov` returns 403
  on both path forms via WebFetch *and* curl with a browser UA, and `cisa.gov`
  404s. A MITRE summary mirror exists and was **deliberately not substituted**;
  auditing against someone else's summary establishes nothing about the
  standard's words while reporting itself as verification.

So the rule is now narrower than it was, and worth stating exactly: **a `source`
string may be quoted in the dissertation unless it rests on NSA-CISA, in which
case it may not.** Closing those 11 needs a copy of the guidance downloaded
manually and placed on disk — nothing in the framework blocks it, and it
blocks neither S3b nor S4. Flip `citations_audited` only then. A green suite is
still not that audit — the anchor test only checks that a standard's *name*
appears in the string.

One caution for whoever next edits a citation string in `rubric.json`. The
freeze permits citation edits and forbids touching a level's score, `meaning` or
`justification`. Enforce that by **proof, not care**: snapshot the document with
every `source` blanked, hash it, edit, re-hash, and refuse to write if the hashes
differ. That is how commit `dddde15` was made, and it is stronger evidence than a
reviewer reading the diff.

Two sub-projects draw on this. **S2** (complete — see below) authored the
evaluation corpus and its ground truth against `eval/ground_truth.schema.json`.
When authoring, `defaulted_factors` and `unresolved_factors` are the distinct
fields they are on purpose: PLAN Q4's missing-declared-value and PLAN Q9's
extractor-failure are reported as separate rates, and merging them makes that
report impossible after the fact. **S3** builds the scanner adapters under
`src/iacrisk/scanners/` (S3a, complete), the bounded context extractor (S3b,
next), and the scoring engine that enforces the coherence rules and the
exposure precedence rule S1 carries as data (S4). One trap to carry forward:
`normalize_severity` returns `int | str`, where the string is the explicit
`unknown` state — every call site must branch on it before arithmetic, or an
unguarded `+` concatenates or raises rather than scoring.

`docs/superpowers/specs/2026-09-19-s1-handoff.md` records these and five more
residual risks in full, with what each one costs if ignored. Read it before
starting S3b.

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

**S2** authored corpus v1, the evaluation ground truth against
`eval/ground_truth.schema.json`: **26 cases (21 vendored, 5 hand-crafted), 10
contrastive pairs, 5 scenarios**, covering all five domains, with zero orphan
cases. Its six acceptance gates are `tests/test_s2_gates.py`. A few facts a
future session will get wrong without stating them explicitly:

- **`severity` has no contrastive pair, by measurement, not by oversight.**
  Zero same-type resource pairs in the corpus share an identical issue-class
  set while differing in maximum severity — a rule's severity is fixed, so two
  resources differing in severity within one class means a *different* rule
  fired, which changes the class set too. Checkov also contributes no integer
  severity at all in this corpus. Gate 2 asserts the zero directly rather than
  leaving it as an absence a later reader could "fix" with a pair that
  isolates nothing.
- **Three taxonomy classes map to no rubric factor**: `networking-egress-exposure`
  (data exfiltration; a distinct property from inbound exposure),
  `containers-host-isolation-breakout` (hostPID / hostPath / SA-token
  automount), and `iam-hardcoded-secrets` (credential exposure in provider
  config, user_data, Lambda env or manifests - exercised by
  `ec2-web-host-compute`, ec2.tf:15-16, CRITICAL). Findings in those classes
  score on severity plus declared context only, with no factor capturing the
  risk itself. `compute-instance-metadata-hardening` and
  `containers-image-supply-chain` read as further candidates of the same
  shape, and the set is not established as complete - a systematic
  28-class x 6-factor sweep is S4's, once a factor-mapping rule exists. S4
  must rule: widen the factor set, or state the risk is out of scope.
- **The oracle is a blinded LLM reviewer, and agreement is reported as a
  number, not a claim**: exact-tier agreement 3 of 5 scenarios; rank
  correlation (Kendall's τ_b) by scenario: storage 1.000, networking 1.000,
  iam 1.000, compute 0.333, containers 0.500; 0 `disagree` verdicts. The
  pre-registered rule (design spec §5): the author's ordering stands as ground
  truth regardless of verdict, and any `disagree` scenario would be excluded
  from the headline figure and reported separately — none was, so all five
  contribute, two only partially.
- **The compute scenario is contested.** The blinded reviewer's ordering is
  better grounded — it read the Privilege factor from source
  (`db-app.tf:206-225`, `:247`), which the author's ordering did not — but the
  author's stands under the pre-registered rule. Re-authoring it needs a fresh
  blinded review, not a patch.
- **Single-factor purity is an authored judgement, not machine-proven.** No
  class-to-factor mapping exists anywhere in the data, and a class named for a
  factor is not evidence of that factor: `iam-authentication-controls` and
  `networking-egress-exposure` both looked like factor evidence and were not,
  caught only by inspection. `tools/paircand/generate.py` makes each pair's
  class difference explicit and re-derivable; it does not establish that the
  named factor is the correct one.
- **Two numbers, never averaged into one.** Pairs: 10 authored, 10
  contributing — none touches a case flagged `excluded_from_quality_claims`.
  Scenarios: 5 authored, 3 free of excluded cases — the networking scenario
  contains `sgr-ingress-vpc-interpolated` and the compute scenario contains
  `ebs-web-host-storage-compute`, both flagged `excluded_from_quality_claims`.

`docs/superpowers/specs/2026-09-25-s2-handoff.md` records these and more
residual risks in full, with what each one costs if ignored. Read it before
starting S4.

**S3b** built layer 3: `src/iacrisk/context/` with one module per factor, the Q4
declared-context join, a Terraform reader on `python-hcl2`, a Kubernetes body reader,
the orchestrator and the coverage report. Seven acceptance gates in
`tests/test_s3b_gates.py`; 748 tests in the suite. Twelve decisions are recorded in the
design spec's §13 with cost-if-wrong, seven of them forced by implementation rather than
anticipated. Four figures a future session will get wrong without being told:

- **There are two resolution-rate numbers and they differ fourfold.** On the primary
  declared-context path (the 209 findings whose resource `corpus-v1` declares),
  **20.1% are low-confidence, so 79.9% are usable for prioritization-quality claims**.
  Across all 1055 corpus-v0 findings it is **78.3%** — because v0 is the measurement
  corpus and `corpus-v1` declares only 20 identities. Reporting the second as the
  framework's resolution rate mislabels it exactly as reporting Tier-2's 91
  same-scanner candidates as cross-scanner overlap would.
- **Exposure is unresolved on 959 of 1025 eligible findings (93.6%), by design.** PLAN
  Q9's closed pattern list means anything that is not a security group or rule, a
  public-flagged resource, a bucket with an attached public-access-block, or a K8s
  `Service`/`Ingress` is unresolved, never low. On those findings exposure contributes a
  constant 3 and does **no ranking work**. It resolves correctly on the cases the oracle
  turns on — the networking scenario's three tiers reproduce from code — so the honest
  framing is that it discriminates *within* the supported patterns.
- **Body coverage is asymmetric: Terraform 99.1%, Kubernetes 46.3%.** The Terraform
  misses are 4 findings on a `data` block. The Kubernetes gap is roughly half *parsing*
  rather than scope: 4 of 22 manifests are Helm templates carrying Go templating and do
  not parse as YAML. Attributing the whole Kubernetes rate to the pattern list is wrong.
- **`exposure` is inbound reachability only.** An egress `0.0.0.0/0` does **not** trigger
  the precedence rule; egress risk maps to `networking-egress-exposure`, one of the three
  classes with no rubric factor. Reading egress as inbound inverts the networking
  scenario's expected ordering.

**One process lesson from S3b, worth more than any single figure.** A defect that left
**0 of 217** container-scoped Kubernetes identities matching the body index was invisible
to seven gates, 746 tests, `ruff` and `mypy` — because every Kubernetes test built its
own index keyed the way the code expected. **A test that builds its own fixture cannot
discover that the real key shape differs.** What found it was a measurement over the real
corpus. Before S4 reports any figure, check the real *match rate*, not just a green suite.

`docs/superpowers/specs/2026-09-30-s3b-handoff.md` records these and six more residual
risks in full, with what each costs if ignored. Read it before starting S4 or S3c.

**The default-fallback washout is arithmetically live, and S3b/S4 must handle it.**
Measured from `rubric.json`: the five context factors' `unresolved_default` values
are exposure 3, privilege 4, sensitivity 3, criticality 4, encryption 2 — **sum
16**. Severity spans 1–5, so an **all-defaulted finding scores 17–21, which is
*always* High**, at both ends of the range. Worse, `unknown_resolves_to` is 4 and all
489 checkov rows in corpus v0 carry null severity, so a checkov finding with no
resolved context at all lands on exactly **20 — High**. If layer 3 resolves little,
the ranking degenerates to one band and the prioritization claim evaporates.

The rubric already carries the mitigation as data, in the `unresolved_default_reporting`
coherence rule: report band distribution **split by count-of-defaulted-factors**, flag
findings above a defaulted-factor threshold as low-confidence and **exclude them from
prioritization-quality claims**, and carry the stacked-default total into the Q10
sensitivity analysis. **That threshold is not specified anywhere** — choosing it is
S3b's or S4's decision, and it must be chosen before scoring output exists or it is a
tuned parameter rather than a frozen one.

**Draft dissertation chapters live in `docs/writeup/`**: `03-framework-design.md` and
`04-research-methodology.md`, plus a `README.md` carrying the provisional chapter
numbering and two standing rules — every number traces to a committed artifact, and
no rubric `source` string resting on NSA-CISA may be quoted. Results and evaluation
chapters need S4 and S5; there is no scoring output to write about yet. The chapters
are written from the measured record, so a figure that changes in an artifact must be
changed there too.

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
