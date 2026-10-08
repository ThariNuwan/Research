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

S0, S1, S2, S3a, S3b and S4 complete. **S5 (the independent evaluation harness and its
first results), S6's sensitivity analysis and S3c (auto-inference) are done, and were merged
into `main` by fast-forward on 2026-10-07** after the pre-merge review recorded below; all
three are recorded below. `main` is ahead of `origin/main` by everything since `e5bdd63` and **has not been
pushed**. The work was done on branch `s5-evaluation-harness`, which no longer exists
locally; `origin` holds a copy of it at `c1b47b3` (the remote-tracking reflog records that
push on 2026-10-07), four commits short of what was merged. **Every sub-project that produces a result is now built.** What remains is **the
write-up** (chapters 1, 2 and 7; chapters 5 and 6 are drafted, and the S4 handoff and
chapter 3 still carry superseded figures behind dated notes) and one item that needs a
person: the NSA-CISA citations. **Supervisor review of the oracle will not be sought** - the
project author ruled on 2026-10-08 that it is not needed. That closes a task, not a
limitation: `docs/PLAN.md` Q7 and `docs/supervisor-brief.md` both say the expected-ordering
labels get independent supervisor review, and a blinded LLM reviewer stood in. Chapters 4
(4.4.3, 4.7.1) and 6 (6.4.4, 6.10) now state that as a permanent threat to validity, not as
pending work. Do not write "not yet reviewed", and do not drop the statement either. S0 pinned the toolchain and
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
- **Taxonomy classes mapping to no rubric factor: 14 of 28, not the three this
  entry used to name.** S2 named `networking-egress-exposure`,
  `containers-host-isolation-breakout` and `iam-hardcoded-secrets`, flagged
  `compute-instance-metadata-hardening` and `containers-image-supply-chain` as
  further candidates, and said the set was **not established as complete** —
  a systematic 28-class x 6-factor sweep being S4's. **S4 ran that sweep and the
  doubt was justified: the answer is 14 classes, 434 of 1025 eligible findings
  (42.3%), against the 122 (11.9%) five classes implied — 3.6x.** The five were
  simply the ones someone had noticed. **The substantive 25.0% is a FLOOR**, because the
  test is per-class: five non-gap classes carrying 191 further findings (18.6%) name a risk
  their bearing factor only partly covers, which puts the upper bound at 43.6%. See `src/iacrisk/data/factor_map.json`
  (the committed 28 x 6 table, which did not exist before S4) and the S4 design
  spec section 1.4. **S4 ruled: do not widen the factor set** — argued in that
  spec's section 2.1 on the measured 25.0%, not the comfortable 11.9%.
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
`tests/test_s3b_gates.py`; 748 tests in the suite. **Thirteen** decisions are recorded in
the design spec's §13 with cost-if-wrong — two taken by the project author, six by the
spec, and **five forced by implementation**. Four figures a future session will get wrong
without being told:

- **There are two resolution-rate numbers and they differ fourfold.** On the primary
  declared-context path (the 209 findings whose resource `corpus-v1` declares),
  **13.9% are low-confidence, so 86.1% are usable for prioritization-quality claims**.
  Across all 1055 corpus-v0 findings it is **77.9%** — because v0 is the measurement
  corpus and `corpus-v1` declares only 20 identities. Reporting the second as the
  framework's resolution rate mislabels it exactly as reporting Tier-2's 91
  same-scanner candidates as cross-scanner overlap would.
- **Exposure is unresolved on 934 of 1025 eligible findings (91.1%), by design.** PLAN
  Q9's closed pattern list means anything that is not a security group or rule, a
  public-flagged resource, a bucket with an attached public-access-block, or a K8s
  `Service`/`Ingress` is unresolved, never low. On those findings exposure contributes a
  constant 3 and does **no ranking work**. It resolves correctly on the cases the oracle
  turns on — the networking scenario's three tiers reproduce from code — so the honest
  framing is that it discriminates *within* the supported patterns.
- **Body coverage: Terraform 99.1%, Kubernetes 100% - and the 46.3% this entry used to give
  for Kubernetes was a defect, not a property of the corpus.** The Terraform misses are 4
  findings on a `data` block. **Corrected 2026-10-06:** S3b recorded Kubernetes at 46.3%
  (268 of 579 context-eligible findings) and attributed "roughly half" of the gap to Helm
  templates that do not parse. **No part of it was Helm.** `build_body_index` rendered an
  omitted `metadata.namespace` as no segment while every finding's identity carried
  `default`, so 311 findings on 8 resources never met their body and scored privilege and
  encryption at the unresolved defaults. With S3a's namespace rule applied all 579 match.
  It is the 0-of-217 lesson below a second time, in the same module: the two tests that
  touched an un-namespaced manifest asserted the un-namespaced key, and so pinned the bug.
  **Every S3b and S4 corpus-level figure in this file that is not marked otherwise was
  measured with this defect present** - the S5 entry below gives the corrected ones.
- **`exposure` is inbound reachability only.** An egress `0.0.0.0/0` does **not** trigger
  the precedence rule; egress risk maps to `networking-egress-exposure`, one of the three
  classes with no rubric factor. Reading egress as inbound inverts the networking
  scenario's expected ordering.

**One process lesson from S3b, worth more than any single figure.** A defect that left
**0 of the 217 findings** on container-scoped Kubernetes identities (14 identities - the
217 was always a count of findings) matching the body index was invisible
to seven gates, 746 tests, `ruff` and `mypy` — because every Kubernetes test built its
own index keyed the way the code expected. **A test that builds its own fixture cannot
discover that the real key shape differs.** What found it was a measurement over the real
corpus. Before S4 reports any figure, check the real *match rate*, not just a green suite.

`docs/superpowers/specs/2026-09-30-s3b-handoff.md` records these and six more residual
risks in full, with what each costs if ignored. Read it before starting S4 or S3c.

**S4** built layers 4 and 5: `src/iacrisk/scoring/` with the committed 28 x 6
class-to-factor table and its loader, the scoring engine, the severity baseline, ranking
with ties preserved, the band-distribution reports and JSON/Markdown emission. Eight
acceptance gates in `tests/test_s4_gates.py`; 820 tests in the suite. Seven decisions are
recorded in the design spec's section 11 with cost-if-wrong. **Four measured facts a future
session will get wrong without being told** - and a fifth about the four: **every count
below was measured before the Kubernetes body-index defect was fixed on 2026-10-06** (the
S3b entry above), over 1,055 findings before the Tier-1 collapse. The mechanisms they
describe are real and unchanged; the numbers are superseded by the S5 entry below, and the
per-factor means in the second bullet have not been recomputed - derive them from
`artifacts/scored-corpus-v0.json` before quoting any:

- **Zero findings reach Critical, and the cause is arithmetic.** Over all 1055 findings:
  Critical **0**, High 555, Medium 466, Low 34. **Report the context-eligible column
  instead** — spec §3.3 excludes ineligible findings from quality claims and 30 of those
  34 Low findings are exactly those, so on the 1025 eligible findings **Low is 4, not 34**.
  The all-defaults total is exactly **20, two short of Critical's 22**, so an unresolved
  finding can never be Critical, and `band_for`'s Critical branch is reached only by unit
  tests — any claim about Critical-band behaviour rests on constructed examples.
- **Resolving a factor typically LOWERS its contribution** — five of six factors have a
  mean resolved value below their conservative default: privilege 0.13 against 4,
  encryption 0.20 against 2, sensitivity 2.45 against 3, criticality 2.50 against 4,
  severity 3.04 against 4; only exposure is above, and marginally, at 3.02 against 3.
  (**An earlier version of this entry gave all six means wrong** — 0.01, 0.00, 1.33, 2.44,
  2.53 and 3.04 — by computing them with each factor's own default bucket dropped, which
  discards *resolved* findings that happen to land on the default. Severity's resolved n is
  **566**, the standing corpus fact above, not the 370 that version implied.) **So an
  unresolved finding outranks a resolved one of the same actual risk.** That follows from
  PLAN Q9 forbidding a missing value to read as low, but it is a ranking artefact, and
  sweeping the five `unresolved_default` values is a more consequential Q10 experiment than
  sweeping the band thresholds. The washout is visible in the missing-count split,
  `{0:38, 1:43, 2:122, 3:203, 4:234, 5:293, 6:122}`: the largest bucket is 5-missing at
  **293**, and with the 122 six-missing findings that is **415 all in High, of which 154
  score exactly 20**. The range reaches 6 because severity is one of the six factors.
- **The framework re-ranks substantially, but the baseline's own coverage must travel with
  every comparison.** 283 findings demote out of baseline-High, 195 promote out of
  baseline-Low, and all 16 baseline-Critical demote. **489 of 1055 (46.4%) reach their
  baseline band through the unknown-severity route**, so an unknown share of the baseline
  column was never a scanner judgement at all.
- **`exposure` contributes a flat 3 to 970 of 1025 findings** (934 defaults plus 36 resolved
  values that equal it), so it does almost no ranking work. It discriminates *within* PLAN
  Q9's closed pattern list and is `unresolved` outside it, never low.

`docs/superpowers/specs/2026-10-01-s4-handoff.md` records these and six more residual
risks in full, with what each costs if ignored. Read it before starting S5 or S3c.

**S5 groundwork (2026-10-06, branch `s5-evaluation-harness`)** built the composition S5
reads: `src/iacrisk/pipeline.py` runs layers 2-5 in order (Tier-1 collapse, context, score,
rank, emit), and `tools/score/run.py` replays the committed captures through it. No scanner
runs. The `corpus` target writes `artifacts/scored-corpus-v0.json`; the `cases` target
writes `artifacts/scored-cases-v1.json`. Building it surfaced four facts a future session
will get wrong without being told:

- **Every S3b and S4 figure above is over 1,055 findings, before the Tier-1 collapse** -
  although S4's spec §5.1 and `rank.py` both say ranking runs over the deduplicated set. No
  path applied the collapse before scoring until `pipeline.py`. **The project author ruled
  on 2026-10-06 that the 1,016 deduplicated population is the headline.** The artifact
  carries both - the ranked payload over the survivors, and the earlier population under
  `before_dedupe` - so name the population whenever quoting either.
- **The headline band distribution has three recorded states, and only the last is
  current.** Over 1,055 with the body-index defect: Critical 0 / High 555 / Medium 466 /
  Low 34 - the S4 handoff's figures, which the artifact committed at `f7fbcfc` reproduces
  exactly. Over 1,016 with the defect: 0 / 531 / 451 / 34 (commit `9b9de59`'s record).
  **Over 1,016 with the defect fixed: Critical 0 / High 235 / Medium 747 / Low 34**, with
  eligible-only Low still 4, 740 low-confidence, and the factor-gap population 420 with 242
  substantive. Over 1,055 fixed it is 0 / 245 / 776 / 34 with 774 low-confidence. The fix
  moved 296 findings from High to Medium because privilege went from unresolved on 319 of
  1,025 eligible findings to 8, and encryption from 648 to 337; exposure barely moved
  (934 to 932). The missing-count split over 1,055 is now `{0:38, 1:47, 2:140, 3:372,
  4:332, 5:122, 6:4}`. The S4 handoff and chapter 3 still carry the first state.
- **The corpus-level declared context is a last-case-wins merge, and 4 identities conflict.**
  `aws_s3_bucket.data`, `.data_science`, `.financials` and `.operations` each carry two or
  three cases with different declared values - the four declared-factor pairs, on purpose -
  and the `-low` case won all four. S4's corpus-level figures inherit that. The artifact
  lists the conflicts. **Pairs and scenarios must be read from the `cases` target**, which
  scores each case under its own declaration.
- **Case-level aggregation was undefined until 2026-10-06, and is now the highest-scoring
  finding.** How a case's several findings become one rank decides the pair pass rate and
  the scenario agreement; the S2 handoff's item 12 says it was undefined and S4 did not
  define it. The project author chose **a case ranks where its top-scoring finding ranks**
  before `artifacts/scored-cases-v1.json` was first generated, for the reason the oracle's
  resolution rule was pre-registered. **Say no more than that.** "Before any case-level
  score had been generated or looked at", which this entry used to say, is stronger than
  the repository can show: a test in `tests/score/test_score_run.py` already computed the
  per-case scores in memory, and the corpus artifact already held the finding scores of 15
  of the 26 cases. The rule must be committed in `eval/` **before**
  `artifacts/scored-cases-v1.json` exists, so git history carries the ordering. Sum and
  mean are reported beside it as an aggregation-sensitivity check, never substituted.
  That ordering holds and is tested: `eval/harness.py` arrived in `4d21966`, the case
  scores in `0b53d9e`, and `tests/test_s5_gates.py` gate 8 asserts the ancestry from git.
- **The suite passed only at `D:\Research` until commit `3e092f8`.** tfsec's captures carry
  absolute paths from the host that made them, and 66 of 825 tests failed in a clone
  anywhere else. `capture_scan_root` recovers the capture root from the document; replay a
  tfsec capture through it, never against the live scan root.

**S5's harness and first results (2026-10-06).** `eval/harness.py` computes every metric
from JSON and imports nothing of the framework; `uv run python -m eval.run` writes
`artifacts/evaluation-v1.json`. Its eight rules are stated once, in the module docstring.
Eight acceptance gates in `tests/test_s5_gates.py`; 916 tests in the suite when it was
built. (This entry used to say each gate recomputed a figure by a second route. Several did
not - see the pre-merge review below, which rewrote them so that they do.) **The results exist in two committed states - as first
measured (`9b9de59`), and after the body-index fix - and where they differ both are given,
because the fix was made after the first results had been seen:**

- **Contrastive pairs: 8 of 10 pass, against the baseline's 1 of 10.** Unchanged by the
  fix. Mechanism holds in 8 and all 8 are isolated; 5 of 7 mined pairs pass and 3 of 3
  hand-crafted. Under `sum` 9 pass and under `mean` 8.
- **Both failures are the two encryption pairs, and both are 15-15 ties.** This is a
  result, not a defect. The encrypted bucket's `server_side_encryption_configuration`
  holds an interpolated key ARN, so literals-only extraction calls it unresolved; the
  unencrypted buckets declare none, which S3b also calls unresolved because the platform
  default is account-level. Both sides score the default of 2. **The encryption factor is
  not shown to discriminate anywhere in this evaluation**, and the storage scenario's exact
  match owes nothing to it - all five buckets contribute 2.
- **Scenarios: 2 of 5 exact tier matches (storage, iam), baseline 0 of 5.** Of 21 ordered
  case pairs the framework gets 19 right, ties 2 and inverts 0; first measured it was 18,
  2 and 1. The baseline gets 4, ties 16, inverts 1. Networking orders every pair correctly
  and splits the expected tie on scanner severity. Compute ties the contested pair - the
  author's order and the reviewer's both fail to appear.
- **The containers scenario was the defect's visible symptom.** First measured,
  `kube-bench-node` outranked `goat-home` (17 against 13, tau-b -0.5) purely because its
  three parsed factors were unresolved. Fixed, it scores 11 and the ordering is
  `[goat-home = internal-proxy] > kube-bench` (tau-b 0.5) - **the blinded reviewer's
  ordering exactly, not the author's**. Three scenarios are now free of excluded and
  low-confidence cases, and 2 of those 3 match.
- **Alert reduction is two numbers.** Deduplication: 39 of 1,055 (3.7%). Critical/High
  count, over the 986 context-eligible findings: **649 to 235, a 63.8% reduction** -
  first measured it was 649 to 531, 18.2%. **Two caveats travel with it:** 441 of the
  baseline's 649 reach High through an unknown severity, and 740 of the 986 are
  low-confidence. **The 986 is not the population the rubric admits to a quality claim** -
  the pre-merge review below gives the figure over the 246 that is.
- **Rank changes over those 986: 196 promoted, 427 demoted, 363 unchanged** (first
  measured: 245, 271, 470). 267 of the 427 demotions and 165 of the 196 promotions are
  low-confidence. The fix removed nearly every default-driven promotion into High: 143
  before, all low-confidence, against 3 after.
- **Ranking consistency is two records, not part of `evaluation-v1.json`:** model
  sensitivity (S6, below) and auto-inference agreement (S3c, below). The evaluation record
  names where each is and restates neither.

**S6's sensitivity analysis (2026-10-06).** `eval/sensitivity_plan.json` registers 63
variants in four experiments; the project author approved it and it was committed
(`4467cf4`) before any variant was computed. `uv run python -m eval.sensitivity` computes
all of them from the scored JSON and writes `artifacts/sensitivity-v1.json`. Five gates in
`tests/test_s6_gates.py`; 956 tests in the suite. **The plan file is the registration: do
not edit it.** A changed or added variant is a second registered round in its own file, and
gate 5 fails if the plan has more than one commit. What it found splits cleanly in two:

- **The ordering results are stable.** Pairs pass 8 of 10 under all 29 default variants,
  all 16 boundary variants, all six doubled weights and both named weightings. They fall
  only when the factor under test is weighted to zero, as they must. Scenario exact matches
  stay at 2 of 5 in 56 of 63 variants and range from 1 to 3.
- **The band counts are not, and the 63.8% alert-reduction figure inherits that.** 199 of
  the 235 High findings score **exactly 16**, the lowest High score. Raising the High
  boundary one point leaves 36 in High; lowering it one gives 296. Lowering any one of five
  defaults by a single point removes most of the band: absent severity 4 to 3 leaves 92,
  exposure 3 to 2 leaves 60, sensitivity 3 to 2 leaves 46, criticality 4 to 3 leaves 46,
  encryption 2 to 1 leaves 64. Only privilege is immaterial (233).
  With every default at its minimum Critical/High is 0; at its maximum, 907. **Never quote
  the Critical/High reduction without this beside it.**
- **Dropping the encryption factor changes no pair and no scenario.** It is the same
  non-result as the two tied encryption pairs, seen from the other side.
- **`exposure-security-group` passes without exposure.** With exposure weighted to zero it
  still passes on a one-point severity difference, so it is weaker evidence for the
  exposure mechanism than `exposure-s3-public-access`, which fails as it should.
- **The networking scenario across the exposure default**, by name as the S2 handoff's
  item 12 asks: over the rubric's registered sweep the tier separation holds at 2, 3 and 4
  and collapses into a shared top tier at 5.
- **The low-confidence threshold is a cliff:** 962, 890, 740 (frozen), 210 and 2 findings
  at thresholds 1 to 5, because 530 findings have exactly three factors missing.
- **Critical stays empty** until its boundary drops from 22 to 20, where 2 findings enter.
- **The two named weightings are not independently expert-derived.** Likelihood-weighted
  (exposure and privilege doubled) and impact-weighted (sensitivity and criticality
  doubled) were proposed from sources the rubric cites and approved by the author; the
  plan says so in its own text. PLAN Q10 asks for "expert-derived" alternatives. None will
  be sought (the author's ruling of 2026-10-08), so this stays a stated shortfall against
  Q10; a weighting obtained later would still be a second registered round.

**S3c's auto-inference mode (2026-10-06).** `src/iacrisk/context/inferred.py` reads
sensitivity and criticality from the conventions in
`src/iacrisk/data/inference_conventions.json` instead of from a declared-context input;
`tools.score.run inferred` writes the two inferred runs and `eval.agreement` compares them
with the declared ones. The conventions and the seven agreement rules were approved by the
project author and committed (`5352c13`) before the mode was run. Five gates in
`tests/test_s3c_gates.py`; 1,018 tests in the suite. **The conventions file is a
registration: do not edit it**, for the reason the sensitivity plan is not edited. Adding a
word after seeing which resources are declared would turn a measurement into a fit, and
gate 5 fails if the file has more than one commit.

- **On this corpus the conventions resolve 2 of 81 resources - 3 of 986 findings.** Both
  are sensitivity 5 from the word `secret` in a Kubernetes Role's name and its binding's.
  No tag, label or namespace resolved, and no criticality was inferred. TerraGoat's tags
  are either built by `merge()` over a computed prefix or are provenance keys from a
  tagging tool; the Kubernetes manifests carry only `app` and `name` labels, in `default`,
  `kube-system` or application-named namespaces, or with none stated.
- **So every agreement figure is a figure about the defaults, and the record shows that
  directly.** Level agreement equals the all-default strawman on every row: sensitivity
  14 of 15 exact, criticality 1 of 16. Reporting either as the conventions agreeing or
  disagreeing with the declarations would be wrong - they resolved none of those resources.
- **The inferred run never scores a finding lower than the declared run**: 199 higher, 787
  equal, 0 lower. Without declared context the framework over-prioritises.
- **What declared context was contributing:** removing it turns 9 of the 19 correctly
  ordered scenario case pairs into ties and resolves one compute tie (11 right, 10 tied, 0
  inverted - a net change of 8, which is what this entry used to give as the count). Storage and
  containers collapse into single tiers. Both modes match 2 of 5 scenarios, and not the same
  two - the inferred run gains compute by coincidence.
- **Four of the ten pairs are not applicable in this mode** - two declarations about one
  resource - and are reported as such, never as failures. The other six behave identically
  in both modes.
- **An inferred value is recorded as `resolved`.** There is no fourth factor state, so a
  low-confidence count is not comparable between the two modes; the difference is in the
  evidence string and in the document's `context_mode`. The declared and inferred modes are
  alternatives and are never merged within a run.
- **A name may raise sensitivity but never lower it, and criticality takes no name hint.**
  Both hold by the shape of the data - every registered name word sits above the default -
  and a test pins that.

**The pre-merge review (2026-10-07), and what it changed.** The branch was reviewed
before merging by a separate automated reviewer - an LLM subagent given the diff and the
requirements, **not a human**; do not describe it as independent expert review. It found no
defect in a result and changed no figure. It found that the evidence was described more
strongly than it was, in six ways a future session will otherwise repeat:

- **The gates were partly tautological.** Several S5, S6 and S3c gates re-derived a figure
  from the record's own fields or called the function under test for the expectation, so
  no wrong figure could have failed them. They are rewritten. `tests/_regrade.py` is a
  second implementation of the oracle's grading that shares nothing with `eval.harness`;
  the S6 gates score all 43 score-moving variants through `engine.score` and compare with
  `sensitivity.rescore` finding by finding; and `tests/test_gates_can_fail.py` corrupts 32
  figures in memory and requires each owning gate to fail. **1,069 tests in the suite.**
  When adding a gate, add its corruption.
- **`engine.score(weights=...)` has one caller, and it is that S6 gate.** The sensitivity
  analysis never called it; it recomputes from JSON. `check_identity` now compares the six
  contributions as well as the total, because two wrong addends can cancel. A weighted
  total outside 1..28 raises from `rubric.band_for` - reachable only for the 30
  context-ineligible findings with severity weighted to zero.
- **986 is the context-eligible population, not the quality-claim population.** The
  rubric's `unresolved_default_reporting` rule also excludes low-confidence findings, which
  leaves **246**. Over those: Critical/High **192 to 35 (81.8%)**; bands 0 / 35 / 207 / 4;
  **31 promoted, 160 demoted, 55 unchanged**. It is the larger reduction and not the better
  evidence: 198 of the 246 sit on resources corpus v1 declares, 87 on the four identities
  declared two or three ways (scored under the `-low` declaration), 103 of the baseline's
  192 have no scanner severity, and 24 of the 35 High score exactly 16. It was computed
  after the results were known and was not part of the registered sensitivity plan. The
  record key is `context_eligible` (was `quality_claim_population`), with an
  `excluding_low_confidence` twin in both `alert_reduction` and `baseline_comparison`; the
  agreement record's is `all_context_eligible_findings`.
- **Half the ordering evidence is declared, not derived.** Four of the eight passing pairs
  (sensitivity x2, criticality x2) put one resource under two declarations and pass by
  construction. Of the three mined pairs that turn on extraction, one passes
  (`exposure-security-group`) and it would pass without exposure. **No mined pair's pass
  depends on a factor extracted from code.** Of the 19 correctly ordered scenario pairs, 9
  are decided by declared context alone (storage 8, containers 1), 3 are the hand-crafted
  IAM scenario, and 7 remain (networking 5, compute 2) - of which only 2 are ordered by a
  value read from code on both sides; the other 5 have an unresolved default on one side.
  On those 7 the baseline gets 4.
- **Isolation is tested on contributions, not evidence.** In 7 of the 8 isolated pairs some
  other factor sits on the same default on both sides; `isolated_without_a_shared_default`
  is 1. The expectation check is one-directional, and `unlisted_non_resolved` reports what
  it does not judge (22 of 26 cases, always exposure or encryption).
- **Pre-registration is commit order and nothing more** - see the case-aggregation entry
  above. S5 gate 8 also now asserts the eight rules' text is word for word what was
  registered.

**The end-to-end command (2026-10-08, `src/iacrisk/cli.py`).** `uv run iacrisk <folder>`
runs the pinned scanners live and prints one line per resource at its highest-scoring
finding. It was built after the evaluation, on request, for demonstration. Five things a
future session will get wrong without being told:

- **No reported figure came from it.** Everything in the dissertation is replayed
  captures. The command adds the one step replay never took - launching the scanners.
- **Live and replay agree exactly on this host, and a test says so.**
  `tests/test_cli.py` has two tests that launch the real scanners: one requires the
  committed per-case scores for `corpus/authored`, the other scans both corpus roots and
  requires `scored-corpus-v0.json` back finding for finding (all 1,016: identity, class,
  scanner, rule, score, band, six contributions, six states). They are **skipped where
  `tools/resolved.json` is absent**, so on an unbootstrapped machine the agreement is not
  checked - read the `-rs` skip line before claiming it. 1,108 tests in the suite.
- **One platform per folder.** `checkov._platform_of` and `trivy._platform_of` read the
  platform off a whole run, so a folder mixing `.tf` and manifests would be misread. The
  command refuses it. Supporting it means changing the adapters, not the command.
- **Unmapped findings are scored with full resource context - a recorded deviation.**
  `docs/PLAN.md`, the S4 design spec (section 2.3) and chapter 3 as first drafted all say
  an `unmapped:` finding scores on severity and default context only. It does not: the
  five contextual factors are resolved per resource without reference to class, so an
  unmapped finding on an addressable resource is scored like any other and marked
  `unmapped`. Corpus v0 has none; the per-case record has 3, all on
  `iam-unrestricted-scope`; `corpus/authored` as a whole has 8. The harness sets them
  aside, so no figure moves. **The project author ruled on 2026-10-08 to record the
  deviation and leave the code alone** (chapter 3, section 3.3). `baseline_only_informational`
  is a different flag: no context block at all.
- **A relative folder used to crash it.** tfsec reports absolute paths, so `analyse`
  resolves the folder first. `artifacts/demo/` holds scratch reports from live runs and
  ignores itself through its own `.gitignore`; nothing in it is a research artifact.

**Never squash-merge this history.** S5 gate 8, S6 gate 5 and S3c gate 5 read commit
ancestry and require the two registered data files to have exactly one commit each. A
squash or a rebase that rewrites those commits turns three gates red and destroys the only
evidence of ordering there is.

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
sensitivity analysis. **That threshold was unspecified and S3b fixed it at 3 of 5**, before any scoring
output existed, so it is a frozen parameter rather than a tuned one. Its rationale rests
on majority-of-evidence rather than arithmetic — two defaults already exceed the
narrowest band, so the arithmetic does not single out three on its own.

**Draft dissertation chapters live in `docs/writeup/`**: `03-framework-design.md`,
`04-research-methodology.md`, `05-implementation.md` and `06-evaluation.md`, plus a
`README.md` carrying the provisional chapter numbering and two standing rules — every
number traces to a committed artifact, and no rubric `source` string resting on NSA-CISA
may be quoted. Chapters 1, 2 and 7 are not drafted; 1 and 2 need the proposal and the
literature sources, which are not in this repository. The chapters are written from the measured
record, so a figure that changes in an artifact must be changed there too.

Chapter 6 was drafted on 2026-10-06 from the four `artifacts/*.json` records and revised
on 2026-10-07 after the pre-merge review; its passages marked "added after review" say how
much of the ordering evidence is declared instead of derived, and must not be softened. Three
further things about it that a later edit could undo without noticing: it gives the results
in **both** committed states wherever the body-index fix moved them (§6.2); it states
that **the encryption factor fails its mechanism test** by Chapter 4's own
falsification criterion (§6.4.2, §6.9); and it concludes that the evidence supports
the ordering claim and **not** a claim about how many alerts are saved (§6.9). Its
§6.7.4 reports auto-inference as resolving two resources of 81 and says the agreement
figures therefore describe the defaults, not the mode. Chapters 3 and 4 carry dated
status notes pointing at it rather than being rewritten; chapter 3's §3.10 figures are
still the pre-fix, pre-dedupe ones, labelled.

Chapter 5 was drafted on 2026-10-07. Two things in it a later edit should not lose. Its
§5.9.2 records the three defects a green suite passed - the container suffix (0 of 217
findings, on 14 identities),
the omitted namespace (311 of 579) and the capture-host paths (66 of 825 tests) - and
states the rule they share: **a test that constructs both sides of a comparison cannot
discover that the real sides differ.** And its §5.11 says plainly that **the end-to-end
command was built after the evaluation and produced no result**: every figure is from
replayed captures. Do not let a later edit present the command as how the results were
obtained. Its §5.9.1 also records that the evaluation gates were weaker than first
claimed, and how they were rewritten. Its file, line, test and gate counts are as of the
commit that introduced `src/iacrisk/cli.py` and will drift.

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

Those four were measured on the original host, where the repository sat at `D:\Research`.
A second host (cloned 2026-10-06 to `C:\Users\TYN\Research\Research`) has no system Python,
no `py` launcher and only uv's 3.12.13, so the last two do not hold there; the rule does.

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

uv run python -m tools.score.run corpus   # replay the captures -> artifacts/scored-corpus-v0.json
uv run python -m tools.score.run cases    # per-case scores -> artifacts/scored-cases-v1.json
                                          # (not before the case-aggregation rule is committed)
uv run python -m tools.score.run inferred # both again in auto-inference mode -> *-inferred.json
uv run python -m eval.run                 # the harness -> artifacts/evaluation-v1.json
uv run python -m eval.sensitivity         # the 63 registered variants -> artifacts/sensitivity-v1.json
uv run python -m eval.agreement           # declared vs inferred -> artifacts/auto-inference-agreement-v1.json

uv run iacrisk <folder>                   # LIVE: run the pinned scanners over a folder and rank
                                          # --declared FILE | --infer, --out DIR, --top N
                                          # needs .\tools\bootstrap.ps1 to have run; writes nothing
                                          # without --out. Not how any reported result was produced.
```

Regenerate in that order - corpus, cases, inferred, then `eval.run`, `eval.sensitivity`,
`eval.agreement` - because each later record digests the earlier ones, and a gate fails
when a digest is stale.

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
