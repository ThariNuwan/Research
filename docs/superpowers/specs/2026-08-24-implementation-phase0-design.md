# S0 — Toolchain & Rule-Inventory Harvest (design)

**Date:** 2026-08-24
**Project:** Risk-aware IaC misconfiguration prioritization framework (MSc, Univ. of Moratuwa)
**Status:** Approved for implementation
**Parent plan:** [`docs/PLAN.md`](../../PLAN.md) — design locked, Codex R4 APPROVED
**Scope:** Sub-project S0 only. Precedes Phase 1 of `docs/PLAN.md`.

---

## 1. Why S0 exists (amendment to the locked plan)

`docs/PLAN.md` orders implementation as *Phase 1 = five specification artifacts, then Phase 2 = pipeline*. Phase 1 deliverable #1 carries this acceptance gate:

> every rule ID emitted by the pinned scanner versions **across the corpus** maps to an issue-class or an explicit `unmapped:` entry

That gate cannot be evaluated before (a) the scanners are installed and pinned, and (b) a corpus exists to run them over. But Q6 lists the issue-class taxonomy as an input to *corpus design*. The dependency is circular.

**Resolution.** Insert S0 ahead of Phase 1:

1. Pin the toolchain.
2. Assemble **corpus v0** — the vendored public repos only, which need no taxonomy.
3. Run the scanners; harvest the observed rule-ID inventory.
4. **Then** author the taxonomy in Phase 1 against observed reality rather than against the scanners' published rule catalogues.

This does not change any locked design decision. It makes deliverable #1's gate measurable on first attempt instead of deferring it to a reconciliation pass. Corpus v1 (contrastive pairs, scenarios) is authored in S2, *after* the taxonomy — preserving Q6's ordering for the part of the corpus that genuinely depends on it.

**Sub-project decomposition** (each gets its own spec → plan → implement cycle):

| ID | Sub-project | Depends on |
|---|---|---|
| **S0** | Toolchain + corpus v0 + rule-inventory harvest | — |
| S1 | The five Phase-1 specification artifacts | S0 |
| S2 | Corpus v1 — contrastive pairs + scenarios | S1 |
| S3 | Pipeline layers 1–3 (input, scan/normalize, context) | S1 |
| S4 | Pipeline layers 4–5 (scoring, reporting) | S3 |
| S5 | Independent evaluation harness + metrics | S2, S4 |
| S6 | Sensitivity analysis + write-up | S5 |

---

## 2. Environment (verified 2026-08-24 on the target machine)

| Present | Absent |
|---|---|
| Python 3.13.5 via `py` launcher (bare `python` is the broken MS-Store alias) | Checkov, tfsec, Trivy, Terraform |
| `uv` 0.11.26 | Docker, Go, pipx, WSL |
| winget 1.29.280, choco 2.2.2 | |

**Host decision: Windows-native.** No WSL2. Consequence: Checkov's Windows path handling becomes an explicit, tested concern in the canonical-identity spec (S1) rather than an accident. Reproducibility is carried by a pinned-version manifest, not by the OS.

### Pinned versions

| Tool | Version | Channel | Justification |
|---|---|---|---|
| Python | 3.12 (uv-managed) | `uv python install` | Checkov 3.3.12's classifiers stop at 3.12; its docs self-contradict on 3.13. Do not gamble the pipeline on an unresolved compatibility claim. System 3.13.5 untouched. |
| Checkov | 3.3.12 | `uv tool install` (isolated) | Latest on PyPI as of 2026-08-24. |
| Trivy | 0.74.0 | GitHub release asset | `trivy_0.74.0_windows-64bit.zip`, released 2026-08-14. |
| tfsec | 1.28.14 | GitHub release asset | `tfsec-windows-amd64.exe`. Last release **2025-05-02 — 15 months stale**. |
| Terraform | *not installed* | — | Q9 is literals-only with no external module resolution, so `terraform init` is out of scope by design. |

**tfsec staleness is a research finding, not just an install note.** A 15-month-old final release is empirical support for the R1-#19 decision to frame tfsec as legacy/comparative. Cite the release date in the dissertation rather than asserting obsolescence. S0 records it; S1 confirms tfsec's deprecation status against upstream sources before it is cited as such.

**No Terraform — documented consequence.** Some module-heavy TerraGoat findings will be skipped. That is an *expected limitation of the literals-only scope*, recorded in the limitations section, not a defect to fix. Naming it here prevents drift into the full-graph resolution Q9 excludes.

---

## 3. Repository skeleton

```
d:\Research
├─ pyproject.toml            # uv project; ruff / mypy / pytest config
├─ uv.lock                   # committed — exact transitive pins
├─ .python-version           # 3.12
├─ src/iacrisk/              # the artifact
│  ├─ scanners/  model/  context/  scoring/  report/  cli.py
├─ specs/                    # the five Phase-1 artifacts, as DATA not code
│  ├─ taxonomy.yaml  rule-mapping.yaml  rubric.yaml
│  ├─ severity-normalization.yaml  ground-truth.schema.json
│  └─ canonical-identity.md
├─ corpus/
│  ├─ vendor/                # v0 — TerraGoat, KubeGoat @ pinned commits
│  │  └─ SOURCES.md          # upstream commit SHA + license + attribution
│  ├─ pairs/  scenarios/     # v1 — authored in S2
├─ eval/                     # independent harness — may NOT import src/iacrisk/scoring
├─ artifacts/                # raw scanner JSON, rule inventory, run outputs (committed)
├─ tools/
│  ├─ scanners.lock.json     # committed: version + SHA256 + URL per scanner
│  ├─ resolved.json          # gitignored: absolute resolved exe paths
│  ├─ bootstrap.ps1  harvest.py
│  └─ bin/                   # gitignored binaries
└─ tests/
```

`artifacts/` and corpus fixtures stay version-controlled per the existing `.gitignore` rationale — they are research artifacts and evaluation reproducibility depends on them. Monitor total size; if raw dumps grow beyond a few MB, revisit.

---

## 4. Design decisions

### 4.1 Checkov is an isolated tool, never a project dependency

Q3 specifies all scanners are subprocess-invoked and JSON-parsed. Installing Checkov via `uv tool install` (its own venv) means its large transitive dependency tree cannot constrain the framework's dependencies, **and the framework cannot `import checkov` even by accident**. This enforces the tool-agnostic seam structurally rather than by convention — the same principle as `eval/` isolation.

### 4.2 Pinned release binaries, checksum-verified

Neither winget nor choco can pin an exact version, and choco's tfsec (1.28.1) is *behind* GitHub's 1.28.14. `tools/scanners.lock.json` records version + SHA256 + URL per scanner; `bootstrap.ps1` **verifies rather than trusts**, and fails loudly on mismatch.

### 4.3 Resolved paths, not `PATH`

`uv tool install` places binaries in `%USERPROFILE%\.local\bin`, which may not be on `PATH`. `bootstrap.ps1` resolves absolute executable paths into `tools/resolved.json` (gitignored — machine-specific); the runner reads that. Removes a class of "works on my machine" failure and makes the executed binary explicit.

### 4.4 Provenance block on every run

Every output JSON carries: resolved scanner paths, verified scanner versions, Python version, `specs/` file hashes, corpus commit SHA, UTC timestamp. Each result becomes self-describing, so any number in the dissertation is reproducible from the artifact alone. Introduced in S0 (the harvest is the first producer) and inherited by S3–S5.

### 4.5 Harvest is a research instrument, not pipeline code

`tools/harvest.py` scope, deliberately narrow:

- for each (scanner × applicable platform × corpus case) → invoke → write raw JSON to `artifacts/raw/<scanner>/<case>.json`;
- walk each raw JSON for rule ID + native severity; tally into `artifacts/rule-inventory.json`.

It does **not** construct the normalized finding record — that is S3, and it depends on the taxonomy that does not yet exist. Hard boundary: harvest lives in `tools/`, never `src/`, so it cannot silently become a half-built layer 2 that S3 then duplicates.

**Dual purpose.** The raw dumps are (a) the empirical input to S1's taxonomy and severity-normalization specs, and (b) the committed **golden fixtures** for S3's parser tests — which is exactly the mitigation `docs/PLAN.md` names for scanner output-schema drift.

### 4.6 Corpus v0 vendoring

Vendored **subtree copies** at recorded upstream commit SHAs, not git submodules — submodules are fragile on Windows and in archival snapshots, and a dissertation artifact should remain complete when zipped. `corpus/vendor/SOURCES.md` records upstream URL, commit SHA, retrieval date, and license per source. **Licenses must be read and recorded before vendoring**, not assumed.

---

## 5. Facts S0 must establish (not assume)

These are open empirical questions whose answers are load-bearing for S1 and S3:

1. **Each scanner's real JSON schema** — the rule-ID field and native-severity field differ across all three.
2. **Platform-applicability behavior.** What does tfsec *actually do* when pointed at Kubernetes YAML — silent zero findings, or a nonzero exit? This decides the R3-#3 "fail loudly only for the input platform's required scanners" logic. Guessing wrong yields either false-clean results or spurious hard failures.
3. **Per-scanner missing/unknown native-severity rate.** R3-#4 requires reporting it; S0 measures it for the first time and thereby sizes the problem.
4. **Checkov path separators on Windows** — whether output paths are backslash-delimited, which sets a normalization requirement for the S1 canonical-identity spec.

Each answer is recorded in `artifacts/rule-inventory.json` or appended to this spec as observed fact.

---

## 6. Testing

TDD applies unevenly here and is claimed honestly:

- **Test-first:** `harvest.py`'s JSON-walking and tallying logic, driven by small hand-written schema fixtures per scanner; the `eval/`-isolation guard.
- **Verify-by-execution, not unit-tested:** `pyproject.toml`, `bootstrap.ps1`, vendoring. These are configuration and provisioning; their test is that the documented command runs clean on the target machine and reports the pinned version.

The `eval/`-isolation test is written in S0 even though `eval/` is still a stub — the guardrail should exist *before* there is anything to violate it.

---

## 7. Acceptance gate

S0 is done when all eight hold:

1. `.\tools\bootstrap.ps1 -Verify` passes — all three scanners resolve, report their pinned versions, and SHA256 checksums match `scanners.lock.json`.
2. Every command written into `CLAUDE.md` has been **executed on this machine** and corrected from observed output. (This closes CLAUDE.md's own standing instruction: *"update this file with the real commands — do not invent them."*)
3. `artifacts/rule-inventory.json` is non-empty, spans all five tested categories (storage / networking / IAM / compute / containers), and reports per-scanner rule-ID counts.
4. Raw JSON fixtures committed for at least one case per (scanner × applicable platform).
5. Platform-applicability behavior recorded as observed fact (§5.2).
6. Per-scanner missing/unknown-severity rate computed and recorded (§5.3).
7. `eval/` import-isolation test exists and passes.
8. `corpus/vendor/SOURCES.md` records upstream commit SHA, retrieval date, and verified license per source.

---

## 8. Out of scope for S0

The normalized finding record; the issue-class taxonomy; any scoring; contrastive pairs and scenario configs; the evaluation harness; the CLI. S0 produces a pinned toolchain and an empirical rule inventory — nothing more.

---

## Appendix — observed scanner behaviour (S0, Task 5)

Recorded as observed fact, per the closing line of §5. Produced by
`tools/capture_fixtures.ps1`, which runs each pinned scanner once over each
*distinct* `scan_root` declared in `tools/corpus.lock.json` (two roots, not five
cases) and writes stdout verbatim. Six fixtures under
`tests/harvest/fixtures/`; the mechanical record of each run — argv, exit code,
byte counts, stream separation, top-level shape — is
`artifacts/scanner-behavior.json`.

Every number below was obtained by reading the committed fixtures. Where a
cause is claimed rather than an observation, the evidence is named inline.

### A.1 §5.1 — each scanner's real JSON schema

| | checkov 3.3.12 | trivy 0.74.0 | tfsec 1.28.14 |
|---|---|---|---|
| top level | **array** of per-framework blocks | object, `SchemaVersion: 2` | object, single key `results` |
| findings path | `[].results.failed_checks[]` | `Results[].Misconfigurations[]` | `results[]` |
| rule id | `check_id` (`CKV_AWS_133`) | `ID` (`AWS-0028`, `KSV-0001`) | `rule_id` (`AVD-AWS-0099`) |
| native severity | `severity` — **always `null`**, see A.3 | `Severity` (`HIGH`) | `severity` (`LOW`) |
| target path | `file_path`, `file_abs_path`, `repo_file_path` | `Results[].Target` — on the **parent**, not the finding | `location.filename` |
| separator style | mixed, see A.4 | forward slashes, scan-root-relative | **absolute**, backslashes |
| reports passes | yes, `passed_checks[]` | counts only, `MisconfSummary.Successes` | no |

Three structural facts that a walker written from the docs would get wrong:

1. **Checkov's top level is an array whose length depends on the input.** It is 3
   for the Terraform root (`terraform`, `dockerfile`, `secrets`) and 2 for the
   Kubernetes root (`kubernetes`, `secrets`). `--framework` is deliberately not
   passed, so auto-detection stays observable — and it fires: both roots yield
   findings from frameworks other than the declared platform. Trivy does the same
   thing through `Results[].Type`, which carries `dockerfile` alongside
   `terraform` and `helm` alongside `kubernetes`.
2. **Trivy puts the file path on the parent object, not on the finding.** A
   `Results` entry can also omit `Misconfigurations` entirely — 1 of 14 entries in
   the Terraform fixture (`Target: "."`, 66 successes and 0 failures) and 2 of 18
   in the Kubernetes fixture. Indexing that key unconditionally raises.
3. **tfsec's `status` is the integer `0` on a *failing* check** (119/119). It is
   not a pass/fail discriminator; tfsec emits failures only.

Rule-ID namespaces do not coincide. Trivy and tfsec both serve the Aqua
Vulnerability Database ruleset but spell the identifier differently — trivy
`AWS-0028`, tfsec `AVD-AWS-0099`. Over the Terraform root: trivy emits 49
distinct IDs, tfsec 48, and 45 coincide once `AVD-` is stripped. Checkov's 98
distinct IDs overlap neither set. Cross-scanner deduplication therefore needs an
identity mapping, not string equality, and the `AVD-` prefix is the only
mechanical part of it.

**No fixture here is byte-reproducible, and the reasons differ per scanner.**
Measured by re-running the capture and diffing against the committed blob:

- **trivy** — `ReportID` is a fresh UUID and `CreatedAt` a local wall-clock
  timestamp with offset on every run; `ArtifactName` embeds the absolute scan
  path. Two runs of the Terraform capture differed in length by one byte for
  this reason alone.
- **checkov** — same byte *length* across runs, different bytes. Two sources:
  the order of records within `failed_checks` and `passed_checks` varies between
  runs, and `check_result.evaluated_keys` is a set serialized to a list, so its
  order varies within a record (observed on the `CKV2_*` graph checks).
- **tfsec** — stable in count and in record order, unstable in content. A third
  run (made while re-verifying the capture script) matched the committed blob at
  119 findings in the same order, but the five `AVD-AWS-0038` findings on
  `aws_eks_cluster.eks_cluster` (`eks.tf:118`) had permuted their `description`
  strings among themselves — same five values, four of them in different slots.
  So the earlier "no instability observed" was an artefact of comparing two runs.
  Load-bearing beyond reproducibility: those five findings differ in nothing but
  `description`, and 119 tfsec findings collapse to 110 distinct
  `(rule_id, filename, start_line, resource)` keys — three keys collide
  (`AVD-AWS-0038` x5, `AVD-AWS-0057` x4 and x3). A deduplication key without
  `description` discards real findings; one with it is order-dependent.

What *is* stable for checkov, and is what later tasks may rely on: the multiset
of `(check_id, file_path, file_line_range, resource)` over each bucket is
identical across runs — 215 failed and 115 passed in the Terraform root's
`terraform` framework **block**, 266 and 994 in the Kubernetes root's
`kubernetes` block, same tuples both times. Those are block counts, not root
counts: checkov emits one block per framework it detects under a root, so the
Terraform root totals 221 failed / 117 passed (`terraform` 215/115 +
`dockerfile` 2/2 + `secrets` 4/0) and the Kubernetes root 268 / 994
(`kubernetes` 266/994 + `secrets` 2/0) — the numbers §A.3 sums to 489 and 1111.

**Consequence.** A test that asserts on fixture bytes, or on a finding at a
fixed array index, will be flaky. Task 6's walkers must be tested against
order-insensitive assertions, and any later re-capture will produce a diff that
is noise rather than a change in scanner behaviour.

### A.2 §5.2 — platform-applicability: what tfsec does with Kubernetes YAML

**It does not refuse. It exits 0 and reports nothing.**

```
tfsec --format json --no-colour --no-module-downloads <repo>/corpus/vendor/kubernetes-goat/scenarios
  exit code : 0
  stdout    : 19 bytes, valid JSON  ->  {\n\t"results": []\n}\n
  stderr    : 365 bytes (the 'tfsec is joining the Trivy family' banner)
```

For contrast, the same invocation over the Terraform root exits **1** with 119
findings. So the exit code carries *findings / no findings*, and
`0` is indistinguishable from *this scanner cannot analyse this input at all*.
The 365-byte banner is emitted on **every** invocation, including `--help` and
including the successful Terraform run, so its presence carries no signal either.
Measured directly rather than inferred: the stderr of the two runs above is
byte-identical, SHA-256
`b2e50e31e1699ac05a6281257f69869778b70200aa80367847f6e686170c3eba` for both --
365 bytes, 12 LF-terminated lines, the first of them blank. `stderr_head` in
`artifacts/scanner-behavior.json` is the field that records it: `stderr_bytes` and
`stderr_lines` agree across the two runs, but only `stderr_head` shows the text
itself is the same. `stderr_first_line` is `''` for both because the banner's
literal first line is empty, so on its own that field misleads; the byte-identity
of the two streams is established by `stderr_head` in the committed manifest
together with the measurement recorded earlier in this section. The capture script
**now also records** `stderr_first_text`, the first line carrying non-whitespace --
a field the committed manifest predates (its `captures` records carry 21 fields and
this is not one of them), and one a future re-capture will include.

**Consequence for R3-#3.** The 'fail loudly only for the input platform's
required scanners' rule cannot be implemented by inspecting what the scanner
returned. Routing Kubernetes manifests to tfsec is a silent false negative that
looks exactly like a clean scan. The platform-to-scanner matrix has to be
declared and enforced by the caller *before* the process is launched, which is
why `tools/scanners.lock.json` carries a `platforms` list per scanner and
`tools/capture_fixtures.ps1` refuses to build a capture for a platform a scanner
does not declare. The tfsec x Kubernetes capture above exists only because it was
requested explicitly as the off-matrix probe that establishes this fact, and it is
the one capture flagged `off_matrix: true` in the manifest.

### A.3 §5.3 — per-scanner missing native-severity rate

Failed findings only, over both scan roots:

| scanner | findings | severity absent or null | rate |
|---|---|---|---|
| checkov | 489 (221 terraform + 268 kubernetes) | 489 | **100%** |
| trivy | 447 (115 + 332) | 0 | 0% |
| tfsec | 119 (119 + 0) | 0 | 0% |

Checkov's 100% is not a corpus artifact and not a flag mistake. It holds for
`passed_checks` too (1111/1111 null), and it was traced to its cause two
independent ways:

- **By reading the installed source.**
  `checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py`.
  `_handle_public_metadata` (`:129`) builds each check's metadata from the public
  response with two keys only, `guideline` and `id`. Severity is assigned at
  `:82` from that metadata, and is populated only by `_handle_customer_run_config`
  (`:146`), which reads `run_config['policyMetadata']` — the response that
  requires a Prisma Cloud / Bridgecrew API key.
- **By a two-arm run** over one vendored file
  (`corpus/vendor/terragoat/terraform/aws/db-app.tf`, 24 findings both arms):

| arm | `severity` | `bc_check_id` | `guideline` |
|---|---|---|---|
| `--compact --skip-download` (the fixture config) | null 24/24 | null 24/24 | null 24/24 |
| `--compact` (metadata fetch allowed) | **null 24/24** | set 24/24 | set 24/24 |

The second arm proves the fetch happened and the integration ran — `bc_check_id`
and `guideline` fill in — and that severity is still absent. So `--skip-download`
costs only the guideline URL and the Bridgecrew alias, which is what vindicates it
as the flag for a hermetic capture.

**Consequences.**

1. The risk model's `Severity` factor (1-5, the baseline term) has **no Checkov
   input** in any configuration reachable without a commercial API key. Findings
   that only Checkov reports arrive with no native severity at all.
2. `native_severity=None` is therefore the common case, not an edge case, and
   R3-#4's prohibition on silently defaulting it is load-bearing rather than
   defensive. `tools/harvest/model.py` types the field `str | None` for this
   reason.
3. CLAUDE.md defines the evaluation baseline as *raw scanner severity output*.
   That baseline cannot be built from Checkov. It has to come from trivy/tfsec,
   or be defined over the subset of findings that carry a native severity, and
   the choice must be stated in S5.
4. Where a native severity does exist it is a **four**-level scale —
   `CRITICAL / HIGH / MEDIUM / LOW`, with no `INFO` or `UNKNOWN` observed in
   the 566 findings that carry one — mapping onto a 1-5 factor. S1's normalization spec has to
   say what the fifth level is for, or drop to four.

### A.4 §5.4 — Checkov path separators on Windows

**Yes, backslashes — and worse than uniformly.** Checkov emits three path fields
per finding, in three different conventions, and one of them is not even
self-consistent within a single document.

Values below are shown decoded; the JSON source escapes each backslash as `\\`.

| field | convention | example |
|---|---|---|
| `file_path` | scan-root-relative, leading separator, **mixed style** | `\db-app.tf` |
| `file_abs_path` | absolute, backslashes, 489/489 findings | `D:\Research\corpus\vendor\terragoat\terraform\aws\db-app.tf` |
| `repo_file_path` | repo-rooted, forward slashes | `/corpus/vendor/terragoat/terraform/aws/db-app.tf` |

The mixing is the part that sets a hard requirement. Within
`tests/harvest/fixtures/checkov-terraform.json`, the *same file* is reported under
two different spellings depending on which framework block found it:

```
terraform block : \ec2.tf
secrets   block : /ec2.tf
```

Three files (`ec2.tf`, `lambda.tf`, `providers.tf`) appear under both spellings in
that one fixture. A single `file_path` value can also carry both separators at
once: `/resources\Dockerfile`, from the dockerfile block — leading forward slash,
interior backslash.

**Requirements this sets for S1's canonical-identity spec.**

1. Normalize separators to `/` before any comparison. Neither `os.path` nor
   `PurePath` on a POSIX host will do it: `PurePosixPath` treats `\` as an
   ordinary filename character, so `\ec2.tf` is a *one-segment* name there.
   The normalization has to be an explicit character replacement.
2. Strip the leading separator. `file_path` is root-relative but always prefixed.
3. Do not assume one spelling per document, per scanner, or per file. Identity has
   to be established after normalization, not by matching raw strings.
4. Prefer `repo_file_path` where it is present — it is the only Checkov field that
   is already normalized and host-independent — but it cannot be the sole source,
   because trivy (`Results[].Target`, forward slashes, root-relative) and tfsec
   (`location.filename`, absolute backslashes) offer nothing equivalent. Case
   attribution has to work from a normalized root-relative form derived from all
   three.

This also decides the shape of `InventoryRow.target`, which stores the scanner's
string **unmodified** (`tools/harvest/model.py`): the normalization is S1's
specified transform, so recording the raw value keeps the observed input to that
transform available rather than pre-empting it.

### A.5 Which S0 acceptance-gate items this closes

| gate item | status after Task 5 |
|---|---|
| 4 — raw JSON fixtures per (scanner x applicable platform) | **met**: six fixtures committed, one per scanner per distinct scan root, plus the off-matrix probe |
| 5 — platform-applicability recorded as observed fact | **met**: A.2 |
| 6 — missing/unknown-severity rate computed and recorded | **met at fixture level**: A.3. The number that goes in `artifacts/rule-inventory.json` is computed by the harvest walkers, not here |

Items 1, 2, 3, 7 and 8 are unaffected by this task.
