# S3a — Detection & Normalization (design)

**Status:** approved at the review gate (2026-09-22); both §12 items resolved by measurement
**Author:** Jayathissa E.A.T.N. (258243J)
**Date:** 2026-09-22
**Scope:** Sub-project S3a — pipeline layers 1–2 plus Q8 deduplication. Splits the S0 roadmap's S3 in two; S3b takes layer 3 (context extraction).
**Spec authority:** `docs/PLAN.md` (locked, Codex R4 APPROVED) — Q3, Q7, Q8, and the layer definitions.
**Upstream input:** S1's five artifacts (`docs/superpowers/specs/2026-09-19-s1-preimplementation-artifacts-design.md`) and the S0 golden fixtures in `tests/harvest/fixtures/`.

---

## 0. Purpose, scope, and why S3 was split

S3a builds the first two pipeline layers and the deduplication step, producing a **normalized, deduplicated finding set** carrying an issue-class and a normalized severity for every finding the pinned scanners emit. It adds **no contextual attributes** — those are S3b's.

The S0 roadmap scoped S3 as layers 1–3 together. PLAN Q9 loads layer 3 heavily (four bounded exposure patterns with an attribution rule, enumerated bucket-publicness combinations, a closed set of supported IAM constructs, literals-only unresolved discipline with per-factor rates) while layer 2 separately owns the normalized finding record, three scanner adapters and Q8 dedupe. Split here because **S3a ends at an independently valuable artifact**: the normalized finding set is exactly what PLAN Q7 calls *normalization / retention coverage*, and that metric can be measured before any context work exists.

### 0.1 Global constraints (bind every part of S3a)

- **Explicit-state discipline.** `unresolved`, `unmapped:`, `unknown`, `None` are first-class states in the record and the output JSON. None is ever silently defaulted to low or safe (PLAN Q9). S3a introduces one more: an **unresolved violation fingerprint**.
- **The taxonomy is the single source of truth.** S3a joins against S1's committed `taxonomy.json`; it does not reclassify, extend or second-guess it. A rule absent from the table takes the `unmapped:` fallback.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — docstrings, comments, test names, commit messages, and this spec. Measured facts in this document carry their source.
- **Windows-native host.** Always `uv run python`. Path handling is explicit character work, never a path-library assumption.
- **Corpus v0 is a corpus observation, not a scanner contract.** Every count below was measured against the committed fixtures on this host and describes them, not the scanners' capabilities.
- **Harvest is not reusable.** `tools/harvest/` is a research instrument that deliberately does **not** construct a normalized finding (phase0 §4.5, enforced by `tests/test_architecture.py::test_harvest_does_not_define_a_normalized_finding`). S3a does not import it. Shared behaviour, if any emerges, is re-derived rather than reached for.

---

## 1. Measured facts S3a is designed around

All figures measured from `tests/harvest/fixtures/` — the golden captures phase0 §4.5 designates as S3's parser test inputs.

| Scanner / platform | Findings | Resource identity present | Attribute path present | Line range present |
|---|---|---|---|---|
| checkov / terraform | 221 | 221/221 (`resource`) | 208/221 (`check_result.evaluated_keys`) | yes |
| checkov / kubernetes | 268 | 268/268 (`resource`) | 165/268 | yes |
| trivy / terraform | 115 | 113/115 (`CauseMetadata.Resource`) | **0** | 113/115 |
| trivy / kubernetes | 332 | **0/332** | **0** | 328/332 |
| tfsec / terraform | 119 | 119/119 (`resource`) | **0** | 119/119 |

Four consequences drive the design:

1. **tfsec emits absolute Windows paths — 119/119**, e.g. `D:\Research\corpus\vendor\terragoat\terraform\aws\db-app.tf`, while checkov emits `/ec2.tf` and trivy emits `ec2.tf`. `identity.normalize_path` is scoped to relative paths and would keep the drive letter, so **every tfsec finding fails the join** unless paths are made scan-root-relative first (§5.1).
2. **Trivy supplies no resource identity for Kubernetes — 0/332.** It states the resource in prose (`Container 'batch-check' of Job 'batch-check-job' should set …`). Checkov supplies `Kind.namespace.name` but omits `apiVersion`, which S1's Kubernetes identity leads with.
3. **Checkov's `resource` field is polymorphic.** Across 47 distinct values it carries Terraform addresses (`aws_db_instance.default`), Dockerfile paths (`/resources\Dockerfile.`), provider blocks (`aws.plain_text_access_keys_provider`) and bare secret hashes (`25910f981e85ca…`). Not everything checkov calls a resource is a Terraform resource.
4. **A structured violation fingerprint exists only in checkov.** Its `evaluated_keys` is high quality where present (`spec/template/spec/containers/[0]/securityContext/allowPrivilegeEscalation`) but absent on 13/221 and 103/268, and its single most common value is the meta-key `resource_type`, which names no attribute at all.

**Kubernetes manifests** (`corpus/vendor/kubernetes-goat/scenarios`, 22 files): 18 parse cleanly under `yaml.safe_load_all`; **4 fail, all under `metadata-db/templates/`** — the Helm chart, whose `{{ … }}` is not valid YAML. Parsing yields **35 kind-bearing documents**, 17 container names, and **13/35 with no `metadata.namespace`**. (An earlier revision of this line said 37 and 15/37. Those figures counted `Chart.yaml` and `values.yaml`, which parse cleanly but carry no `kind` and are therefore not manifests — §3 excludes them by exactly that test. Corrected from Task 3's measurement.)

**Taxonomy coverage** of the rule families the adapters will see: checkov `CKV_*`/`CKV2_*` 128, tfsec `AVD-AWS-*` 48, trivy `AWS-*` 47 and **`KSV-*` 30**. All 255 map.

---

## 2. Deliverable 1 — the normalized finding record

The record S0 refused to define because it depends on a taxonomy that did not then exist. A frozen dataclass in `src/iacrisk/finding.py`:

| Field | Type | Meaning |
|---|---|---|
| `scanner` | `str` | `checkov` \| `trivy` \| `tfsec` |
| `rule_id` | `str` | Exactly as emitted |
| `canonical_rule_id` | `str` | One leading `AVD-` removed (S1 §2.2) |
| `issue_class` | `str` | A taxonomy class id, or `unmapped:<scanner>:<rule_id>` |
| `title` | `str` | The scanner's own description |
| `remediation` | `str \| None` | The scanner's suggested fix where it offers one |
| `native_severity` | `str \| None` | Raw token as emitted; `None` is first-class |
| `severity_level` | `int \| str` | 1–5, or the literal `"unknown"` |
| `platform` | `str` | `terraform` \| `kubernetes` |
| `resource_identity` | `str` | Canonical per S1 §5, or `<unresolved>` |
| `identity_kind` | `str` | `terraform` \| `kubernetes` \| `file` \| `provider` \| `secret` \| `unresolved` |
| `file_path` | `str` | Normalized, **scan-root-relative** (§5.1) |
| `line_range` | `tuple[int, int] \| None` | Source span where reported |
| `fingerprint` | `str \| None` | Normalized attribute path; **`None` means unresolved** |
| `context_eligible` | `bool` | Whether a cloud resource exists for S3b to contextualize |

`identity_kind` is what keeps finding 3 honest. A checkov Dockerfile or secret finding is retained with its real identity kind rather than being forced into a Terraform shape or silently dropped — it still counts toward retention coverage, and a consumer can tell at a glance that it is not a Terraform resource.

### 2.1 Why non-resource findings are retained, and what `context_eligible` is for

Measured: **9 of 489 checkov findings (1.8%) carry a non-resource `resource`** — on Terraform, 4 secret hashes, 2 Dockerfile findings and 1 provider block; on Kubernetes, 2 secret hashes. (An earlier revision said 8 of 489. That figure counted the secrets and Dockerfiles but overlooked the provider block `aws.plain_text_access_keys_provider`, which is equally not a resource. Corrected from Task 5's adapter run, which classifies terraform as 214 resource + 1 provider + 2 file + 4 secret = 221.) The choice moves no metric materially, so it goes to whichever side is cheaper to defend: retaining requires an honest label, while dropping requires justifying an exclusion from a *coverage* metric. They are also genuine findings a user wants surfaced — `CKV_SECRET_*` is a hardcoded credential.

**An unresolved identity is also context-ineligible.** Settled during Task 5, because the adapter originally set the flag from the resource *shape* before identity resolution had run — so a Kubernetes-shaped finding that failed both index lookups carried `resource_identity = "<unresolved>"` alongside `context_eligible = True`, telling S3b to extract context from a resource that was never found.

The rule: **when identity resolution fails, `identity_kind` becomes `"unresolved"`**, and eligibility follows from the kind as it already did — only `terraform` and `kubernetes` are eligible. No conjunction of kind and resolution, because that would give one flag two meanings; the kind carries it. Nothing is lost, since `platform` still records that the finding was Kubernetes, keeping "might resolve after a re-harvest or a fixed template" distinguishable from a secret hash that never can. Corpus v0 does not exercise this branch — no checkov Kubernetes finding lands in the four unparseable Helm templates — so it is a latent correctness rule, and its test says so rather than implying the case occurs.

`context_eligible = False` marks them. It exists because of the washout spec §3.5(2) identifies: the five context defaults sum to 16, so a finding with nothing resolved lands at 17–21 and is **always High**. A hardcoded secret may well deserve High, but it must not arrive there because no factor resolved. The flag makes S3b skip extraction rather than default every factor, and makes S4/S5 exclude these from prioritization-quality claims — the same discipline the `unmapped:` contract already applies, on a different axis. `unmapped:` means *no class*; `context_eligible = False` means *no resource to contextualize*.

---

## 3. Deliverable 2 — layer 1, input discovery

`src/iacrisk/input.py`. Walks a scan root and classifies each file:

- `*.tf` → terraform.
- `*.yaml` / `*.yml` → a **candidate** Kubernetes manifest; confirmed only if a parsed document carries both `apiVersion` and `kind`. This is what excludes `Chart.yaml` and `values.yaml`, which parse cleanly but are not manifests (2 of the 37 documents indexed carry no `kind`).
- Everything else → ignored, counted.

Discovery is separate from scanning because the platform decides which scanners are applicable, and that matrix is **data** — `tools/scanners.lock.json` declares tfsec as `["terraform"]` only. S3a reads that lockfile; it never encodes a scanner name in an `if`.

---

## 4. Deliverable 3 — the Kubernetes resource index

`src/iacrisk/resources.py`. Parses confirmed manifests once into an index supporting two lookups:

- **by file and line** → the document whose span contains that line, for trivy, which gives only `CauseMetadata.StartLine`;
- **by kind, namespace and name** → for checkov, which gives `Kind.namespace.name` but no `apiVersion`.

**Checkov's four-component form is NOT a container address — erratum, corrected 2026-09-22.** An earlier revision of this section claimed `Kind.namespace.name.container`, measured from 10 findings such as `Pod.default.build-code-deployment.app-build-code`. That reading was wrong, and it was caught by Task 3's implementer and confirmed against the manifests: **the fourth component is the pod template's label rendered `key-value`, in 10 cases out of 10.** `Pod.default.internal-proxy-deployment.app-internal-proxy` settles it — that workload has two containers, `info-app` and `internal-api`, and the fourth component is neither. The synthesized `Kind` is `Pod` rather than the workload's actual `Deployment`, which is the other tell.

Consequently **the checkov adapter must never feed the fourth component to `by_address(container=…)`.** Checkov container-scoped identity, where it is needed at all, comes from the by-line path like trivy's. Every one of these 10 findings is `CKV2_K8S_6`, a pod-level check, so the workload identity is the correct target anyway.

**Spans nest, so the by-line lookup needs a tie-break rule.** A container's lines fall inside its parent workload's span, so a line can match both the document and a container within it. The rule: the lookup returns the **innermost** match — the container when the line falls in a container block, the document otherwise. Documents within one file do not nest (multi-document YAML is sequential), so the only nesting is workload-to-container, and resolving to the container is what gives a container-scoped finding its `[container=…]` component rather than collapsing every container finding onto the workload.

Where a line matches no span at all, identity is `<unresolved>` — not the nearest document, which would be a guess presented as a lookup.

Each entry carries `apiVersion`, `kind`, `namespace`, `name`, the container names (`containers` and `initContainers`), and the document's line span. Namespace absent → `identity.DEFAULT_NAMESPACE`, **flagged**, per S1 §5.2 — the flag is what keeps a genuinely cluster-scoped resource distinct from a namespaced one whose namespace was merely omitted.

A file that fails to parse yields **no index entries and is recorded as unparseable**. Findings landing in it take `<unresolved>` identity. The 4 Helm templates are that case, which is how S1's unresolved path gets genuinely exercised rather than remaining theoretical.

This module exists because of measured fact 2: without it, 332 trivy Kubernetes findings have no identity at all, and every checkov Kubernetes identity is missing its `apiVersion`.

---

## 5. Deliverable 4 — the three scanner adapters

`src/iacrisk/scanners/`, one module per scanner behind a shared protocol, plus `invoke.py` for subprocess execution. Each adapter turns one scanner's raw JSON into `NormalizedFinding` values and reports what it could not resolve.

### 5.1 Path handling — one target spelling, and it is scan-root-relative

Every `file_path` is normalized to a **scan-root-relative** form. That target is not arbitrary: it is the spelling checkov and trivy already emit, so it is the only one all three scanners can be brought to without rewriting two of them.

- **checkov** — `file_path`, scan-root-relative already, with mixed separators (`/ec2.tf`, `\db-app.tf`, `/batch-check\job.yaml`). Normalize directly.
- **trivy** — `Results[].Target`, scan-root-relative already. One target is `.`, which names no file and yields no `file_path`.
- **tfsec** — `location.filename`, **absolute** (`D:\Research\corpus\vendor\terragoat\terraform\aws\ec2.tf`). Made **scan-root-relative** by stripping the scan-root prefix, *then* normalized — yielding `ec2.tf`, which is what checkov and trivy report for the same file.

**Repo-relative would be the wrong target and is worth naming as the trap it is.** Stripping only the repository root gives `corpus/vendor/terragoat/terraform/aws/ec2.tf`, which joins with neither of the other two scanners. The join key is the scan root, because that is the frame the scanners were invoked in.

Prefix matching is by normalized-case comparison on Windows, since the scan root as configured and the path as tfsec reports it need not agree on drive-letter case. An absolute path that does not lie under the scan root is an explicit error, not a silent pass-through.

**Identity resolution, per platform:**

- **Terraform** — from the scanner's own field, which is reliable there. A value matching `<type>.<name>` becomes a Terraform identity; anything else is classified by `identity_kind` per §2. Note tfsec sometimes appends the attribute (`aws_db_instance.default.publicly_accessible`); the trailing component is split off and becomes the fingerprint.
- **Kubernetes** — from the resource index (§4), by line for trivy and by kind/namespace/name for checkov. Container-scoped findings take the container component. Unresolvable → `<unresolved>`.

**Severity** goes through `rubric.normalize_severity(scanner, token)` unchanged. **Class** goes through `taxonomy.class_for(scanner, rule_id)` unchanged. S3a adds no judgement to either.

---

## 6. Deliverable 5 — the violation fingerprint

PLAN Q8 #6 added the fingerprint so that materially different violations on one resource are not collapsed. Measured fact 4 says only checkov supplies one.

**Rule.** The fingerprint is the normalized attribute path where the scanner supplies one, and **`None` — explicitly unresolved — where it does not.** It is never synthesized from line numbers, and never defaulted to a constant.

- **checkov** — `check_result.evaluated_keys`, normalized as follows, because "sorted and joined" is not a specification: discard the meta-key `resource_type`, which names no attribute; lowercase nothing (attribute paths are case-significant); sort the remaining keys lexicographically so key order in the scanner's output cannot change the fingerprint; join with `,`. An empty list after discarding → unresolved. A single key `storage_encrypted` therefore fingerprints as `storage_encrypted`, and two keys as `kms_key_id,storage_encrypted`.
- **tfsec** — the attribute split off the `resource` field where present; otherwise unresolved.
- **trivy** — unresolved, and the reason is measured rather than stylistic. Extraction is entirely feasible: **185 of 332 trivy Kubernetes `Resolution` strings (55.7%) carry a cleanly quoted attribute token**, e.g. `containers[].securityContext.runAsNonRoot`. The problem is that the vocabularies do not meet. Checkov spells the same attribute `spec/template/spec/containers/[0]/securityContext/readOnlyRootFilesystem` where trivy spells it `containers[].securityContext.readOnlyRootFilesystem` — different separators, different rooting — and the **exact string overlap between the two extracted vocabularies is 0** (18 distinct trivy tokens, 23 distinct checkov keys, no shared spelling). Extracting trivy's attribute would therefore produce **zero** additional Tier-1 collapses while adding a field that never matches. Closing the gap needs an attribute-normalization mapping across three scanner vocabularies — a taxonomy-sized artifact, not a line in an adapter. It is named here as scoped future work rather than attempted.

Synthesizing a fingerprint from the source span was considered and rejected: the three scanners report spans at incompatible granularities — checkov the whole resource block `[1, 42]`, trivy the precise cause `[11, 12]`, tfsec the block `[117, 134]` — so equal-fingerprint would almost never hold across scanners, and the dedupe key would track formatting rather than the violation.

The **per-scanner fingerprint-resolution rate is reported** as an evaluation-integrity metric, in the same discipline S0 applied to the 46.4% missing-severity finding.

---

## 7. Deliverable 6 — two-tier deduplication

`src/iacrisk/dedupe.py`. Q8's key is `(canonical resource identity, normalized issue-class, violation fingerprint)`.

**Tier 1 — exact collapse.** Two findings collapse when identity and issue-class match **and both fingerprints are resolved and equal**. Scanner provenance is retained as metadata on the collapsed group. **This tier alone produces the reported deduplication number.**

**Tier 2 — candidate overlap.** Findings sharing identity and issue-class where either fingerprint is unresolved are reported as *candidates*: counted, surfaced, and **never merged**. They do not enter the deduplication number.

**Tier 2 is reported as two numbers, never one — erratum, corrected 2026-09-24.** An earlier revision of this section stated the condition above (no scanner requirement) but labelled the output "candidate **cross-scanner** overlap". Those disagree, and Task 8's implementer found the disagreement by measuring 207 candidates where the controller had predicted ~123 and then re-deriving why, rather than bending to the prior. The 207 decomposes exactly:

| Population | Measured | What it is |
|---|---|---|
| Candidates, the condition above | **207** | every pair the pipeline declined to merge |
| — **cross-scanner** | **116** | two or more scanners, one resource, one class → the rule-family overlap PLAN #19 asks the dissertation to account for |
| — **same-scanner** | **91** | *one* scanner raising two or more findings on one resource in one class that no fingerprint separates → a limit of **this method**, not scanner overlap at all |

Merging them would label the 91 as cross-scanner overlap, which is precisely the error PLAN Q7 forbids for alert reduction: *two separate numbers, never combined*.

**What the 91 actually are, measured.** By raising scanner: **trivy 71, checkov 19, tfsec 1**. Trivy dominating is not incidental — it follows from §6, where trivy's fingerprint is always `None`, so *every* trivy pair sharing identity and class necessarily lands in Tier 2 and can never be separated. The largest single group is one trivy scan of the `docker-bench-security` DaemonSet's `docker-bench` container raising six KSV rules (`KSV-0001, 0012, 0017, 0020, 0021, 0105`) that all map to `containers-privileged-execution`. Of checkov's 19, the cleanest shape accounts for **6**: `CKV2_AWS_61` with `CKV2_AWS_62` on one bucket under `storage-data-lifecycle-hygiene`, on the buckets `flowbucket, data, financials, operations, data_science, logs`. The other 13 are `CKV_K8S_16/20/23/40` and `CKV_K8S_22/31` groups, plus the two single-rule cases below.

So the 91 compose **three** mechanisms, none of which is scanner disagreement:

1. the taxonomy **deliberately** groups many rule IDs into 28 classes — a design choice;
2. the scanner supplies no fingerprint with which to tell same-class findings apart — a data limit;
3. **one rule firing more than once on one resource** — measured on exactly **3** of the 91, where the group carries a single distinct rule id: tfsec `AVD-AWS-0057` ×5 on `aws_iam_user_policy.userpolicy` (five statements in one policy), checkov `CKV_SECRET_2` ×2 on one secret hash spanning `lambda.tf` and `providers.tf`, and checkov `CKV_K8S_21` ×2 on `v1/Service/default/health-check-service` declared in two files.

**Erratum, corrected 2026-09-25.** Mechanism 3 was missing, and the table row above read "*one* scanner raising several **distinct rules**". For those 3 the taxonomy-grouping cause does not apply at all — there is only one rule — so the earlier wording described 88 of the 91 and mis-described the rest. The whole-branch review found this by measuring the rule-id cardinality of every candidate; the counts were right, the mechanism sentence was not, and it is the sentence the limitations section quotes.

Mechanism 3 is also the shape the Rationale below already names — "two separate open ingress rules on one security group" — which makes it the best evidence in the section that the fingerprint is doing the job §6 added it for.

That makes the same-scanner figure the more valuable of the two for the write-up — it quantifies what **this method** cannot separate rather than a property of the scanners — and it belongs in the limitations section, not the alert-reduction result.

**A fourth number that must not be reported.** The controller's original ~123 was `(identity, class)` pairs spanning more than one scanner counted **before** Tier 1 ran, so it double-counts groups Tier 1 has already collapsed. It is neither of the two figures above and has no place in the results.

**Measured deduplication, for the record.** Over all five adapter runs on corpus v0: 1055 findings in, **35 Tier-1 groups holding 74 findings, so 39 removed** — a reported reduction of **39/1055 = 3.7%**, with exactly **one** of those groups cross-scanner. A conservative number, which is the intent.

Rationale. Collapsing on identity and class alone would maximise the measured reduction, but it is exactly what Q8 #6 added the fingerprint to prevent — two separate open ingress rules on one security group, or two different container fields, would become one finding and the number would be inflated by that conflation. Refusing to merge without evidence keeps the headline number conservative and true, and it matches the explicit-state discipline. Tier 2 is not a consolation prize: PLAN's scanner-selection note (#19) asks the dissertation to account for rule-family overlap between tfsec and Trivy, and the **cross-scanner** half of the candidate tier — the 116, not the 207 — is the evidence for exactly that discussion.

A finding whose identity is `<unresolved>` never collapses with anything, in either tier.

---

## 8. Deliverable 7 — the retention-coverage report

PLAN Q7 renames "detection coverage" to **normalization / retention coverage**: what fraction of scanner findings the pipeline correctly normalizes and carries through. S3a emits it, per scanner and per platform:

- findings in, findings out, and any dropped — with the reason;
- **identity-resolution rate**, and the unresolved count by cause (unparseable file, no line match, non-resource kind);
- **fingerprint-resolution rate**;
- `unmapped:` rate;
- `unknown` severity rate;
- Tier 1 collapses and Tier 2 candidate overlaps, reported as separate numbers, never summed.

Nothing is dropped silently. A finding the pipeline cannot fully resolve is carried with explicit states and counted, because a dropped finding would quietly improve every rate that follows.

---

## 9. Testing

Adapters are tested against the committed golden fixtures, which phase0 §4.5 designates for exactly this purpose — not against live scanners, so the suite stays hermetic and fast. `invoke.py` is tested separately and narrowly: that it reads the platform matrix from the lockfile and dispatches accordingly, not that the scanners work.

Every measured figure in §1 becomes an assertion, driven from the fixtures rather than restated as a literal, so a re-capture that changes the corpus fails the suite instead of leaving a stale claim standing. That is the S1 lesson applied: a test that compares an artifact to its own restatement cannot fail for the reason its name promises.

---

## 10. Acceptance gates

1. Every finding in every golden fixture produces exactly one `NormalizedFinding`, or is counted as dropped with a stated reason. No silent loss.
2. Every finding carries an issue-class — a real class or an explicit `unmapped:` id — and a severity level or the explicit `unknown`.
3. All 119 tfsec findings resolve to scan-root-relative paths that are **string-equal** to the normalized paths checkov and trivy report for the same files. Asserted as set equality over the shared files, not merely as "tfsec paths look relative".
4. Kubernetes identity resolves for every finding in a parseable manifest; findings in the 4 unparseable Helm templates take `<unresolved>` and are counted.
5. Tier 1 never collapses two findings with different resolved fingerprints, and never collapses an unresolved-fingerprint finding with anything.
6. The retention report accounts for every input finding: in = out + dropped, per scanner.

---

## 11. Deferred to S3b, explicitly

All five contextual attributes; the Q4 declared-context join; the four bounded exposure patterns and the target-not-rule attribution rule; the enumerated bucket-publicness combinations; the closed set of supported IAM constructs; per-factor unresolved rates. S3a produces the record those attach to, and nothing more.

**Also out of scope:** scoring and reporting (S4), the evaluation harness (S5). S3a emits machine-readable JSON; it computes no risk score.

---

## 12. Review-gate items, resolved

Both open items were settled by measurement rather than argument, and the measurement changed one of the answers.

1. **Non-resource checkov findings are retained** (§2.1). They are 8 of 489 findings (1.6%), so neither choice moves a metric materially; retaining needs only an honest label where dropping needs a defended exclusion from a coverage metric. They carry `context_eligible = False` so the §3.5(2) all-defaulted washout cannot float them into High for structural reasons.

2. **Trivy fingerprints stay unresolved, on evidence rather than principle** (§6). The original rationale — that `Resolution` is prose and parsing it would be inference — was wrong: 55.7% of trivy Resolutions carry a cleanly extractable quoted attribute. The real reason is that the extracted vocabulary has **zero exact overlap** with checkov's, so extraction would add a field that never matches and produce no additional Tier-1 collapse. The cost of doing better is named (an attribute-normalization mapping across three vocabularies) rather than hidden.

A third item surfaced from the same measurement and was folded into §4 — **and was then itself wrong.** This spec claimed checkov's four-component form was a container address. Task 3's implementer measured it against the manifests and found the fourth component is the pod template's **label**, 10 times out of 10. §4 now carries the corrected reading and the erratum. Recorded here rather than quietly rewritten, because a measurement that corrects an earlier measurement is exactly the kind of thing this project's §G3 discipline exists to keep visible.

## 13. Named future work, deliberately not attempted here

**Cross-scanner attribute normalization.** A mapping from each scanner's attribute vocabulary to one canonical spelling would move most Tier-2 candidate overlaps into Tier-1 exact collapses, materially raising the measured deduplication. It is taxonomy-sized — three vocabularies, per-rule spellings, its own acceptance gate and its own verification — and it is not in S3a, S3b, S4 or S5 as currently scoped. Recorded here so the smaller deduplication number S3a reports is understood as a scope boundary with a known price, not as a limitation of the approach.
