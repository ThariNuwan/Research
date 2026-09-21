# S1 — Phase-1 Pre-Implementation Specification Artifacts (Design)

**Status:** approved at the review gate; implemented by `docs/superpowers/plans/2026-09-19-s1-preimplementation-artifacts.md`
**Author:** Jayathissa E.A.T.N. (258243J)
**Date:** 2026-09-19
**Spec authority:** `docs/PLAN.md` (locked, Codex R4 APPROVED) — "Pre-implementation deliverables" and Q1–Q10.
**Upstream input:** `docs/superpowers/specs/2026-08-24-implementation-phase0-design.md` (S0) and the S0 rule inventory `artifacts/rule-inventory.json` (1055 rows).

---

## 0. Purpose and scope

S1 produces the five version-controlled specification artifacts that the runtime pipeline (S3+) and the evaluation harness (S2/S4) are built against. **No pipeline code is written in S1.** Each artifact has an acceptance gate copied verbatim from `PLAN.md`; this document is the design those artifacts are authored to.

The five deliverables, in dependency order:

1. **Issue-class taxonomy + scanner-rule-ID mapping** (+ `unmapped:` fallback) — blocks context-join, rubric, dedupe, test design.
2. **Per-factor scoring rubric** — blocks risk-scoring.
3. **Scanner severity-normalization table** — blocks the baseline comparison.
4. **Evaluation ground-truth schema** — blocks the evaluation harness.
5. **Canonical-identity spec** (Terraform + Kubernetes) — blocks context-join and dedupe.

Deliverables 1 and 3 are authored as one data file (`taxonomy.json`) plus one rubric config; the normalization table is the operational layer beneath the rubric's Severity factor. Everything the runtime consumes is **data, not code** — mirroring how S0 treats the platform matrix in `scanners.lock.json`.

### Global constraints (bind every deliverable)

- **Explicit-state discipline.** `unresolved`, `unattributed`, `unmapped:`, `unknown`, `None` are first-class states in the record and output JSON. None is ever silently defaulted to low/safe (PLAN Q9).
- **Frozen model.** Risk = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk. Ranges: Severity 1–5, Exposure/Privilege/Sensitivity/Criticality 0–5, EncryptionRisk 0–3. Max 28, min 1. Bands: Critical ≥22, High 16–21, Medium 9–15, Low <9. Ranges and bands **freeze at the end of S1**, before any scoring output is generated; later movement is reported as sensitivity analysis (Q10), never tuned to fit.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — applies to docstrings, comments, test names, briefs, ledger, commit messages, and this spec.
- **Windows-native host.** Always `uv run python`. Path normalization is by explicit character replacement (see §5).
- **Corpus v0 is a corpus observation, not a scanner contract.** Facts measured on this host (four severity levels, 46.4% null severity) describe corpus v0, not the scanners' capabilities.

---

## 1. Deliverable 1 — Issue-class taxonomy

### 1.1 Structure

A **category-first, 28-class** taxonomy over five categories (storage, networking, IAM, compute, containers — the five tested domains). Each class has an `id`, `category`, `title`, and a one-sentence `definition`. Every one of the 255 distinct scanner rule IDs observed across corpus v0 maps to exactly one class; **0 unmapped** in corpus v0.

Grounding method: the taxonomy was derived from all 255 rule IDs (checkov 128, trivy 79, tfsec 48) by a parallel classification pass, then an adversarial cross-scanner reconcile pass that caught and corrected two real defects (below), then three delegated structural rulings.

### 1.2 The 28 classes

**storage (7)**
| id | title | rules |
|---|---|---|
| `storage-encryption-at-rest` | Data-store encryption at rest missing | 21 |
| `storage-key-management-cmk` | Weak encryption key ownership / rotation | 20 |
| `storage-transit-encryption` | Data-store transport encryption weak or absent | 8 |
| `storage-public-accessibility` | Data store publicly accessible | 15 |
| `storage-logging-audit` | Data-store logging / audit gaps | 16 |
| `storage-data-recoverability` | Backup / durability / deletion-protection gaps | 19 |
| `storage-data-lifecycle-hygiene` | Lifecycle / snapshot-tagging / patch-currency hygiene | 6 |

**networking (6)**
| id | title | rules |
|---|---|---|
| `networking-ingress-exposure` | Unrestricted inbound exposure | 12 |
| `networking-egress-exposure` | Unrestricted outbound egress | 3 |
| `networking-isolation-segmentation` | Weak network isolation / segmentation | 8 |
| `networking-transport-encryption` | Load-balancer / listener transport encryption | 2 |
| `networking-flow-logging` | Network flow / access logging gaps | 4 |
| `networking-config-hygiene` | Security-group documentation hygiene | 5 |

**iam (4)**
| id | title | rules |
|---|---|---|
| `iam-overpermissive-policy` | Over-permissive / wildcard permissions | 11 |
| `iam-privilege-escalation-sensitive-perms` | Privilege escalation & sensitive-permission paths | 5 |
| `iam-authentication-controls` | Identity & authentication controls | 10 |
| `iam-hardcoded-secrets` | Hardcoded credentials & secret exposure | 7 |

**compute (4)**
| id | title | rules |
|---|---|---|
| `compute-instance-metadata-hardening` | Instance metadata service hardening | 3 |
| `compute-workload-integrity-patching` | Workload integrity & patch currency | 3 |
| `compute-managed-cluster-hardening` | Managed orchestration control-plane hardening | 6 |
| `compute-reliability-observability` | Compute reliability & observability gaps | 7 |

**containers (7)**
| id | title | rules |
|---|---|---|
| `containers-privileged-execution` | Privileged / root container execution | 13 |
| `containers-linux-capabilities` | Excess Linux capabilities | 7 |
| `containers-host-isolation-breakout` | Host isolation / breakout surface | 11 |
| `containers-securitycontext-hardening` | Missing security-context hardening | 9 |
| `containers-image-supply-chain` | Image provenance & supply chain | 7 |
| `containers-workload-reliability` | Workload resource-limit & hygiene gaps | 14 |
| `containers-image-vulnerability-scanning` | Registry image vulnerability scanning | 3 |

Full per-class definitions ship in `taxonomy.json`; they are the one-sentence definitions grounded against the rules assigned to each class.

### 1.3 The three delegated structural rulings

Decided under "do the best way possible" / "best options":

1. **EKS split by property.** EKS control-plane logging & cluster secrets-encryption → `compute-managed-cluster-hardening`; the public-endpoint property → networking exposure. Rationale: the scoring factors read different axes off the two properties; keeping them in one class would blur the compute/networking boundary. (Most-arguable line — flagged for the review gate.)
2. **`containers-image-vulnerability-scanning` added (base tree 26 → 27).** ECR scan-on-push (`CKV_AWS_163`, `AVD-AWS-0030`) is a CVE-detection property with no home in the base tree and both scanners agree it is distinct from image provenance. Placed in `containers` (the property is a workload/registry concern) though the resource is `aws_ecr_repository`.
3. **`storage-data-protection-resilience` split (27 → 28).** The base class was overloaded (~24 rules across backup, HA, patch-currency, operational integration). Split into `storage-data-recoverability` (backup/durability/deletion-protection/Multi-AZ/HA) and `storage-data-lifecycle-hygiene` (lifecycle config, copy-tags-to-snapshots, event notifications, auto minor-version upgrade).

Net: base tree 26 → 28 classes.

### 1.4 Acceptance gate (verbatim from PLAN)

> Every rule ID emitted by the pinned scanner versions across the corpus maps to an issue-class or an explicit `unmapped:` entry (measured mapping completeness); taxonomy covers all five tested categories.

Met in corpus v0: 255/255 mapped, 0 unmapped, all five categories populated.

---

## 2. Deliverable 1 (cont.) — Scanner-rule-ID → class mapping

### 2.1 Structure

`taxonomy.json` carries one row per observed `(scanner, rule_id)` — 255 rows. Each row:

```json
{ "scanner": "tfsec", "rule_id": "AVD-AWS-0026", "canonical_id": "AWS-0026",
  "class_id": "storage-encryption-at-rest", "title": "..." }
```

Keying on the raw `(scanner, rule_id)` as-emitted (not a pre-normalized key) keeps every row independently verifiable against the S0 fixtures. No wildcards.

### 2.2 Canonical identity for cross-scanner equality

`canonical_id` strips a leading `AVD-`: trivy emits `AWS-0026`, tfsec emits `AVD-AWS-0026`, both are the same Aqua rule → `canonical_id = AWS-0026`. (Corpus v0 holds 45 such twin pairs; `AWS-0057`, `AWS-0082` and `AWS-0088` are tfsec-only and have no trivy counterpart, so they canonicalize without pairing.) Checkov IDs (`CKV_AWS_*`, `CKV2_AWS_*`, `CKV_K8S_*`, `CKV_DOCKER_*`, `CKV_SECRET_*`) are their own canonical form.

Two guarantees asserted as tests:
- **Co-location.** Every trivy `AWS-####` and its tfsec `AVD-AWS-####` twin map to the same `class_id`. True by construction for the 45 twin pairs (trivy took tfsec's class directly during derivation); the test locks it so no future edit can split a twin.
- **Dedupe key.** The key itself is defined in §5.4 — `(canonical resource identity, normalized issue-class, violation fingerprint)` — and that is what the implementation uses. `canonical_id` is not a term in it. Its role here is upstream: the co-location guarantee above is what makes a trivy finding and its tfsec twin carry the *same* `class_id`, which is what lets the §5.4 key recognise them as one logical finding (the deduplication half of the Q7/Q8 alert-reduction number).

  Note the consequence, because it is a reported metric: keying on issue-class rather than on `canonical_id` collapses **any** two findings sharing a class on one resource with one fingerprint, not only Aqua twins. That is the intended behaviour — two rules flagging the same missing control on the same attribute are one remediation — but it means the dedup number measures class-level collapse, and it must be described that way rather than as twin-level collapse.

### 2.3 Provenance

Each row traces to a fixture occurrence. The 45 twin-derived trivy rows are distinguished from the 34 trivy rows placed via the class tree's own example IDs (no tfsec twin), so the mapping is transparent about which placements are cross-scanner-proven vs single-scanner.

### 2.4 The `unmapped:` fallback

Coverage is 255/255 **for corpus v0 as measured on this host** — a corpus observation, not a scanner contract. A newer scanner version or an unseen rule emits an ID not in the table. The runtime assigns it `class_id = "unmapped:<scanner>:<rule_id>"`, scored severity-only / default-context, surfaced as **"baseline-only informational"** (PLAN Q8 #6), counted once, never dropped, and **excluded from prioritization-quality claims** (PLAN Q7 #9). A test feeds a synthetic unknown rule ID and asserts it lands in `unmapped:` rather than any of the 28 classes.

---

## 3. Deliverable 2 — Per-factor scoring rubric

Six factors, per-level definitions source-anchored to CVSS v3.1 / NIST SP 800-30 Rev.1 / FIPS 199 / OWASP Top 10 2021 / OWASP Risk Rating Methodology / NSA-CISA Kubernetes Hardening Guidance. Rubric ships in a shared config file, mirrored verbatim in the dissertation (PLAN Q5).

### 3.1 Verification provenance, and its limits

The rubric's per-level anchors were checked during design by an adversarial verification pass — 6 per-factor citation/boundary/unresolved checks plus 2 cross-factor coherence passes. Its actionable output is the corrections in §3.4 and the coherence resolutions in §3.5. **Result: no *fabricated* standard** — every CVSS band and NIST tier named corresponds to a real published tier.

Three limits bound what that pass warrants. They are stated because the alternative is a claim the record cannot support, which is the §G3 defect class this document defines for itself.

1. **It did find misattributions, so "verified" is not unqualified.** §3.4 records one directly: Criticality L3 sourced the pre-prod-touches-prod-data elevation to NSA-CISA, which is silent on environment ladders. An earlier version of this section claimed "no fabricated **or misattributed** standard", which its own §3.4 contradicted. The accurate claim is the narrower one above.

2. **The corrections did not reach the artifact for a month.** §3.4 was written as *applied*, but the edits were made to this prose only. `rubric.json` shipped with all fourteen still present and was marked frozen, and six task reviews missed it — because every check asserted the artifact was byte-identical to its design input, and that input carried the same uncorrected text. The check compared uncorrected text against itself and could not fail for the reason that mattered. Applied to the artifact in commit `bf72673`.

3. **The pass's raw output is not in this repository, and no audit of the shipped text exists.** The pass ran against a design-time working file; what survives is this section's summary. A reader can check that §3.4's corrections are applied to `rubric.json`; they cannot re-derive the pass. Accordingly `rubric.json` carries `citations_audited: false` **separately from** `structure_frozen: true`. The structural freeze is earned — the six factors, their ranges, the 1–28 bounds and the bands were computed before any scoring output existed and are pinned by tests. The citation text is not, and no test can make it so: the anchor gate only checks that a standard's *name* appears in the string, which cannot distinguish a correct citation from a plausible one.

**Consequence for the dissertation.** Any text quoting a `source` string needs an independent audit of all 33 levels against the primary sources, committed as its own artifact, before it can be relied on. That audit is scoped work, not a test.

### 3.2 The six factors and unresolved policies

| Factor | Range | Unresolved default | Policy |
|---|---|---|---|
| Scanner severity | 1–5 | `unknown` → 4 | conservative-scored |
| Public exposure | 0–5 | 3 (sweep [2..5]) | sensitivity-analysed |
| IAM privilege scope | 0–5 | 4 | conservative-scored |
| Resource sensitivity | 0–5 | 3 | conservative-scored |
| Environment criticality | 0–5 | 4 | conservative-scored |
| Encryption risk | 0–3 | 2 | conservative-scored |

Every unresolved default was verified to satisfy PLAN Q9's "never silently scored low" rule. Public exposure is sensitivity-analysed (not a fixed default) precisely because Q9 names it as the factor a fixed numeric default distorts; the [2..5] sweep keeps unresolved-exposure findings in the ranking while quantifying the uncertainty.

Per-level definitions, justifications, and anchors ship verbatim in the rubric config.

### 3.3 Severity normalization (Deliverable 3, the layer beneath the Severity factor)

A per-scanner **raw-token → 1–5** table, version-controlled, so the baseline (raw scanner severity) is genuinely comparable across scanners (PLAN Q7 #5):

| Scanner token | Level | Note |
|---|---|---|
| CRITICAL | 5 | observed in trivy/tfsec |
| HIGH | 4 | observed |
| MEDIUM | 3 | observed |
| LOW | 2 | lowest exercised in corpus v0 |
| (CVSS None / 0.0) | 1 | reserved; not exercised |
| Trivy `UNKNOWN` | → `unknown` → 4 | severity-undetermined, routed to unresolved default |
| Checkov `null` | → `unknown` → 4 | 46.4% of corpus v0; public-path severity absent |

`severity=unknown` is a first-class state; the per-scanner unknown rate is reported as an evaluation-integrity metric (PLAN Q3 #4).

### 3.4 Citation corrections applied (from the verification pass)

- **Severity level-1 "informational" → UNKNOWN (grave, and the question phase0 left to S1).** Phase0 §A.3 item 4 recorded only four observed levels and required S1 to "say what the fifth level is for, or drop to four"; it did not itself warn against reading the fifth level as informational. This bullet is that answer. Trivy's fifth level is `UNKNOWN` (severity-undetermined), not a benign informational/None band. Fixed: `UNKNOWN` routes to the unresolved default (4), not level-1/score-1 — captured in the §3.3 table. Level 1 remains reserved for a genuine CVSS None/0.0.
- **IAM levels 1/2/5:** drop the CVSS `PR:` parentheticals (PR = attacker prerequisite, not authority granted); the NSA-CISA / NIST anchors that carry those levels are correct and stay.
- **Criticality L3:** the "pre-prod that touches prod data is elevated" claim is re-sourced from NSA-CISA (which is silent on environment ladders) to OWASP A05 environment-parity + NIST Moderate/CVSS CR:Medium.
- **Encryption L0:** "Appendix G" → "Appendix H, Table H-3" (impact scale; the rest of the doc already cites H-3). **L1:** CVSS C:L quote fixed to "…the amount or kind of **loss** is limited" (not "information obtained"). **L3:** NSA-CISA framed as recommended hardening, not hard "required controls."
- **Sensitivity:** "PII" given one home — L4 reserved for specially-regulated PHI/PCI/trade-secrets, generic PII → L3 (MECE fix). OWASP RRM quote "extensive **critical** data" (value 7), NIST "severe **or catastrophic**."
- **Public exposure:** ClusterIP → L1 only (removed from L0). **Precedence rule added:** a `0.0.0.0/0` (or `::/0`) network-layer opening forces exposure ≥4; identity-gating modulates only *within* a network-openness tier, never across it. Level-5 differentiator restated on the anonymous-vs-authenticated axis rather than the arguable CVSS `S:C`.
- Minor: OWASP "Note" not "Note/informational"; drop non-existent NIST "Low-to-Moderate"/"upper High" tiers (state as ordinal interpolation); FIPS-199 sub-Low reworded as N/A.

### 3.5 Coherence resolutions (the three approved structural decisions)

1. **IAM band cap — governed-resource inheritance.** Bare identity findings score 0 on Exposure/Sensitivity/EncryptionRisk, capping an admin-wildcard at 15 (Medium). Resolution: for a **resource-attached** IAM finding, Sensitivity and Criticality are inherited from the *governed resource's* declared context (available via the Q4 context-join, no graph resolve, so within Q9's bounded extraction). A pure account-level admin policy with no attachment keeps the cap and is documented as a stated limitation of the transparent additive model. An assertion test confirms no privilege-5 resource-attached finding is capped below High when the governed resource carries declared context.
2. **Unresolved-default washout + inversion.** The five context defaults sum to 16, so all-unresolved findings land 17–21 (always High) and resolving context downward can lower a band. Resolution (evaluation-integrity, not a model change): (a) report band distribution **split by count-of-defaulted-factors**; (b) findings above a defaulted-factor threshold are flagged low-confidence and **excluded from prioritization-quality claims** (same discipline as `unmapped:`); (c) the stacked-default total is carried into the Q10 sensitivity analysis.
3. **Severity↔context double-count + Critical knife-edge.** Scanner severity is rule-level and already prices a class's generic exposure/impact; context factors add it at instance level. Resolution: fence definitionally — **severity is treated as a context-free rule baseline; the five context factors are instance-level deltas scored only from resolved instance evidence, never re-derived from the rule** — and prove it empirically via the planned contrastive pairs + baseline rank-change table, plus report the severity-vs-context correlation as an integrity number. The frozen thresholds are sanity-checked against a hand-labelled must-be-Critical panel; any knife-edge is reported as sensitivity analysis, not tuned away. **`class_id` is never a term in the score** (assertion test) — forecloses re-amplifying exposure via the taxonomy dimension.

A secondary orthogonality fix: **Encryption L3** keys only on the control-mandate being an established engineering requirement (e.g. NSA-CISA etcd Secret encryption, TLS across a trust boundary) — the data's regulated status raises Sensitivity alone, so the two axes share no input.

### 3.6 Acceptance gate

Rubric anchors cite CVSS/NIST/NSA-CISA/OWASP, each score point justifiable; equal-weighted additive sum is the primary model; weighting is a tunable framed as sensitivity analysis. (No PLAN-stated numeric gate; the verification pass in §3.1 is the evidence of anchor soundness.)

---

## 4. Deliverable 4 — Evaluation ground-truth schema

A version-controlled, machine-validated schema the harness *reads*; results are never hand-judged (PLAN Q7). Three record types, never merged (matches PLAN #16 mechanism-vs-scenario split and the split metric reporting).

### 4.1 Case record

One config under test: `case_id`, `platform`, `domain` (storage/networking/iam/compute/containers), `source` (`{repo, commit, path}` or `hand-crafted`), `declared_context` keyed on canonical resource identity (§5) with `sensitivity`/`criticality` each `0–5` **or `null`** (null exercises the default-fallback path), and an `expected` block. `unmapped:`/`unresolved` are first-class in expected findings so the harness holds them to Q7 #9 exclusion.

### 4.2 Contrastive-pair record (mechanism test)

`pair_id`, `factor_under_test`, `case_high`, `case_low`, expected `rank(high) > rank(low)`, expected score-delta sign. The **"differs in exactly one factor" invariant is machine-checked** by the harness against the two cases' resolved factors — the claim the pair rests on is one the artifact actually supports (§G3).

### 4.3 Scenario-ordering record (realistic test)

`scenario_id`, `domain`, `expected_ordering` (partial order / tiers over cases), pre-registered `rationale`, and an `oracle` block: `author` ≠ `reviewer`, `registered_at` (must precede any scoring output), `reviewer_verdict`, `disagreement_note`. Disagreements are reported as **oracle uncertainty**, not resolved away (PLAN Q7 R2 #7 / R3 #9).

### 4.4 Ordering primary, band secondary

The coherence pass showed absolute bands are knife-edge-sensitive (the flagship bucket sits exactly on 22). So the **primary** mechanism signal is relative ordering / rank-movement direction; per-case `expected_band` is a **secondary, optional** field. The oracle leans on ordering, keeping the evaluation stable against the exact threshold-sensitivity §3.5(3) flagged.

### 4.5 Acceptance gate (verbatim)

> Schema validates on all corpus cases; harness rejects a case with missing/ill-formed expected outputs rather than skipping it.

Implemented as JSON-Schema validation at harness entry: a malformed/absent `expected` block is a hard reject, not a skip.

---

## 5. Deliverable 5 — Canonical-identity spec (TF + K8s)

The per-platform resource identity the context-join (Q4) and dedupe (Q8) key on.

### 5.1 Terraform identity

Structured tuple with a canonical string form:

```
<module_path> :: <resource_type>.<resource_name> [<instance_key>]
```

- `module_path` disambiguates duplicate local names across modules; `instance_key` is the `for_each` key or `count` index where present.
- `moved` blocks map old→new address so a relocated resource keeps one identity.
- **Unresolvable dynamic `for_each` keys → explicit `[<unresolved>]`**, counted in the fallback rate; never silently merged.
- Data sources (e.g. `data aws_iam_policy_document`) stay outside the managed-resource scheme unless a scanner flags one, in which case `type.name` with no instance key.

### 5.2 Kubernetes identity

```
<apiVersion>/<kind>/<namespace>/<name> [container=<container_name>]
```

- `container_name` is present for container-scoped findings (multi-container pods, initContainers).
- Cluster-scoped / namespace-less kinds (`Namespace`, `ClusterRoleBinding`, `ClusterPolicy`) omit the namespace component explicitly.
- Omitted `metadata.namespace` → the documented default, flagged.
- **Helm-templated components** (`{{ }}` names/namespace/container, e.g. the `metadata-db` scenario) → explicit `<unresolved>`, counted in the fallback rate — the K8s analogue of the TF dynamic-key case.

### 5.3 File-path normalization (load-bearing, phase0 §A.4)

Checkov emits **mixed** separators for the same file across framework blocks (`\ec2.tf` vs `/ec2.tf`, `/resources\Dockerfile`). Normalization is a named, tested function that:
1. replaces `\` → `/` by **explicit character replacement** (PurePosixPath does not do this on Windows),
2. strips the leading separator,
3. assumes **no** single spelling per file.

Without this the context-join silently misses.

### 5.4 Dedupe key (Q8) — where §2 and §5 meet

`(canonical resource identity, normalized issue-class, violation fingerprint)`. The **fingerprint** is the specific affected attribute/config path (one IAM action, one SG ingress rule, one K8s container field) so materially different violations on one resource are not collapsed. Cross-scanner dedup uses `canonical_id` (§2.2) with this canonical resource id; scanner provenance is retained as metadata.

### 5.5 Corpus coverage (the gate), enumerated

**Acceptance gate (verbatim):** *Identity is defined for every resource/instance shape present in the corpus (module, `for_each`/`count`, namespace/kind).*

Confirmed by read-only inventory of `corpus/vendor/`:

**Terraform** (terragoat `terraform/aws`): no `module` blocks, no `for_each`, no `moved`, no duplicate `<type>.<name>`; 39 resource types. One instance-key case: `aws_neptune_cluster_instance.default` with static `count = 1` → `[0]`. The `module_path` and `[<unresolved>]` machinery is defined for robustness but the TF corpus exercises only base `type.name` and one static `[0]`. Stated honestly rather than implied stressed.

**Kubernetes** (kubernetes-goat `scenarios`): cluster-scoped/namespace-less kinds present (`Namespace`, `ClusterRoleBinding`, `ClusterPolicy`) — namespace-optional identity is corpus-tested. Multi-container shapes present (`internal-proxy` two containers; `health-check`, `docker-bench` initContainer+container) — `container_name` is corpus-exercised. The `metadata-db` Helm chart exercises the `<unresolved>` path (templated name/namespace/container).

Every shape the corpus contains maps to a defined identity rule; the unresolved path is exercised by the Helm case rather than left theoretical.

---

## 6. Deliverable summary and gates

| # | Deliverable | Artifact | Gate status (corpus v0) |
|---|---|---|---|
| 1 | Taxonomy + mapping | `taxonomy.json` | 255/255 mapped, 0 unmapped, 5 categories, 28 classes ✅ |
| 2 | Scoring rubric | rubric config | 6 factors anchored, verification-clean after §3.4/§3.5 ✅ |
| 3 | Severity normalization | rubric config §3.3 | per-scanner token→1–5, unknown-state routing ✅ |
| 4 | Ground-truth schema | schema + validator | validates/rejects at harness entry ✅ (spec) |
| 5 | Canonical identity | identity module spec | every corpus shape has a rule ✅ |

All ranges/bands freeze at end of S1. The taxonomy is the cross-cutting single source of truth for §2 (mapping), §3 (rubric class-anchoring), §4 (test design), and §5.4 (dedupe).

---

## 7. Open items for the review gate

1. **EKS split (§1.3.1)** — the most-arguable taxonomy boundary; confirm compute-vs-networking split by property.
2. **DB IAM auth** — placed in `iam-authentication-controls`; confirm it is IAM, not storage.
3. **IAM governed-resource inheritance (§3.5.1)** — confirm the hybrid (inherit Sensitivity/Criticality from the governed resource for resource-attached IAM findings; cap + document for account-level policies) is the intended resolution of the band-cap.
