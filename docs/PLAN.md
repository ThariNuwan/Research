# PLAN.md — Locked Architecture Plan

**Project:** A Framework for Risk-Aware Security Misconfiguration Detection and Prioritization in Cloud Infrastructure-as-Code (IaC) Environments
**Author:** Jayathissa E.A.T.N. (258243J) — MSc in Computer Science (Cloud Computing), University of Moratuwa
**Status:** Design locked (Act 1, Q1–Q10) + revised through Codex Round 4 adversarial review — **APPROVED (Codex, Round 4, no viva-fatal blockers)**.
**Date captured:** 2026-07-26 (Q10 added 2026-07-27; Codex R1–R4 revisions 2026-07-28)

> **Terminology (fixed after review):** there are **five contextual attributes** (Public Exposure, IAM Privilege Scope, Resource Sensitivity, Environment Criticality, Encryption Risk) which, **together with scanner severity, make six scoring factors**. "Six contextual factors" was imprecise; use "five contextual attributes + severity" throughout.

---

## Goal

Build an **automated Python pipeline (with a required declared-context input for its primary mode)** that sits *on top of* existing IaC scanners (Checkov, tfsec, Trivy) and adds a **transparent, explainable prioritization layer**. The layer enriches each scanner finding with cloud context and produces a ranked, priority-categorized remediation list. The prioritization layer is the **main research contribution**; detection is delegated to the baseline scanners and is not re-implemented. Optional convention-based **auto-inference** of the two declared factors is built and evaluated separately, not as the headline result.

This is **design-oriented research**: the deliverable is the artifact **plus** an evaluation of its prioritization quality — not just working code. Every design decision below traces back to that evaluation.

---

## Approach — the 5-layer pipeline

1. **IaC Input** — Terraform (`.tf`, HCL) and Kubernetes YAML manifests.
2. **Security Scanning** — invoke Checkov, tfsec, Trivy as subprocesses; parse each JSON output into one **normalized finding record**.
3. **Context Extraction** — enrich each finding with the five contextual attributes (two from declared context; three parsed from the flagged resource **and bounded related resources where explicitly supported**, per the exposure-scope list in Q9).
4. **Risk Scoring** — explainable weighted-additive score over six factors (five attributes + severity); NOT ML.
5. **Reporting** — rank findings, map to priority bands, emit machine-readable JSON + human report.

An **independent evaluation harness** consumes the JSON to compute the evaluation metrics.

---

## Locked decisions (Q1–Q9)

### Root — Artifact form: **B+ (hybrid)**
Fully-automated Python pipeline (option A mechanics) but with an **honest declared-context seam** for the two factors that are *not* reliably derivable from IaC code (Resource Sensitivity, Environment Criticality).
- **Primary evaluation** runs on a clean **declared-context** path (deterministic, defensible inputs).
- **Convention-based auto-inference** of sensitivity/criticality is built and evaluated as a **second mode**, so the tool is genuinely automated end-to-end but the headline results don't rest on noisy heuristics.
- **MSc scope confirmed** (the memory/PDF "PG Dip" wording is stale — to be corrected in CLAUDE.md).

### Q3 — Language & scanner integration
- **Python** end-to-end.
- Invoke **Checkov / tfsec / Trivy via subprocess**, parse each JSON output into a single **normalized finding record** (issue id, description, severity, affected resource, file path, remediation suggestion, source scanner).
- **Pin scanner versions** for reproducibility.
- **Platform-scanner matrix (revised after review R3, #3):** applicability differs by input type — tfsec is **Terraform-only**; Kubernetes coverage comes from **Checkov + Trivy**. Fail loudly only when a scanner **required for the platform of the input under analysis** is missing — not when an inapplicable scanner is absent.
- **Missing/unknown native severity (revised after review R3, #4):** some findings (version/config-dependent) arrive with absent or unknown severity. Map these to an explicit `severity=unknown` state with a documented conservative default, and **report the missing-severity rate** — never silently treat as low.

### Q4 — Context join
- **Per-resource declared context**, keyed on a **canonical resource identity** defined **separately per platform** (see below).
- **Documented default** applied when no declared-context match exists — **this fallback applies only to missing declared Sensitivity/Criticality (revised after review R4, #2)**. It is distinct from the extractor's `unresolved` state (Q9): a *missing declared value* takes the documented default, whereas an *extractor failure* on a code-derived factor is marked `unresolved` and handled per the Q9 policy. The two are reported as separate rates.
- **Report the default-fallback rate** as an evaluation-integrity metric (so reviewers can see how much of the corpus leaned on defaults vs. explicit context).

**Canonical identity (revised after review, #9):** `<type>.<name> + file path` is insufficient for real IaC. Define identity per platform:
- **Terraform:** module path + resource type + name + instance key (`for_each`/`count` index) where present; account for `moved` blocks and duplicate local names across modules.
- **Kubernetes:** `apiVersion/kind` + namespace + name (+ container name for container-scoped findings).
Unresolvable instance keys (dynamic `for_each`) → documented default, counted in the fallback rate.

### Q5 — Scoring rubric
- **Fine-grained, source-anchored, deterministic per-factor rubrics** in a **shared config file**, mirrored verbatim in the dissertation.
- Rubric anchors cite **CVSS / NIST 800-30 / NSA-CISA / OWASP** so each score point is justifiable, not arbitrary.
- **Equal-weighted additive sum** is the **primary model**.
- **Weighting is a tunable** tested during evaluation (see Q10 — to be framed as sensitivity analysis, not fitting).

### Q6 — Test corpus
- Mix of **open-source deliberately-insecure configs** (TerraGoat, KubeGoat — cited) **plus hand-crafted contrastive pairs** (configs differing in exactly one contextual factor, to prove a factor *causes* a rank change).
- **~20–30 cases** spanning storage / networking / IAM / compute / containers, **with per-category coverage counts reported**. Evaluation is framed as **controlled artifact validation, not generalizable empirical proof** (#4) — the corpus is too small for broad claims across two platforms × three scanners × five domains, and the write-up says so explicitly.
- **Version-controlled with expected output**; each re-ranked finding is **justified by named factors**.

### Q7 — Output & evaluation separation
- Tool emits **JSON (source of truth)** + a rendered **Markdown/HTML report**.
- A **separate evaluation harness** computes the metrics from that JSON.
- **Baseline** = raw scanner severity mapped into the same four priority bands. Because raw severity is **not equivalent across Checkov/tfsec/Trivy** (#5), the mapping uses a **documented scanner-specific severity-normalization table** (each scanner's native levels → a common 1–5 scale), justified and version-controlled, so baseline-vs-framework is genuinely comparable.

**Evaluation metrics (revised after review, #2/#3/#16/#17):**
- **Normalization / retention coverage** (renamed from "detection coverage") — what fraction of scanner findings the pipeline correctly normalizes and carries through. *Not* detection accuracy (delegated to scanners).
- **Prioritization usefulness** — measured against a defined **oracle**, not by inspection: (a) **contrastive-pair pass/fail** (does the rank move in the predicted direction when one factor changes?), and (b) **scenario-expected ordering** (hand-labeled expected orderings per domain). **Oracle independence (revised after review R2 #7 / R3 #9):** scenario rationales are **pre-registered before any scoring output is generated**, and the expected-ordering labels get **independent supervisor review** — the rubric author does not also silently set the labels, or the evaluation is circular. **Reviewer disagreements are recorded** and either resolved before scoring or **reported as oracle uncertainty** (no pretence of a single unanimous ground truth).
- **Alert reduction** — reported as **two separate numbers**: (a) reduction from **deduplication** alone, (b) reduction in **Critical/High band** count from prioritization. Never combined into one headline (#17).
- **Ranking consistency — split into two distinct measures (revised after review R2, #8):** (a) **auto-inference agreement** — how closely the auto-inference mode's ranking matches the declared-context ranking (tests heuristic quality); (b) **model sensitivity** — how stable the ranking is under threshold/weight perturbation (tests model robustness). These are not averaged together.
- **Baseline comparison** — rank-change table vs the normalized baseline, each change justified by named factors.
- **Unmapped findings (revised after review R2, #9):** `unmapped:*` findings are **reported separately and excluded from prioritization-quality claims** (severity-only scoring would otherwise artificially depress serious-but-unmapped findings). Their count and rate are reported as a coverage/limitation figure.

**Mechanism vs. scenario (revised after review, #16):** contrastive pairs are **mechanism tests** (prove the formula reacts to a factor) and are reported separately from **realistic-scenario evaluation** (prove the ranking is useful on whole configs). No causal-validity claim is made beyond the controlled pairs.

**Evaluation ground-truth schema (added after review, #20):** define, *before* coding the harness, a version-controlled schema for expected outputs — per-case expected priority band, expected relative ordering, contrastive-pair expectation (which factor should move the score and which way), and expert/scenario labels. The harness reads this; results are not hand-judged.

### Q8 — Deduplication
- Deduplicate to **one logical finding per `(canonical resource, normalized issue-class, violation fingerprint)`** — the **fingerprint** (affected attribute / config path, e.g. a specific IAM action, a single SG ingress rule, one K8s container field) is added after review (#6) so that materially different violations on the same resource are **not** collapsed.
- Keep **provenance** (which scanners flagged it) as metadata.
- Taxonomy **scoped to tested categories**; **unmapped rules** are assigned a synthetic class `unmapped:<scanner>:<rule_id>` and scored **severity-only / default-context**, documented explicitly. Such findings are labelled **"baseline-only informational" (revised after review R3, #6)** — surfaced for completeness but **not counted as framework-prioritized findings**, matching Q7's exclusion of them from prioritization-quality claims. Counted once, never silently dropped.
- Prevents scanner overlap from inflating the alert-reduction metric (which is itself reported split by dedup vs. prioritization, per Q7).

### Q9 — Context/attribute extraction: **hybrid (option C)**
- **Scanner rule ID seeds the issue-class** (cheap, reliable first signal).
- **Bounded per-finding attribute parsing** reads rubric values **only for flagged resources** (not a full graph resolve).
- **Literals-only**: interpolated / variable / unresolved values are represented as an **explicit `unresolved` state — not a silently-substituted numeric default (revised after review R3, #5)**. For **exposure and IAM** especially, a numeric default can distort rankings even when the unresolved rate is reported, so unresolved factors are handled by one of: (a) **conservative scoring** (assume the risk-relevant value pending proof), (b) **exclusion from prioritization-quality claims**, or (c) a **bounded sensitivity analysis** over the plausible range — chosen per factor and documented. The unresolved state is first-class in the finding record and the output JSON.

**Extraction fidelity — honest limits (added after review, #10/#11/#12/#13):**
- **Per-factor unresolved rate** is reported, not just an overall fallback rate; cases with high unresolved rates are flagged and analyzed separately (#10).
- **Public exposure — supported patterns fixed now (revised after review R1 #11 / R2 #6).** Bounded cross-resource lookups are implemented for a **committed, closed list** of exposure patterns present in the corpus:
  - security-group / NSG ingress open to `0.0.0.0/0` (or `::/0`) attached to the flagged resource;
  - a resource carrying a public-IP / `publicly_accessible` / public-endpoint flag;
  - storage buckets with public-access-block disabled or public ACL/policy;
  - Kubernetes `Service` of type `LoadBalancer`/`NodePort` and `Ingress`.
  **Explicitly unsupported** (→ marked *unresolved*, never scored as low-exposure): multi-hop route-table + subnet + IGW/NAT reachability analysis, VPC peering / transit-gateway paths, and DNS-based exposure. This scope is fixed before corpus finalization so test cases and expected outputs match what the extractor actually supports.
  - **Exposure attribution (revised after review R3, #7):** for the SG/NSG pattern, a scanner finding may land on the **rule resource** (e.g. `aws_security_group_rule`) rather than the **attached target** (compute/storage). Rule: exposure is attributed to the **target resource**, with the open-ingress rule resource resolved via the bounded lookup; the **violation fingerprint** records which resource the scanner originally flagged so dedupe does not merge a rule-level and target-level finding incorrectly.
  - **Bucket publicness (revised after review R3, #8):** bucket exposure can derive from separate ACL, bucket policy, object-ownership, and public-access-block resources. **Supported combinations are enumerated** (public-access-block disabled; public ACL; public policy statement); **partial or cross-resource combinations outside the enumerated set → unresolved**, not assumed private.
- **IAM privilege scope** is not a simple literal read (indirect attachment, wildcards + conditions, managed policies/bindings). Define the **exact IAM constructs supported**; anything outside them is marked **unresolved (not low-risk)** so the score never falsely reassures (#12/R1).
- **Encryption risk vs. severity overlap — resolved by issue-class, not scanner-rule instance (revised after review R2, #10).** The overlap rule is keyed on **issue-class**, so two identical unencrypted resources score the same regardless of which scanner/rule triggered. Contextual encryption risk amplifies only when the issue-class carries information independent of the triggering severity; tested with duplicate-provenance cases (same resource flagged by >1 scanner).

### Q10 — Threshold & weight methodology: **fix a priori + freeze + sensitivity as analysis**
- **Bands are defined by remediation semantics first (revised after review, #15):** name the *action* each band implies (Critical = block deploy / remediate now; High = fix before prod / needs approval; Medium = backlog; Low = monitor), then map score intervals onto those actions — the score range does not, by itself, justify the cut points.
- Derive the **equal weights** from the score structure by **documented reasoning**, *before* running on test cases; commit to the shared config as **the** model.
- **Equal weighting is stated as a deliberate neutral baseline (revised after review, #14)** — not a claim that criticality == IAM admin == exposure — and the **sensitivity analysis explicitly tests plausible expert-derived alternative weightings**, not just threshold moves.
- **Freeze** weights and thresholds for the primary evaluation — no tuning-to-fit.
- Then, as a **reported experiment**, show how the priority distribution shifts as thresholds/weights move: a **sensitivity analysis**, not a search for winning values.
- **Defends against the circularity/overfitting critique.** Viva line: *"I did not tune to fit the data; I fixed the model a priori and then analyzed its sensitivity."*
- Reframes (does not delete) the proposal's "adjusted based on observed behavior" wording: adjustment = documented sensitivity analysis, not fitting.

### Scanner selection (clarified after review, #19)
Checkov / tfsec / Trivy are all retained (the proposal specifies them), but **tfsec is framed as legacy/comparative** (its rule families increasingly overlap Trivy's). The dissertation justifies the selection and **accounts for rule-family overlap** so the novelty claim rests on the prioritization layer, not on scanner count.

---

## Cross-cutting load-bearing artifact

**The normalized issue-class taxonomy** is reused across four subsystems and must stay internally consistent:
- Q4 — context join,
- Q5 — rubric mapping,
- Q6 — test-case design,
- Q8 — dedupe key.
A change to the taxonomy ripples through all four — treat it as a single source of truth.

**Specified before implementation (added after review, #7):** the initial issue-class list, the **scanner-rule-ID → issue-class mapping table**, and the `unmapped:<scanner>:<rule_id>` fallback behavior are authored as a version-controlled artifact *before* coding, since every downstream subsystem depends on them. Taxonomy scope is bounded to the tested categories (storage/networking/IAM/compute/containers).

---

## Key decisions & tradeoffs (summary)

| Decision | Chosen | Trade-off accepted |
|---|---|---|
| Artifact form | B+ hybrid | Full automation, but headline results rest on declared context, not heuristics |
| Integration | Subprocess + JSON parse | Simple, tool-agnostic; depends on stable scanner output schemas |
| Context join key | Per-platform canonical identity | Deterministic; needs TF module/instance + K8s namespace discipline |
| Rubric | Source-anchored deterministic config | More upfront rubric work; buys defensibility |
| Model | Equal-weighted additive (neutral baseline) | Explainable; weights + thresholds are sensitivity dimensions, not tuned params |
| Dedup | `(resource, issue-class, fingerprint)` | Honest alert-reduction metric; needs a maintained taxonomy |
| Extraction | Hybrid, literals-only, fidelity reported | No full IaC graph resolution; unresolved values reported per-factor, not hidden |

---

## Risks / open questions

- Scanner output-schema drift between pinned versions (mitigated by version pinning + parser tests).
- Small N (~20–30) limits statistical claims — evaluation is **controlled artifact validation**, not significance testing; the write-up must state this bound rather than overclaim.
- Sensitivity-analysis presentation (Q10) must be clearly separated from the frozen primary model in the write-up, or it reads as tuning anyway.
- **Cross-resource exposure (from R1 #11 / R2 #6):** the supported/unsupported pattern list is now **closed** (see Q9); remaining risk is only the **implementation effort** of the bounded lookups for that closed list and keeping the corpus within it.
- **Pre-implementation artifacts now on the critical path (from #7/#20):** the issue-class taxonomy + rule mapping table, and the evaluation ground-truth schema, must be authored before their dependent code.

## Pre-implementation deliverables (ordered, each with an acceptance gate)

These must exist before the code that depends on them. Each has an **acceptance criterion (revised after review R2, #12)** so a weak artifact can't silently pass:
1. **Issue-class taxonomy + scanner-rule-ID mapping table** (+ `unmapped:` fallback) — blocks context join, rubric, dedupe, test design. *Gate:* every rule ID emitted by the pinned scanner versions across the corpus maps to an issue-class or an explicit `unmapped:` entry (measured mapping completeness); taxonomy covers all five tested categories.
2. **Per-factor scoring rubric config** (source-anchored) — blocks scoring. *Gate:* every score point cites a source (CVSS/NIST/NSA-CISA/OWASP); no factor has an unjustified level; **the rubric includes an explicit `unresolved`-handling policy per factor (revised after review R4, #3)** — declaring, for each factor, whether unresolved is conservatively scored, excluded from prioritization-quality claims, or sensitivity-analysed.
3. **Scanner severity-normalization table** — blocks the baseline transform. *Gate:* each scanner's native severity levels have an explicit mapping to the common 1–5 scale, with a one-line justification each.
4. **Evaluation ground-truth schema** — blocks the evaluation harness. *Gate:* schema validates on all corpus cases; harness rejects a case with missing/ill-formed expected outputs rather than skipping it.
5. **Canonical-identity spec** (TF + K8s) — blocks context join and dedupe. *Gate:* identity is defined for every resource/instance shape present in the corpus (module, `for_each`/`count`, namespace/kind).

---

## Out of scope (guardrails)

Runtime intrusion detection, malware analysis, full cloud-provider monitoring, complete enterprise CSPM, multi-cloud production repos, **ML-based scoring**. Named as future work; do not let feature work drift here.
