# Project Brief — A Framework for Risk-Aware Security Misconfiguration Detection and Prioritization in Cloud IaC Environments

**Author:** Jayathissa E.A.T.N. (258243J)
**Programme:** MSc in Computer Science (Cloud Computing), University of Moratuwa
**Document date:** 3 August 2026
**Purpose:** Supervisor review of the locked design, prior to implementation

---

## 1. Executive summary

Rule-based Infrastructure-as-Code (IaC) scanners — Checkov, tfsec, Trivy — reliably *detect* misconfigurations but report them as a flat list of severity labels with no awareness of where the resource sits, what it holds, or who can reach it. The result is alert overload and remediation in the wrong order.

This project builds a **prioritization layer that sits on top of those scanners**. It does not re-implement detection. It enriches each scanner finding with cloud context and computes a transparent, weighted-additive **risk score over six factors**, producing a ranked remediation list in four priority bands (Critical / High / Medium / Low).

The design is now **locked and externally reviewed**. It was subjected to four rounds of adversarial cross-model review (a second AI model, read-only, tasked with attacking the methodology), which raised 46 distinct issues; 45 were accepted and applied, one was contextualised and retained with justification. The review concluded with approval and no viva-fatal blockers.

**Implementation has not started.** The immediate next phase is five specification artifacts, each with an acceptance gate, followed by the pipeline itself and then the evaluation harness.

---

## 2. Problem and motivation

Cloud misconfiguration remains a leading cause of data exposure, and IaC shifts that risk earlier — a single flawed Terraform module can be replicated across an estate before deployment. Existing scanners address *detection* well.

The gap is **prioritization**:

- Findings arrive with a flat severity, so a publicly-exposed production database holding customer data is presented alongside a cosmetic tagging violation in a sandbox.
- Severity labels are **not comparable across tools** — Checkov, tfsec and Trivy assign them by different conventions.
- The same underlying problem is often reported multiple times by multiple scanners, inflating the apparent alert count.
- Context that determines real business risk — internet reachability, IAM blast radius, data sensitivity, environment criticality, encryption state — is either absent from the finding or not reliably derivable from the code alone.

Practitioners therefore triage manually, which does not scale and is inconsistent between engineers.

---

## 3. Proposed framework — a five-layer pipeline

| # | Layer | Responsibility |
|---|---|---|
| 1 | **IaC Input** | Accept Terraform (HCL) and Kubernetes YAML manifests. |
| 2 | **Security Scanning** | Invoke Checkov, tfsec and Trivy as subprocesses (pinned versions); parse each tool's JSON into a single **normalized finding record**. |
| 3 | **Context Extraction** | Attach the five contextual attributes to each finding — two supplied via a declared-context input, three parsed from the flagged resource and a bounded, closed set of related resources. |
| 4 | **Risk Scoring** | Apply the explainable weighted-additive model (Section 4). Not machine learning. |
| 5 | **Reporting** | Rank findings, map scores to priority bands, emit machine-readable JSON plus a human-readable report. |

A **separate evaluation harness** consumes the JSON output and computes the evaluation metrics. Keeping it independent of the tool prevents the framework from grading its own output.

---

## 4. Risk scoring model

**Terminology:** there are **five contextual attributes** which, together with scanner severity, make **six scoring factors**.

```
Risk Score = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk
```

| Factor | Range | Meaning | Source |
|---|---|---|---|
| Scanner severity | 1–5 | Baseline severity from the scanner, normalized across tools | Scanner output |
| Public exposure | 0–5 | Reachable from the public internet? | Parsed from code |
| IAM privilege scope | 0–5 | Degree of sensitive/administrative permission | Parsed from code |
| Resource sensitivity | 0–5 | Business/data sensitivity of the affected asset | **Declared** |
| Environment criticality | 0–5 | Production vs staging vs development | **Declared** |
| Encryption risk | 0–3 | Required encryption/data protection missing? | Parsed from code |

Maximum possible score 28, minimum 1.

| Priority | Score | Remediation action |
|---|---|---|
| **Critical** | ≥ 22 | Block deployment, remediate immediately |
| **High** | 16–21 | Fix before production / require approval |
| **Medium** | 9–15 | Schedule in normal sprint or backlog |
| **Low** | < 9 | Monitor, document, fix when convenient |

Two properties are deliberate and defensible:

- **Explainability.** Every factor and weight is inspectable and adjustable. Each finding's score decomposes into named contributions, so a reviewer can see *why* something ranked where it did. Learning-based scoring is explicitly future work.
- **No tuning to fit.** Bands are defined by *remediation semantics first* (what action does this band imply?), then mapped onto score intervals. Weights and thresholds are fixed a priori from the score structure and **frozen before evaluation**. Threshold and weight movement is then reported as a **sensitivity analysis**, not as a fitting step. This removes the circularity critique — the model is not tuned on the data used to evaluate it.

### Two factors need a declared source — and why that is honest

Resource sensitivity and environment criticality are **not reliably recoverable from IaC code**. A bucket named `data-prod-01` may or may not hold regulated data. Rather than inferring them and silently absorbing the error into the headline result, they enter via an explicit declared-context input on the primary evaluation path. A convention-based **auto-inference mode** (from tags and naming conventions) is also built and evaluated as a **second mode**, so the tool runs end-to-end automatically — but the headline claim never rests on heuristics.

---

## 5. Key design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Artifact form | Automated Python pipeline with a required declared-context input for its primary mode | Full automation without resting headline results on noisy inference |
| Scanner integration | Subprocess invocation, JSON parsed into one normalized record; versions pinned | Tool-agnostic and reproducible |
| Scanner selection | Checkov + Trivy primary; **tfsec framed as legacy/comparative** | tfsec's rule families increasingly overlap Trivy's; novelty must rest on the prioritization layer, not scanner count |
| Context join key | **Per-platform canonical identity** (Terraform: module path + type + name + instance key; Kubernetes: apiVersion/kind + namespace + name) | `type.name + file path` breaks on modules, `for_each`/`count`, and namespaces |
| Scoring rubric | Fine-grained, deterministic, **source-anchored** rubrics (CVSS, NIST SP 800-30, NSA-CISA, OWASP) in a shared config, mirrored in the dissertation | Every score point is justifiable rather than arbitrary |
| Deduplication | One logical finding per `(canonical resource, issue-class, violation fingerprint)` | Without the fingerprint, materially different violations on one resource collapse into a single finding |
| Extraction fidelity | Literals only; unresolved values are an **explicit first-class state**, never a silent numeric default | A default of "low" on an unresolved exposure or IAM value would falsely reassure |
| Weighting | Equal weights as a **deliberate neutral baseline**, tested against expert-derived alternatives in sensitivity analysis | Equal weighting is a defensible starting point, not a claim that all factors are equally important |

### Cross-cutting artifact

A **normalized issue-class taxonomy** — the framework's own vocabulary of misconfiguration types, independent of any scanner's rule IDs — is load-bearing across four subsystems: context join, scoring rubric, test-case design, and the dedupe key. It is authored and version-controlled before implementation, since everything downstream depends on it.

---

## 6. Evaluation methodology

**Framing.** The evaluation is **controlled artifact validation, not generalizable empirical proof**. With ~20–30 cases across two platforms, three scanners and five resource domains, the corpus cannot support broad statistical claims, and the write-up states this bound explicitly rather than overclaiming.

**Baseline.** Raw scanner severity mapped into the same four bands via a **documented, version-controlled severity-normalization table** (each scanner's native levels → a common 1–5 scale). Because native severities are not equivalent across tools, this table is what makes baseline-versus-framework a fair comparison.

**Oracle (how "better prioritization" is judged without circularity).**

- **Contrastive pairs** — configurations differing in exactly one contextual factor, establishing that a factor *causes* the rank change. These are **mechanism tests**.
- **Scenario-expected orderings** — hand-labelled expected orderings per domain, testing usefulness on realistic whole configurations.
- **Independence controls:** scenario rationales are **pre-registered before any scoring output is generated**, and expected-ordering labels receive **independent supervisor review**. Reviewer disagreements are recorded and either resolved before scoring or reported as oracle uncertainty. The rubric author does not silently set the labels.

**Metrics.**

| Metric | What it measures |
|---|---|
| Normalization / retention coverage | Fraction of scanner findings correctly normalized and carried through. *Not* detection accuracy — that is delegated to the scanners. |
| Prioritization usefulness | Contrastive-pair pass/fail plus scenario-expected ordering, against the pre-registered oracle. |
| Alert reduction | **Two separate numbers, never combined:** reduction from deduplication, and reduction in Critical/High band count from prioritization. |
| Ranking consistency | **Two separate measures:** auto-inference agreement (heuristic quality) and model sensitivity under threshold/weight perturbation (robustness). |
| Baseline comparison | Rank-change table versus the normalized baseline, each change justified by named contextual factors. |

**Corpus.** Open-source deliberately-insecure repositories (TerraGoat, KubeGoat — cited) plus hand-crafted contrastive pairs, spanning storage, networking, IAM, compute and container workloads, with per-category coverage counts reported. Version-controlled alongside expected outputs.

---

## 7. Design assurance — adversarial review

Before locking, the design was put through a structured cross-model adversarial review: the plan was authored by one model and attacked, read-only, by a second (OpenAI Codex, gpt-5.5) instructed to find methodological flaws rather than agree. Every issue and its resolution is recorded in `PLAN-REVIEW-LOG.md`.

| Round | Issues raised | Verdict |
|---|---|---|
| 1 | 20 | Revise |
| 2 | 12 | Revise |
| 3 | 10 | Revise |
| 4 | 4 (implementation hygiene) | **Approved** |

**Totals:** 46 issues raised, 45 accepted and applied, 1 contextualised (retaining tfsec, which the proposal specifies, reframed as legacy/comparative).

The review improved the design most in three areas:

1. **Evaluation validity** — the circularity risk was eliminated via the pre-registered, independently-reviewed oracle and a-priori frozen thresholds.
2. **Honest scoping** — unresolved values became a first-class state; the public-exposure analysis was reduced to a *closed, committed list* of supported patterns with explicit attribution rules, and everything outside it is marked unresolved rather than assumed safe.
3. **Schema integrity** — the violation-fingerprint dedupe key, per-platform canonical identity, and acceptance-gated pre-implementation artifacts.

Reviewer's closing assessment: *"No viva-fatal blockers remain… the methodology is now bounded, auditable, and defensible enough for implementation."*

---

## 8. Current status and next steps

**Status:** design locked and externally reviewed. No implementation code has been written yet — this is deliberate; the artifacts below are on the critical path because every downstream component depends on them.

**Phase 1 — pre-implementation specifications (each with an acceptance gate):**

1. **Issue-class taxonomy + scanner-rule-ID mapping table.** *Gate:* every rule ID emitted by the pinned scanners across the corpus maps to an issue-class or an explicit `unmapped:` entry; all five categories covered.
2. **Per-factor scoring rubric config.** *Gate:* every score point cites a source; each factor declares its unresolved-handling policy.
3. **Scanner severity-normalization table.** *Gate:* every native severity level mapped to the common 1–5 scale with a one-line justification.
4. **Evaluation ground-truth schema.** *Gate:* validates on all corpus cases; the harness rejects ill-formed expected outputs rather than skipping them.
5. **Canonical-identity specification (Terraform + Kubernetes).** *Gate:* defined for every resource shape in the corpus (module, `for_each`/`count`, namespace/kind).

**Phase 2 — implementation:** the five-layer pipeline in Python.

**Phase 3 — evaluation:** build the independent harness, run the corpus, report the five metrics plus the sensitivity analysis.

**Phase 4 — write-up.**

---

## 9. Feedback sought

1. **Declared context as the primary path.** Is the declared-context seam — with auto-inference evaluated as a documented second mode — acceptable as the primary evaluation path for an MSc artifact, or would you prefer inference to carry the headline result?
2. **Oracle rigour.** Is the pre-registered, independently-reviewed oracle sufficient given the corpus size, and are you willing to act as the independent reviewer for the expected-ordering labels?
3. **Scope of the exposure analysis.** The supported public-exposure patterns are a deliberately closed list; multi-hop route/subnet reachability and DNS-based exposure are explicitly out of scope and marked unresolved. Is that boundary defensible for the dissertation?
4. **Sequencing.** Does the five-artifact Phase 1 look correctly prioritised, or should implementation begin in parallel with any of them?

---

## Appendix A — Supporting documents

| File | Contents |
|---|---|
| `docs/PLAN.md` | The full locked architecture plan (all design decisions, with post-review revisions annotated) |
| `PLAN-REVIEW-LOG.md` | Complete adversarial review transcript — every issue raised, accepted or rejected, with reasoning |
| `CONTEXT.md` | Glossary of project terminology |
| `CLAUDE.md` | Project guidance and scope guardrails |
| `docs/research-overview.html` | Single-page visual overview of the framework (open in any browser) |

---

## Appendix B — Scope guardrails

**In scope:** pre-deployment static analysis of IaC; Terraform and Kubernetes primary.

**Out of scope (named as future work):** runtime intrusion detection, malware analysis, full cloud-provider monitoring, a complete enterprise CSPM platform, multi-cloud production repositories, and machine-learning-based scoring.
