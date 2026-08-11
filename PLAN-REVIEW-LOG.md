# PLAN-REVIEW-LOG.md — Act 2 Codex Adversarial Review

**Plan under review:** `docs/PLAN.md` (Q1–Q10 locked)
**MAX_ROUNDS=5**
**Reviewer model:** Codex (cross-model adversarial review, read-only)

---

## Round log

_(rounds recorded below as they run)_

## Round 1 — Codex (thread 019fa81f-230b-7e72-97e7-0513f357fffc) — VERDICT: REVISE

Model: gpt-5.5 (Codex CLI 0.142.5), read-only. 20 material issues:

1. "Six contextual factors" (PLAN) vs "five non-severity attributes" (CONTEXT) vs six *scoring* factors incl. severity — inconsistent. Fix: say "five contextual attributes + scanner severity = six scoring factors."
2. "Detection coverage" listed as a metric though detection is delegated to scanners — examiner will attack. Fix: rename to normalization/retention coverage or drop from primary eval.
3. "Prioritization usefulness" undefined/subjective. Fix: define an oracle (expert-labeled order, scenario-expected ordering, or contrastive pass/fail).
4. ~20–30 cases too small for broad claims across TF/K8s × 3 scanners × 5 domains. Fix: frame as controlled artifact validation, not generalizable proof; add per-category counts.
5. "Apples-to-apples baseline" false — raw severity not equivalent across Checkov/tfsec/Trivy. Fix: define a scanner-specific severity-normalization table, justified.
6. Dedupe key `(resource, issue-class)` collapses materially different findings (separate IAM actions, SG rules, K8s container fields). Fix: add a violation fingerprint (affected attribute/path) to the key.
7. Taxonomy called load-bearing but unspecified. Fix: define initial issue-classes, rule-ID mappings, unmapped behavior before implementation.
8. "Unmapped rules pass through counted once" conflicts with dedupe/scoring absent a rubric. Fix: assign `unmapped:<scanner>:<rule_id>`, severity-only/default-context scoring, documented.
9. Join key `type.name + file path` brittle for TF modules/for_each/count/moved blocks/duplicate locals and K8s namespace/name/kind. Fix: define canonical identity per platform.
10. Literals-only creates systematic defaults for common var/local/module patterns. Fix: report unresolved-rate per factor; exclude/separately analyze high-unresolved cases.
11. Public exposure often not inferable from the flagged resource alone (SG + route table + LB + subnet + K8s Service/Ingress jointly determine it). Fix: bounded cross-resource lookups or explicitly downgrade the claim.
12. IAM privilege scope can't be a simple per-resource literal read (indirect attach, wildcards+conditions, managed policies/bindings). Fix: define supported IAM constructs; unsupported = unresolved, not low.
13. Encryption risk overlaps scanner severity (many rules already encode "unencrypted"); additive model may double-count. Fix: document overlap handling / justify intentional amplification.
14. Equal weighting explainable but not self-justifying (why criticality == IAM admin == exposure?). Fix: justify as neutral baseline + sensitivity vs expert-derived alternatives.
15. Thresholds from 1–28 range arbitrary unless tied to action semantics. Fix: define bands by remediation decisions first, then map score intervals to them.
16. Contrastive pairs prove the formula reacts to factors, not that prioritization is valid in realistic cases. Fix: separate "mechanism tests" from "realistic scenario evaluation."
17. Alert reduction gameable by dedup rather than better prioritization. Fix: report dedup reduction separately from priority-band reduction.
18. Doc drift: CLAUDE.md says thresholds "tunable during evaluation" vs PLAN's frozen-a-priori. Fix: update CLAUDE.md.
19. tfsec effectively superseded by Trivy — using both may duplicate rule families and muddy novelty. Fix: justify selection or treat tfsec as legacy/comparative.
20. No explicit ground-truth artifact format (expected outputs, expert labels, contrastive expectations). Fix: define an evaluation schema before coding the harness.

Summary: "directionally implementable, not yet viva-safe. Biggest gaps: evaluation validity, canonical identity/deduplication, unresolved IaC semantics, taxonomy/rubric specification."

### Claude's response — accepted 19/20, contextualized 1

Codex's review is high quality and grounded; I accept nearly all of it. Revisions applied to `docs/PLAN.md`:

- **#1** — Fixed terminology throughout: "five contextual attributes + scanner severity = six scoring factors."
- **#2, #3, #16, #17, #20** — Reworked the evaluation section: renamed "detection coverage" → **normalization/retention coverage**; defined a **prioritization oracle** (contrastive pass/fail + scenario-expected ordering); split **mechanism tests vs realistic-scenario evaluation**; separated **dedup reduction from priority-band reduction** in alert-reduction reporting; committed to an **evaluation ground-truth schema** as a pre-harness deliverable.
- **#4** — Reframed evaluation as **controlled artifact validation, not generalizable empirical proof**; added per-category coverage counts.
- **#5** — Added a **scanner-specific severity-normalization table** as the documented baseline transform (upgrades Q7's vague "documented transform").
- **#6, #9** — Extended dedupe key to `(canonical resource, normalized issue-class, violation fingerprint)`; defined **canonical identity separately for Terraform and Kubernetes**.
- **#7, #8** — Committed to specifying the **initial taxonomy + rule-ID mappings + `unmapped:<scanner>:<rule_id>` handling** before implementation.
- **#10, #11, #12, #13** — Added an **extraction-fidelity** subsection: per-factor unresolved-rate reporting; **downgraded exposure/IAM claims** to what a bounded per-resource read supports, with unsupported cases marked unresolved (not low-risk); documented **encryption/severity overlap** handling.
- **#14, #15** — Strengthened Q10: **remediation-semantics-first band definitions**, equal weights as an explicitly-justified neutral baseline tested by sensitivity analysis.
- **#18** — Fixing CLAUDE.md threshold-wording drift.
- **#19 (contextualized, not fully accepted)** — tfsec stays (the proposal names it), but reframed as **legacy/comparative** input with a justification sentence and rule-family-overlap accounting; I won't drop a proposal-specified scanner.

## Round 2 — Codex (same thread) — VERDICT: REVISE

12 remaining issues. Notably caught **doc-drift I only half-propagated in Round 1** (CLAUDE.md still had "detection coverage" + old alert-reduction wording; CONTEXT.md still had the 2-tuple dedupe key + "tunable/coupled" thresholds):

1. CLAUDE.md still lists "detection coverage." → Fix CLAUDE.md.
2. CLAUDE.md alert-reduction not split. → Mirror the split.
3. CONTEXT.md dedupe key missing violation fingerprint. → Update glossary.
4. CONTEXT.md thresholds still "tunable and coupled." → Fix to a-priori/sensitivity-only.
5. PLAN pipeline says attrs "from the flagged resource" but later needs cross-resource. → Reword to "flagged + bounded related resources where supported."
6. Exposure decision still deferred (either/or) — too late-stage for a locked arch; affects corpus/rubric/expected outputs. → **Choose supported exposure patterns now.**
7. Oracle "scenario-expected ordering" lacks independence — same author rubric+labels = circular. → Pre-register rationales / independent label review.
8. "Ranking consistency" conflates auto-inference agreement (heuristic quality) with threshold/weight sensitivity (model robustness). → Split into two measures.
9. Severity-only scoring of unmapped rules may depress serious unmapped findings. → Report unmapped separately, exclude from prioritization-quality claims.
10. Encryption-overlap suppression keyed on scanner-rule instance makes identical resources score differently by trigger. → Key overlap on issue-class; test duplicate-provenance cases.
11. "Fully automated" rhetorically risky since headline eval needs declared context. → "Automated pipeline with required declared-context input for primary mode."
12. Pre-implementation deliverables lack acceptance criteria — weak taxonomy/rubric could pass. → Add review gates.

### Claude's response — accepted all 12

- **#1, #2** — Fixed CLAUDE.md evaluation-metrics line: renamed to normalization/retention coverage, defined oracle, split alert reduction, split ranking consistency, normalized baseline.
- **#3, #4** — Fixed CONTEXT.md: dedupe key now the 3-tuple with fingerprint (+ new **Violation fingerprint** glossary term); priority-category thresholds now a-priori/frozen/sensitivity-only, semantics-first.
- **#5** — Pipeline layer-3 wording now "flagged resource and bounded related resources where explicitly supported."
- **#6** — **Committed a closed list of supported exposure patterns** (SG/NSG `0.0.0.0/0`, public-IP/`publicly_accessible`, public bucket access, K8s LoadBalancer/NodePort/Ingress) and an explicit **unsupported** list (multi-hop route/subnet/IGW, peering/TGW, DNS) → unresolved, fixed before corpus finalization.
- **#7** — Oracle independence: scenario rationales **pre-registered before scoring outputs**, labels get **independent supervisor review**.
- **#8** — Split ranking consistency into **auto-inference agreement** and **model sensitivity**.
- **#9** — `unmapped:*` findings **reported separately and excluded from prioritization-quality claims**.
- **#10** — Encryption/severity overlap keyed on **issue-class, not scanner-rule instance**; test with duplicate-provenance cases.
- **#11** — Goal rephrased to "automated pipeline with required declared-context input for primary mode."
- **#12** — Added an **acceptance gate to each pre-implementation deliverable** (mapping completeness, source coverage, schema validation, identity coverage).

## Round 3 — Codex (same thread) — VERDICT: REVISE

10 issues, narrowing to correctness detail:

1. Stale risk text says exposure must be decided before corpus finalization, but list is now closed. → Rewrite as implementation risk only.
2. CLAUDE.md still says non-declared factors parsed from flagged resource; plan now allows bounded related-resource lookups. → Mirror wording.
3. "Fail loudly if a scanner missing" ignores platform applicability (tfsec=TF-only; K8s=Checkov/Trivy). → Platform-scanner matrix; fail only for the input's required scanners.
4. Severity normalization assumes every finding has usable native severity; some don't. → Explicit missing/unknown-severity handling + rate.
5. "Unresolved → documented default" still dangerous for exposure/IAM — numeric default distorts rankings. → Represent unresolved as explicit state; conservative-score / exclude / sensitivity-analyse.
6. Q8 severity-only unmapped vs Q7 excluded — semantics need to be explicit. → Label unmapped "baseline-only informational."
7. Closed exposure list says SG `0.0.0.0/0` "attached to flagged resource," but scanner findings often land on the SG rule itself, not the target. → Define attribution (rule vs target vs both) + dedupe/fingerprint handling.
8. Public bucket access may come from separate ACL/policy/ownership/public-access-block. → Enumerate supported bucket combinations; partial → unresolved.
9. Oracle has supervisor review but no inter-rater disagreement handling. → Record disagreements; resolve or report as oracle uncertainty.
10. Status line still says "Round 1 revisions." → Update revision metadata.

### Claude's response — accepted all 10

- **#1, #10** — Rewrote stale exposure risk as implementation-effort only; status line now "revised through Codex Round 3."
- **#2** — CLAUDE.md context-extraction line now mentions bounded related-resource lookups + explicit unresolved state (not silent low default).
- **#3** — Added **platform-scanner matrix** to Q3 (tfsec TF-only; K8s = Checkov+Trivy); fail-loud scoped to the input's required scanners.
- **#4** — Q3 now handles **missing/unknown native severity** as an explicit state + reported rate.
- **#5** — Q9 literals-only rule now represents **unresolved as a first-class explicit state**; exposure/IAM handled by conservative-score / exclude / bounded sensitivity, not numeric default.
- **#6** — Q8 unmapped findings now labelled **"baseline-only informational,"** consistent with Q7 exclusion.
- **#7** — Added **exposure attribution rule** (attributed to target resource; open-ingress rule resolved via lookup; fingerprint records originally-flagged resource so dedupe doesn't mismerge).
- **#8** — Enumerated **supported bucket-publicness combinations**; partial/out-of-set → unresolved.
- **#9** — Oracle now **records reviewer disagreements**, resolved before scoring or reported as oracle uncertainty.

## Round 4 — Codex (same thread) — VERDICT: APPROVED

Codex: *"No viva-fatal blockers remain. The plan is now scoped honestly enough to implement: it separates detection from prioritization, defines the oracle, bounds exposure/IAM claims, handles scanner/platform applicability, preserves unresolved states, and has pre-implementation gates… The methodology is now bounded, auditable, and defensible enough for implementation."*

Four remaining items explicitly flagged as **implementation hygiene, not architecture blockers**:
1. CONTEXT.md unmapped entry doesn't say "excluded from prioritization-quality claims." → added.
2. Q4 declared-context fallback default should not blur into `unresolved` semantics. → Q4 now states the default applies only to missing declared Sensitivity/Criticality; extractor failures use `unresolved`; separate rates.
3. Q9's per-factor unresolved handling should become a spec artifact. → added "unresolved-handling policy per factor" to the scoring-rubric acceptance gate.
4. Status metadata said R1–R3. → updated to R4 + APPROVED.

### Claude's response — all four folded in before freezing

All four accepted and applied (they are cheap and improve auditability). No item was rejected.

---

## Outcome — CONVERGED

**APPROVED at Round 4 of 5.** The plan survived four rounds of cross-model adversarial review (Codex gpt-5.5, read-only throughout). The argument improved the plan most in: (1) **evaluation validity** — killed the circularity risk via a pre-registered, independently-reviewed oracle and a-priori frozen thresholds; (2) **honest scoping** — unresolved as a first-class state, a closed exposure-pattern list with explicit attribution, platform-scanner applicability; (3) **schema integrity** — violation-fingerprint dedupe key, per-platform canonical identity, and acceptance-gated pre-implementation artifacts. Total: 46 distinct issues raised across R1–R4, 45 accepted, 1 contextualized (tfsec retained as legacy/comparative).

