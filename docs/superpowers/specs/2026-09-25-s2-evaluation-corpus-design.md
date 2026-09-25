# S2 — Evaluation corpus v1 and its ground truth (design)

**Status:** awaiting review
**Author:** Jayathissa E.A.T.N. (258243J)
**Date:** 2026-09-25
**Scope:** Sub-project S2 — corpus v1 (contrastive pairs + scenarios) and the ground-truth document they are recorded in. No scoring, no harness.
**Spec authority:** `docs/PLAN.md` — Q4 (declared context), Q7 (metrics), Q9 (unresolved discipline), Q10 (sensitivity analysis).
**Upstream input:** S1's committed `eval/ground_truth.schema.json` and `eval/ground_truth.py`; S3a's normalized finding set and the golden fixtures in `tests/harvest/fixtures/`.
**Roadmap position:** `docs/superpowers/specs/2026-08-24-implementation-phase0-design.md` — "S2 | Corpus v1 — contrastive pairs + scenarios | depends on S1". S5 depends on S2 and S4.

---

## 0. Purpose, and why S2 comes before S4

S2 authors the data the framework is evaluated *against*. S1 built the schema and its validator; a corpus of real cases does not exist yet, so every evaluation claim in the dissertation currently rests on nothing.

**S2 must precede S4.** Once a scoring engine exists and has been run, expected orderings can no longer be authored independently — the author has seen the output. This is the same discipline the project already applies to thresholds ("frozen before evaluation, never tuned to fit the test data"), and S1's freeze is what makes the ordering possible: the rubric is fixed, so a case's expected ranking can be derived from the rubric without a single score being computed. Building S3b and S4 first would forfeit that independence with no way to recover it afterwards.

### 0.1 Global constraints (bind every part of S2)

- **Relative claims are primary.** S1 already decided this: `expected_band`'s own schema description reads *"Secondary and optional. Ordering is the primary signal."* S2 confirms rather than introduces it. Pairs and scenario orderings carry the prioritization-quality claim because both are threshold-independent, and PLAN Q10 commits to moving thresholds in a sensitivity analysis.
- **`defaulted_factors` and `unresolved_factors` are never merged.** PLAN Q4's missing-declared-value and PLAN Q9's extractor-failure are reported as separate rates. Merging them makes that report impossible after the fact.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a defect — including in this document. Every measured fact below carries its source.
- **Corpus v0's fixtures are the experimental control.** `tests/harvest/fixtures/`'s five golden documents are never re-captured or rewritten by S2.
- **The taxonomy and rubric are fixed inputs.** S2 joins against them; it does not extend, reclassify or re-weight.

---

## 1. Measured facts S2 is designed around

Measured from `tests/harvest/fixtures/` through S3a's committed adapters on this host. Corpus observations, not scanner contracts.

**Pair-formability of corpus v0.** A contrastive pair isolates one *factor*, not one issue class, so several differing classes are acceptable where they all feed the same factor.

| Factor | Can v0 form a controlled pair? | Evidence |
|---|---|---|
| sensitivity | **Yes, with no new code** | declared-context variation on one resource |
| criticality | **Yes, with no new code** | declared-context variation on one resource |
| exposure | Yes | `aws_security_group.default` carries `networking-config-hygiene` only; `aws_security_group.web-node` adds `networking-ingress-exposure` *and* `networking-egress-exposure` — both feed exposure |
| encryption | Yes | `aws_instance.db_app` carries `storage-encryption-at-rest`; `aws_instance.web_host` does not |
| **severity** | **No** | see below — presence of all four levels is not a controlled pair |
| **privilege** | **No** | every genuine IAM policy type is single-instance: `aws_iam_policy_document` 1, `aws_iam_role_policy` 1, `aws_iam_user` 1, `aws_iam_user_policy` 1 |

**Why severity cannot be paired from v0, corrected from an earlier draft of this table.** That draft reasoned "all four levels are present (CRITICAL 15, HIGH 133, MEDIUM 47, LOW 39), therefore a severity pair exists." Presence is not isolation. Measured: **zero** resource pairs share an identical issue-class set while differing in maximum severity, because severity is determined by which rule fires and which rule fires also determines the class — the two co-vary. Five classes *do* show intra-class severity variance (`iam-authentication-controls` 2–3, `networking-ingress-exposure` 4–5, `storage-key-management-cmk` 2–4, `storage-logging-audit` 2–3, `storage-public-accessibility` 4–5), but in every case the two resources are of **different types** and therefore differ in other classes too. So severity joins privilege as hand-crafted (§4).

**Candidate supply, measured.** Over corpus v0: **249** same-type combinations considered, **129** with an empty class difference, **120** usable candidates. Grouped by the class family their difference touches: containers+networking 82, containers 21, storage 9, networking 7, iam 1. The clean single-family supply is comfortable where it exists — exposure has `aws_security_group.default` vs `web-node` (ingress + egress) and `aws_security_group_rule.egress` vs `ingress`; encryption has **four** clean pairs against `aws_s3_bucket.logs` (`data`, `financials`, `flowbucket`, `operations`), each differing only in `storage-encryption-at-rest` + `storage-key-management-cmk`. The single `iam`-family candidate is `aws_instance.db_app` vs `web_host`, which mixes `iam-authentication-controls` with `iam-hardcoded-secrets` and is privilege material in neither case.

Seven Terraform resource *types* have more than one instance (`aws_rds_cluster` 9, `aws_s3_bucket` 6, `aws_subnet` 4, then `aws_security_group`, `aws_security_group_rule`, `aws_instance`, `aws_vpc` at 2 each); of those, **5 have instances whose issue-class sets genuinely differ**. 28 distinct issue classes appear across the corpus, and 39 distinct Kubernetes identities.

**The privilege trap.** Nine `aws_rds_cluster` instances carry `iam-authentication-controls`, which makes them look like privilege-pair material. They are not: that class is authentication configuration, not privilege *scope*. A pair built from them would validate, read plausibly, and test the wrong thing. Privilege therefore requires hand-crafted code — this is the single reason S2 authors any IaC at all.

**What S1's validator already enforces**, so S2 neither re-implements nor claims credit for it (`eval/ground_truth.py::_check_semantics`): unique `case_id`/`pair_id`/`scenario_id`; both pair sides resolving to known cases; `case_high != case_low`; every scenario tier entry resolving to a known case; and — decisively — **`oracle.author != oracle.reviewer`**, rejected with *"the oracle would be reviewing itself"*. An independent reviewer is a load-time requirement, not a preference.

**No class-to-factor mapping exists, and S2 does not create one.** `taxonomy.json`'s class records carry `id`, `category`, `title` and `definition` — no factor. `rubric.json` carries the six factors with no per-class relation. So which factor a given issue class bears on is nowhere in the data, and §3 is designed around that rather than around wishing it were there. Authoring such a table in S2 would be worse than the gap: it is a *scoring* decision, and a table the evaluator writes and the scorer later consumes couples the grader to the graded — the exact coupling `test_eval_does_not_import_the_framework` exists to prevent.

**`eval/` may not import `iacrisk` at all.** `tests/test_architecture.py::test_eval_does_not_import_the_framework` guards the whole package, deliberately: its docstring records that the ground-truth schema *duplicates* the class-id pattern and the factor-key enum as literal values rather than importing them, and that "a guard that permits the import the duplication exists to avoid is not guarding anything." Anything needing the adapters therefore cannot live in `eval/` (§3).

**Schema shapes that constrain authoring**, read from the committed schema:

- `case.source` is either `{repo, commit, path}` with a 7–40 hex commit, or the literal `"hand-crafted"`. The schema already anticipates authored cases and names them; authored cases need no commit pin because the repository is the pin.
- `scenario.expected_ordering` is an array of **tiers** of `case_id`s, highest first, minimum 2 tiers, and cases within a tier are explicitly unordered with respect to each other. Ties are expressible, which matters: an oracle forced to break a tie it does not believe in manufactures a judgement.
- `contrastive_pair.expected_rank_order` is `const "high_above_low"` and `expected_score_delta_sign` is `const "positive"`. Authoring a pair therefore means **choosing its orientation** — which case is `case_high` — not filling in a direction. The schema's own note says these are stated in the data so the assertion is one the artifact carries rather than something implicit in harness code.
- `declared_context` is keyed on canonical resource identity and requires **both** `sensitivity` and `criticality` per resource, each an integer 0–5 **or `null`**, where `null` exercises the default-fallback path.
- `root.schema_version` is `const 1` and `additionalProperties` is `false` throughout.

---

## 2. Deliverable 1 — the ground-truth document

`eval/ground_truth/corpus-v1.json`. **One file**, because the schema's root requires `cases`, `contrastive_pairs` and `scenarios` in a single object — a directory of fragments would not validate.

The roadmap's sketch of `corpus/…/pairs/` and `scenarios/` directories predates the schema and is superseded here: those paths hold IaC, not ground truth.

Every case carries its `source` honestly — a `{repo, commit, path}` triple for anything mined from a vendored root, `"hand-crafted"` for authored cases.

---

## 3. Deliverable 2 — the pair-candidate generator

`tools/paircand/`, **not** `eval/`, because it consumes S3a's adapters and `eval/` may not import them (§1). It sits with `tools/harvest/` as a research instrument: outside `src/` because it is not part of the artifact, and outside `eval/` because it is not part of the grader.

This is the **first `tools/ → iacrisk` import** in the repository, so it is a deliberate precedent rather than a slide: the direction is instrument-consumes-artifact, which is sound, while the reverse — `src/` importing `tools/` — stays forbidden and tested.

It enumerates same-type resources from adapter output over corpus v0 and emits, for every pair whose issue-class sets differ, the two identities and **exactly which classes differ in each direction**. It writes `artifacts/pair-candidates.json`. It reports how many same-type combinations it considered and how many had an empty difference, because "12 usable pairs" means little without the denominator.

**What it does not do, stated because an earlier draft of this section claimed otherwise.** It does not prove single-factor purity. Proving that needs a class-to-factor mapping, which does not exist and which S2 is not the place to invent (§1). Purity is therefore an **authored judgement**: the human reads the listed class difference, names the `factor_under_test`, and justifies purity in the `rationale`. The generator *supports* that judgement by making the difference explicit and re-derivable; it does not replace it, and the spec does not dress it up as mechanical.

It also emits one negative figure: the count of resource pairs sharing an identical class set while differing in maximum severity. §1 measured that as **0**, and having the generator recompute it keeps that claim re-derivable instead of a one-time observation someone has to trust. If a re-capture ever makes it non-zero, severity becomes minable and §4's hand-crafted severity cases can retire.

What *is* mechanically enforceable is **cross-pair consistency** — §6 gate 5. The set of pairs induces a class-difference-to-factor relation, and that relation must be a function: if one pair rests the `exposure` claim on a class difference and another rests `severity` on the same difference, one of them is wrong. That catches the realistic authoring error without inventing the table.

---

## 4. Deliverable 3 — hand-crafted gap-filling cases

`corpus/authored/`, with its scan root declared in `tools/corpus.lock.json` alongside v0's vendored roots.

**Scope: the minimum v0 cannot express — two factors, not one.**

- **privilege:** three IAM policies differing in scope alone — narrow, moderate, broad — yielding two pairs from three cases.
- **severity:** two or three resources of one type, each triggering rules in a single shared issue class at different severities. §1 shows this is constructible because five classes span multiple severities; it is not minable because in v0 that variance only ever appears across different resource types.

Anywhere a mined candidate turns out impure on inspection, its factor gets a hand-crafted pair too.

A note on relative value, so the authored surface is spent knowingly: severity enters the additive model as a direct term, so its pair is a **sanity check on the engine** rather than a test of the research contribution. It is included because the marginal cost is two small resources in a scan the privilege cases already require — not because it carries an argument.

**These files must be scanned.** `expected.findings` references real `resource_identity` and `issue_class` values, and there is no honest way to author those without seeing what the pinned scanners actually emit. S2 therefore runs the pinned scanners over the **new root only**, capturing fixtures to `tests/harvest/fixtures/authored/`. Corpus v0's five golden documents are not touched, re-captured, or rewritten. This is a deliberate, bounded relaxation of the don't-run-the-scanners rule, and it is bounded by path.

A resource whose findings the scanners do not produce as expected is a defect in the authored case, not in the scanners — the case gets fixed until the scan shows what the pair needs.

---

## 5. Deliverable 4 — the oracle protocol

The protocol that makes `oracle.reviewer` mean something. This is the part the prioritization-usefulness metric rests on, so it is specified rather than left to practice.

**What the reviewer receives:** the rubric (the six factors, their ranges, and their level definitions), the case's IaC, the scanner findings on it, and the declared context.

S1's outstanding citation audit does **not** block this. `rubric.json` carries `citations_audited: false`, and what is unaudited is the per-level `source` *attribution strings* — not the level definitions themselves, which were frozen before any output existed and are pinned by tests. The reviewer is given the definitions and must not be given the `source` strings, since nothing unaudited should influence a judgement that ends up in the results.

**What the reviewer never receives:** any score the framework computed, the author's expected ordering, or the author's rationale. The reviewer derives an ordering independently from the rubric.

**Identity.** `oracle.reviewer` is a free string, so S2 fixes its spelling: it names the reviewing model and the protocol section, e.g. `blinded-reviewer:claude-opus-5 (design §5)`. `oracle.author` names the student. The validator rejects them being equal.

**Timing.** `oracle.registered_at` is set when the reviewer's verdict is recorded, and every one must predate the first scoring artifact. §6 enforces this mechanically rather than trusting the dates.

**The resolution rule, pre-registered here so it cannot be chosen later to suit the outcome:**

1. The author's ordering stands as ground truth.
2. Every disagreement is reported — the schema's `disagreement_note` exists for this.
3. **Any scenario the reviewer marks `disagree` is excluded from the headline prioritization-usefulness number** and reported separately, with its own count.
4. A `partial` verdict is reported but not excluded; the note states what differed.

Rule 3 is the load-bearing one. Without a rule fixed in advance, disagreements resolve toward whatever flatters the framework, and the metric becomes self-graded — which is exactly what the validator's `author != reviewer` check exists to prevent at the structural level.

**Agreement is reported as a number, not a claim:** exact-tier agreement across scenarios, plus a rank correlation for partial credit. Both figures belong in the results whatever they say.

**Disclosure.** That the reviewer is a language model under a blinding protocol is stated plainly in the dissertation, as a limitation and as a method. It is not presented as human expert review.

---

## 6. Deliverable 5 — coverage targets and their enforcement

Fixed a priori, before any case is authored, and enforced as tests in `tests/test_s2_gates.py`.

| Target | Minimum | Rationale |
|---|---|---|
| contrastive pairs per factor | 2 × 6 factors = 12 | one pair per factor is a single point of failure |
| scenarios per domain | 1 × 5 domains = 5 | the five domains are the tested categories |
| cases per scenario | 3, across ≥2 tiers | the schema enforces ≥2 tiers; 2 cases in 2 tiers is a pair, not an ordering |
| cases exercising `defaulted_factors` | ≥1 | a `null` declared value (PLAN Q4) |
| cases exercising `unresolved_factors` | ≥1 | an extractor failure (PLAN Q9) |

**The six S2 acceptance gates.** Each covers something S1's validator does *not*:

1. `eval/ground_truth/corpus-v1.json` loads through the committed `load_and_validate` without error.
2. Every one of the six `factor_key` values is the `factor_under_test` of at least 2 pairs.
3. Every one of the five `domain` values has at least 1 scenario, and every scenario orders ≥3 cases across ≥2 tiers.
4. **No orphan cases** — every `case_id` is referenced by at least one pair or scenario. The validator checks that references resolve; it does not check the converse.
5. **Cross-pair consistency.** For every mined pair, the recorded class difference between its two cases is still what the adapters produce when re-derived. And the relation the pairs induce from class-difference to `factor_under_test` is a **function**: no single class difference is cited as evidence for two different factors. Hand-crafted cases carry `source: "hand-crafted"`; mined ones carry a `{repo, commit, path}` triple.
6. Both `defaulted_factors` and `unresolved_factors` are non-empty on at least one expected finding each, and every scenario oracle is complete: a `reviewer_verdict` in the enum, a `reviewer` distinct from the `author`, and a `registered_at` that parses as a date in the past.

**What gate 6 can and cannot carry.** An earlier draft of this section had gate 6 assert that every `registered_at` predates the earliest scoring artifact. That test would be **vacuous**: no scoring module exists, so there is nothing to compare against, and it would pass while proving nothing — the precise defect S3a shipped three times before it was caught. Stated plainly instead:

- The **test** carries oracle *completeness and well-formedness*. That is all a test can establish from inside S2.
- The **ordering claim** — that ground truth was authored before any score existed — is evidenced by **git history**: the commit adding `corpus-v1.json` precedes any commit introducing a scoring engine, and both are in the repository. That is stronger evidence than a self-reported timestamp anyway, because it is not written by the party making the claim.
- When S4 lands, gate 6 gains the comparison and becomes load-bearing. Until then the ordering rests on git, and the dissertation cites git rather than the gate.

---

## 7. Testing

- `tests/paircand/test_generate.py`, mirroring the existing `tests/harvest/` layout — the generator: two same-type resources with differing class sets are emitted **with the difference recorded in both directions**; two with identical class sets are not emitted but *are* counted in the considered denominator; and the `aws_rds_cluster` trap is pinned as a regression test in the form the generator can actually express — all nine instances carry an identical class set, so no candidate is produced for them at all. That is the mechanical half of §1's trap; the judgement half (that `iam-authentication-controls` is authentication config, not privilege scope) lives in the spec and in the hand-crafted privilege pair's rationale, because no test can hold it.
- `tests/test_s2_gates.py` — the six gates above.
- Ground-truth authoring is data, so its test is the validator plus the gates. There is no unit test of a judgement — and §6 gate 5 is deliberately the strongest mechanical check available over authored judgements rather than a proof of them.

---

## 8. Out of scope, explicitly

- **Scoring and reporting** (S4) and the **evaluation harness** (S5). S2 produces the data those consume and computes no metric itself.
- **A second vendored real-world repository.** Corpus v1 is built on deliberately-insecure teaching repos plus minimal hand-crafted cases. That limits external validity, and that limitation is **stated in the results** rather than solved here — consistent with PLAN's existing exclusion of multi-cloud production repos.
- **`expected_band` beyond the few unambiguous cases**, each flagged so the Q10 threshold sensitivity analysis can exclude them instead of appearing to fail.
- **Auto-inference mode's ground truth.** S2 authors the declared-context path; the convention-based inference mode is evaluated against the same cases later, not given its own corpus.

---

## 9. Residual risks

1. **Single-factor purity is an authored judgement, not a proven property.** This is the largest residual risk in S2 and it follows from the missing class-to-factor mapping (§1). The generator makes each pair's class difference explicit and re-derivable, and gate 5 enforces that the induced class-difference-to-factor relation is a function — but nothing establishes that the *named* factor is the right one. A pair can be internally consistent, mechanically clean, and still test the wrong factor. **Cost if wrong:** a contrastive-pair pass rate that measures something other than what the results claim it measures, with no artifact that would reveal it. The only real mitigation is that the reviewer of §5 sees the pairs too; a disagreement there is the signal to look.
2. **A hand-crafted pair is a pair the framework's author wrote.** Mitigated by keeping authoring to the minimum v0 cannot express, by recording the class difference mechanically for everything else, and by disclosing the hand-crafted count. Not eliminated.
2. **The blinded reviewer shares a model family with the author's tooling.** Correlated blind spots are possible and cannot be measured from inside. A supervisor review of a sample would bound it; that is available later and does not block S2.
3. **Scanning the authored root introduces a second fixture set.** Two fixture directories mean two things that can drift. Bounded by never touching v0's, and by the authored fixtures being regenerable from committed files.
4. **`iam-authentication-controls` looks like privilege material and is not.** Only half of this is testable: the generator emits no `aws_rds_cluster` candidate because all nine instances share an identical class set, and that is pinned as a regression test. The judgement — that the class is authentication configuration rather than privilege scope — cannot be tested and lives in §1 and in the hand-crafted privilege pair's rationale. The next author will have the same thought, so it is written down twice rather than once.
