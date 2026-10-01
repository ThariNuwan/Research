# S4 — Risk Scoring and Reporting (design)

**Project:** A Framework for Risk-Aware Security Misconfiguration Detection and Prioritization in Cloud IaC Environments
**Author:** Jayathissa E.A.T.N. (258243J) — MSc in Computer Science (Cloud Computing), University of Moratuwa
**Date:** 2026-10-01
**Scope:** Sub-project S4 — pipeline layers 4 and 5. The scoring engine, the priority banding, the ranked output, and the reports.
**Authority:** `docs/PLAN.md` Q5, Q7, Q8, Q10; `src/iacrisk/data/rubric.json` (frozen); the S1, S3a and S3b handoffs.

---

## 0. Purpose and scope

S3b attaches five contextual attributes to every context-eligible finding. **S4 turns them
into a number, a band, and a ranked list a practitioner can act on.** It is the layer the
whole framework exists to deliver: the prioritization layer is the research contribution,
and until S4 exists there is no prioritization to evaluate.

S4 computes **no evaluation metrics**. Normalization coverage, prioritization usefulness,
alert reduction, ranking consistency and the baseline comparison are S5's, computed by an
independent harness reading S4's JSON. That separation is a validity control, not a
convenience: a tool that graded its own output would be circular no matter how carefully the
metrics were defined.

**What S4 enforces rather than invents.** The rubric already carries the formula, the frozen
1–28 bounds, the four band boundaries with their remediation actions, four coherence rules,
the per-scanner severity-normalization table, and the exposure precedence rule — all as
data. `rubric.band_for()` already validates and raises outside 1–28. S4's job is to apply
them and to make a violation impossible, not to restate them in code.

### 0.1 Global constraints (bind every part of S4)

- **The structural freeze is absolute.** Six factors, their ranges, the 1–28 bounds and the
  four bands were fixed at the end of S1 before any scoring output existed. **S4 adds no
  factor and moves no boundary.** Any such change is reported as sensitivity analysis
  (PLAN Q10), never applied to the primary model. §2 is where this bites hardest.
- **`scored_level` is the only arithmetic input.** Never read `FactorValue.level` in a sum —
  it is `int | None`. S3b built `scored_level` precisely so a scoring call site cannot
  forget the unresolved branch.
- **All four coherence rules are enforced, and three of them by construction.**
  `severity_context_fencing`, `encryption_sensitivity_orthogonality`,
  `iam_governed_resource_inheritance` and `unresolved_default_reporting` — §4.3 says how
  each is enforced and which are testable only by mutation.
- **Explicit states survive into the output.** `unresolved`, `defaulted`, `unknown`,
  `unmapped:`, `low_confidence` and §2's `factor_gap` all appear in the JSON. A consumer
  must be able to tell a resolved 3 from an unresolved one, because S5's reports depend on
  the difference.
- **JSON is the source of truth**; the human report renders from it, never the reverse.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a
  defect — docstrings, comments, test names, commit messages, this spec. Measured facts
  carry their source.
- **Windows-native.** Always `uv run python`; `uv run mypy` takes no path argument. Judge
  pytest by exit code — under `-q --strict-markers -rs` a failing test emits no `FAILED`
  line.

---

## 1. Measured facts S4 is designed around

Every figure was measured on this host at `0908cd2` against the committed fixtures. Each
changes a design decision rather than decorating it.

**1.1 The washout is still the governing constraint.** The five context defaults sum to 16,
so a finding with nothing resolved scores 17–21 — **always High**. `unknown` severity
resolves to 4 and all 489 Checkov rows carry null severity, so a Checkov finding with no
resolved context lands on exactly **20**.

**1.2 Exposure contributes a near-constant.** Exposure is `unresolved` on **934 of 1,025**
eligible findings (91.1%), by design: PLAN Q9's closed pattern list marks anything outside
it unresolved, never low. On those findings exposure contributes a flat 3 and does **no
ranking work**. S4 must not present exposure as a discriminator across the corpus, and
§7.3's per-factor contribution report is what keeps that visible.

**1.3 Two resolution rates, never conflated.** On the declared-context path (the 209
findings whose resource `corpus-v1` declares): **13.9% low-confidence, 86.1% usable**.
Across all 1,025 eligible corpus-v0 findings: **77.9% low-confidence**. v0 is the
measurement corpus; `corpus-v1` is the evaluation corpus and declares only 20 identities.

**1.4 The factor-gap population is 122 of 1,025 (11.9%)**, measured across the five
candidate classes §2 rules on:

| Class | Category | Findings |
|---|---|---|
| `containers-image-supply-chain` | containers | 63 |
| `containers-host-isolation-breakout` | containers | 43 |
| `networking-egress-exposure` | networking | 6 |
| `compute-instance-metadata-hardening` | compute | 6 |
| `iam-hardcoded-secrets` | iam | 4 |

**1.5 Banding is already implemented and already validates.** `rubric.band_for()` maps
1–8 Low, 9–15 Medium, 16–21 High, 22–28 Critical, and raises `ValueError` outside 1–28. S4
calls it rather than reimplementing the thresholds.

---

## 2. The ruling on the factor-gap classes

`CLAUDE.md` states that S4 must rule: **widen the factor set, or state the risk is out of
scope.** This section is that ruling.

### 2.1 The ruling: do not widen the factor set

**Three reasons, in order of weight.**

**The freeze is load-bearing for the central methodological claim.** Six factors, their
ranges, the 1–28 ceiling and the four bands were fixed before any scoring output existed,
and that ordering is the whole of the project's answer to the circularity objection — *"I did
not tune to fit the data; I fixed the model a priori and then analysed its sensitivity."* A
seventh factor changes the ceiling, which invalidates every band boundary, because the bands
are positioned against the ceiling. Widening would therefore not be an improvement to the
model; it would be a **new model**, and the a-priori claim would not transfer to it.

**The trade is bad on its own terms.** The gap covers 11.9% of findings. The freeze covers
the credibility of the entire evaluation. Trading the second for the first is not a close
call.

**The gap is not a scoring error.** A finding in `containers-image-supply-chain` still has
all six factors legitimately scored for its resource — its severity, its exposure, its
privilege, its declared sensitivity and criticality, its encryption state. What is missing
is a *term for that specific risk dimension*. The ranking is **insensitive** to supply-chain
risk; it is not **wrong** about the finding. That distinction matters, because it is the
difference between a limitation to report and a defect to fix.

### 2.2 What S4 does instead: make the gap measurable

Stating a risk is out of scope is only honest if a reader can see how much risk that is. S4
therefore ships three things the project does not currently have.

**A committed class-to-factor mapping table** (`src/iacrisk/data/factor_map.json`). For each
of the 28 taxonomy classes, which of the six factors bear on the risk the class names, and
which do not. **This artifact does not exist anywhere today** — the S2 handoff records that
"no class-to-factor mapping exists anywhere in the data", which is why single-factor purity
remained an authored judgement and why the gap set was "not established as complete". The
table closes both gaps at once: it makes the 28 × 6 sweep a committed artifact rather than an
unrun promise, and it is what derives §2.3's marker instead of a hand-maintained list of
class names.

**A per-finding `factor_gap` marker**, derived from that table: true when no factor maps to
the class's named risk. Derived, never hand-listed, so a taxonomy change cannot leave the
marker stale.

**A band distribution reported twice** — with and without the gap findings — so a reader can
see whether excluding them changes any conclusion. If gap findings cluster low, that is a
reportable understatement and the write-up says so; if they distribute like the rest, the
limitation is cosmetic. **Either way the number is reported, not predicted.**

### 2.3 What the marker does NOT do

**Gap findings are not excluded from prioritization-quality claims.** This is a deliberate
departure from how `unmapped:` findings are treated, and the asymmetry is the point. An
`unmapped:` finding has **no class**, so it scores on severity plus default context and ranks
artificially low — including it would depress a quality figure for a reason unrelated to the
model. A gap finding has a class **and** full context; every factor that applies to it is
scored from evidence. Excluding it would discard a legitimately-scored finding and would
overstate the model's coverage by shrinking the denominator.

They are reported as a named subset instead. §10's gate 6 asserts the two distributions are
both emitted, so the comparison cannot be quietly dropped.

---

## 3. Deliverable 1 — the scored finding record

`ScoredFinding` wraps a `ContextualizedFinding`; nothing S3b wrote is modified.

| Field | Type | Meaning |
|---|---|---|
| `contextualized` | `ContextualizedFinding` | The input, carried whole |
| `severity` | `FactorValue` | Normalized scanner severity as a factor, so all six are uniform |
| `contributions` | `Mapping[str, int]` | Per-factor `scored_level`, the six addends |
| `score` | `int` | Their sum, in 1–28 |
| `band` | `str` | From `rubric.band_for(score)` |
| `action` | `str` | The band's remediation action, from the rubric |
| `factor_gap` | `bool` | §2.3's marker, derived from `factor_map.json` |
| `low_confidence` | `bool` | Carried from S3b's frozen threshold of 3 |
| `explanation` | `tuple[str, ...]` | One line per factor: its level, its state, its evidence |

**3.1 Severity becomes a `FactorValue` at the boundary.** `rubric.normalize_severity`
returns `int | str`, where the string is the explicit `unknown` state — the trap both the S1
and S3a handoffs record. S4 converts it once, at the edge, into a `FactorValue` with
`state=UNRESOLVED` and the rubric's `unresolved_default` of 4, so the scoring sum sees six
uniform `FactorValue`s and no call site can concatenate a string into a total.

**3.2 The explanation is a deliverable, not a debugging aid.** PLAN's explainability claim is
that "each finding's score decomposes into named contributions, so a reviewer can see *why*
something ranked where it did". That is a property of the output, so it is a field, and
gate 3 asserts every scored finding carries one line per factor with its evidence.

**3.3 A context-ineligible finding is scored on severity alone and labelled.** S3b gives it
no context block at all. S4 does **not** default its five factors — that would re-open the
washout `context_eligible` exists to close. It scores severity only, is marked
`baseline_only_informational` per PLAN Q8, and is excluded from prioritization-quality claims
exactly as `unmapped:` is.

---

## 4. Deliverable 2 — the scoring engine

### 4.1 The sum

```
score = severity + exposure + privilege + sensitivity + criticality + encryption
```

Equal weights, each factor contributing its `scored_level`. Equal weighting is a **declared
neutral baseline**, not a claim that the six matter equally; PLAN Q10 puts alternative
weightings in the sensitivity analysis, and §4.4 keeps the engine ready for that without
making weights part of the primary model.

### 4.2 Bounds are asserted, not assumed

The sum of six in-range factors is necessarily within 1–28, so a score outside it means a
factor was out of range or a weight crept in. S4 asserts membership rather than trusting the
arithmetic, and `band_for` raises on its own account.

### 4.3 How each coherence rule is enforced

| Rule | Enforcement | Why that mechanism |
|---|---|---|
| `severity_context_fencing` | Mutation gate: substituting `issue_class` across and within categories changes no contribution, and `class_id` appears in no addend | The constraint is that a change *cannot* have an effect, which no positive assertion can show. S3b's gate 5 proves it at layer 3; S4 re-proves it on the sum, since a scoring layer could reintroduce the dependency |
| `encryption_sensitivity_orthogonality` | Mutation gate: varying declared `sensitivity` changes the sensitivity contribution and **nothing else**; varying the encryption attribute changes only encryption | The rule says the two axes "share no input". Same shape as fencing, same reason assertions cannot establish it |
| `iam_governed_resource_inheritance` | Already enforced in S3b's join; S4 asserts a resource-attached IAM finding's sensitivity contribution equals its governed resource's | S4's obligation is not to undo it when summing |
| `unresolved_default_reporting` | §7.2's band distribution split by defaulted-factor count, with the low-confidence subset named | The rule is a reporting obligation, so the report *is* the enforcement |

### 4.4 Weights exist as a parameter and default to 1

The engine takes an optional per-factor weight map defaulting to all ones. **The frozen
primary model is the unweighted sum**, and no S4 output uses anything else. The parameter
exists so S5's sensitivity analysis does not have to fork the engine — which would risk the
analysed model drifting from the scored one. A non-default weight map is a hard error in any
S4 report, so the primary path cannot silently become weighted.

---

## 5. Deliverable 3 — ranking and ties

Findings sort by descending score. **Ties are preserved as ties**, not broken arbitrarily:
the ranked output assigns the same rank to equal scores, because `corpus-v1`'s containers
scenario contains a deliberate tie and an arbitrary tiebreak would make the framework appear
to discriminate where it does not.

A secondary ordering is applied **within** a tie for output stability only — canonical
resource identity, then issue class, then scanner — and is documented as presentational. It
never changes a rank number.

**5.1 Ranking is over the deduplicated set.** S3a's Tier-1 collapse runs first; S4 ranks what
survives. Tier-2 candidates are *not* collapsed, so a Tier-2 pair appears as two ranked
findings, which is correct and is why PLAN Q7 reports deduplication and band reduction as two
numbers that are never combined.

---

## 6. Deliverable 4 — the severity-normalized baseline

The baseline is **raw scanner severity mapped into the same four bands** through the rubric's
per-scanner normalization table. Without that table the comparison would measure tool
convention as much as prioritization, because the three scanners assign severity by different
conventions and Checkov assigns none at all in this corpus.

**6.1 The baseline is a band assignment, not a score.** A severity of 1–5 cannot be banded
against a 1–28 ceiling. The baseline therefore maps each normalized severity level directly
onto a band by its own documented table — `5 → Critical`, `4 → High`, `3 → Medium`, `2 → Low`,
`1 → Low` — and that table is committed in S4 and cited wherever a baseline comparison
appears. Scaling severity onto 1–28 instead would invent precision the scanner never
supplied.

**6.2 `unknown` severity bands as High** under the rubric's `unknown_resolves_to: 4`, and the
**rate is reported with every baseline figure**, because 489 of 1,055 findings reach the
baseline through that route and a reader must know the baseline's own coverage before
comparing against it.

S4 emits the baseline band per finding. The rank-change table and every comparison statistic
are S5's.

---

## 7. Deliverable 5 — reporting

**7.1 JSON is the source of truth**, carrying per finding: identity, class, scanner
provenance, the six contributions, the score, the band, the action, the explanation lines,
the baseline band, and every explicit-state flag (`low_confidence`, `factor_gap`,
`baseline_only_informational`, per-factor `state`).

**7.2 The band distribution is reported four ways**, and no two are combined:

1. Overall, across all scored findings.
2. **Split by count-of-defaulted-or-unresolved factors (0–5)**, which is
   `unresolved_default_reporting`'s obligation.
3. **With and without the §2 factor-gap findings.**
4. **Framework bands against baseline bands**, as a contingency table — counts only. Any
   claim about whether the re-ranking is *better* is S5's.

**7.3 Per-factor contribution summary.** For each factor: how many findings it contributed a
resolved level to, how many a default, and the distribution of its contributions. This is
what makes §1.2 visible — a factor contributing a flat 3 to 91% of findings shows up here as
a near-constant column, and a reader can see which factors are doing the ranking work.

**7.4 The human report renders from the JSON**, grouped by band in Critical-first order, each
finding showing its score decomposition and its explanation lines. It is a view, never a
second source.

---

## 8. What S4 does not do

Normalization/retention coverage (S3a's report already exists), prioritization usefulness,
alert reduction, ranking consistency, the baseline **comparison statistics**, and the Q10
sensitivity analysis — **all S5's**, computed by the independent harness from S4's JSON.

S4 also does not implement auto-inference (S3c), does not render Helm charts, does not
aggregate IAM role→attachment→policy, and does not attempt cross-scanner attribute
normalization. Each is recorded future work in the S3a or S3b handoff.

---

## 9. Testing

Unit tests per module; integration over the committed fixtures; and **mutation tests for the
two orthogonality-shaped rules**, because "this change must have no effect" cannot be shown
by a positive assertion.

One lesson from S3b is binding here. A defect leaving **0 of 217** container identities
unmatched survived seven gates and 746 tests, because every test built its own fixture keyed
the way the code expected. **S4's gates must therefore measure over the real corpus and
report rates, not only assert over hand-built inputs** — and gate 7 is that requirement.

---

## 10. Acceptance gates

1. **Every scored finding's score equals the sum of its six contributions**, lies in 1–28, and its band equals `rubric.band_for(score)`. Asserted over the whole corpus, not a sample.
2. **No contribution is ever read from `FactorValue.level`.** Every addend is a `scored_level`, and a finding with an unresolved factor still scores — asserted by constructing one and checking the total.
3. **Every scored finding carries one explanation line per factor**, each naming the factor, its level, its state and its evidence. Empty or missing lines fail.
4. **Fencing and orthogonality, by mutation.** Substituting `issue_class` within and across categories changes no contribution; varying declared sensitivity changes only the sensitivity contribution; varying an encryption attribute changes only encryption.
5. **Context-ineligible findings score on severity alone**, carry `baseline_only_informational`, and have no defaulted context contributions — the washout `context_eligible` closes stays closed.
6. **All four band distributions of §7.2 are emitted**, including the with/without-gap pair, and the per-factor contribution summary of §7.3.
7. **The factor map covers all 28 classes × 6 factors** with no unmapped cell, `factor_gap` is derived from it rather than hand-listed, and the gap population is **measured and reported over the real corpus**, not asserted.
8. **A non-default weight map is rejected** by any report-producing path, so the frozen primary model cannot silently become weighted.

---

## 11. Decisions taken in this document

| # | Decision | Taken by | Cost if wrong |
|---|---|---|---|
| 1 | **Do not widen the factor set**; state the factor-gap risk as a scope limitation (§2.1) | This spec, under the S1 freeze | 11.9% of findings are ranked insensitively to the risk their class names; the alternative forfeits the a-priori freeze that answers the circularity objection |
| 2 | **Author `factor_map.json`**, a committed 28 × 6 class-to-factor table (§2.2) | This spec | Without it the gap set stays "not established as complete" and single-factor purity stays an unverifiable authored judgement |
| 3 | **Gap findings are reported, not excluded** from quality claims (§2.3) | This spec | Excluding them would shrink the denominator and overstate coverage; including them without the marker would hide the insensitivity |
| 4 | **Severity becomes a `FactorValue` at the boundary** (§3.1) | This spec | `int \| str` reaching six call sites reproduces the `normalize_severity` trap the S1 and S3a handoffs both record |
| 5 | **Baseline maps severity directly to a band**, not onto 1–28 (§6.1) | This spec | Scaling a 1–5 severity onto a 28-point ceiling invents precision the scanner never supplied and would flatter the framework by comparison |
| 6 | **Ties are preserved**, with a documented presentational sub-order (§5) | This spec | An arbitrary tiebreak makes the framework appear to discriminate where it does not, and `corpus-v1`'s containers scenario contains a deliberate tie |
| 7 | **Weights exist as a parameter, default to 1, and are rejected in reports** (§4.4) | This spec | A forked engine for S5's sensitivity analysis risks the analysed model drifting from the scored one |

Decision 1 is the one a reader should challenge first, so it is argued at length in §2.1
rather than asserted here. The short form: **the freeze is worth more than the coverage.**
