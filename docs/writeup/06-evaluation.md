# Chapter 6 — Evaluation

## 6.1 What this chapter reports, and how the record was produced

This chapter reports what the framework did when it was run against the evaluation
corpus and graded against the oracle of Chapter 4. It reports the results that
support the framework's claim and the ones that do not, and it keeps them apart from
the interpretation placed on them.

Every figure below is read from one of seven committed records, and none was
transcribed from an earlier draft.

| Record | What it holds | Produced by |
|---|---|---|
| `artifacts/scored-corpus-v0.json` | Corpus v0 through pipeline layers 2–5: every ranked finding with its six contributions, and the band distributions | `tools.score.run corpus` |
| `artifacts/scored-cases-v1.json` | Each corpus v1 case scored under its own declared context, at finding level | `tools.score.run cases` |
| `artifacts/evaluation-v1.json` | The harness's metrics over the two records above and the ground truth | `eval.run` |
| `artifacts/sensitivity-v1.json` | The registered sensitivity analysis | `eval.sensitivity` |
| `artifacts/scored-corpus-v0-inferred.json`, `artifacts/scored-cases-v1-inferred.json` | The first two records again, in auto-inference mode | `tools.score.run inferred` |
| `artifacts/auto-inference-agreement-v1.json` | The declared run compared with the inferred run | `eval.agreement` |

Three properties of how these were produced bear on how far they can be trusted.

**No scanner ran during the evaluation.** The scored records replay the scanner
outputs captured when the corpus was built — the same bytes every earlier measurement
in this dissertation was taken from — so a result does not depend on a scanner being
installed or on what it would emit today. Each record carries a digest of every input
it was computed from.

**The harness shares no code with what it grades.** `eval/` reads JSON and imports
nothing from the framework, and a structural test fails if that changes. The band
order and the factor names are restated in the harness as literals for the same
reason.

**At the frozen settings the sensitivity analysis must reproduce the scored record
before it runs.** It recomputes scores from the per-factor contributions rather than
by calling the framework, so it first re-derives every committed score, band and
low-confidence flag — 1,396 findings — and refuses to continue if one differs.

### 6.1.1 Rules fixed before the case-level results existed

The ground truth of Chapter 4 fixes the expected orderings. It does not fix how the
framework's output is compared with them, and two of those rules decide the headline
figures. They were therefore written down and committed before the per-case scores
were generated, and before any had been seen.

1. **A case ranks where its highest-scoring finding ranks.** The framework's output is
   a ranked list of findings, so a resource surfaces at its top finding. The number of
   findings on a resource is not a rubric factor and does not count. The sum and the
   mean of a case's finding scores are computed beside this rule as a check on how much
   the results depend on it (Section 6.4.5), and are never substituted for it.
2. **A finding counts toward a case only if the framework makes a quality claim about
   it.** `unmapped` findings are set aside, as Section 4.5 requires, and so are findings
   that carry no context at all. A case left with nothing to rank is reported as
   unrankable, never as a score of zero.
3. **A contrastive pair passes when the high case scores strictly above the low case.**
   A tie is a failure, because the oracle's expectation is an order.
4. **Isolation is checked rather than assumed.** A pair is *isolated* when, of the five
   contextual contributions, only the factor under test differs between the two cases.
   Severity is reported beside this and is not part of the test, because severity has no
   contrastive pair by measurement (Section 4.7.2) and moves whenever the set of issue
   classes does.
5. **A scenario is compared as tiers.** Three things are reported: whether the tiers the
   scores induce equal the expected tiers; Kendall's τ_b between them, left undefined
   where one side is tied throughout; and counts of the case pairs the oracle orders and
   the case pairs it ties.
6. **Nothing is excluded from the headline that the oracle's own rule does not
   exclude** — every pair contributes, and every scenario the reviewer did not mark
   `disagree`. A second figure over the *clean* subset, with no ground-truth-excluded
   case and no low-confidence case, is reported beside the first and never averaged
   with it.
7. **The baseline is graded by the same rules on the same findings**, ranking a case by
   its highest baseline band.
8. **Alert reduction is two numbers**, and nothing adds them.

The ordering is evidenced by the repository's history rather than by this paragraph:
the commit that introduced the harness is a strict ancestor of the commit that
introduced the per-case scores, and a test asserts that ancestry. The same was done
for the sensitivity plan (Section 6.7).

### 6.1.2 The populations

Three counts recur, and a figure means little without knowing which it is over.

- **1,055** findings leave the scanner adapters.
- **1,016** are ranked, after the exact-match deduplication tier removes 39.
- **986** of those are findings the framework makes a prioritization claim about. The
  other 30 have no addressable cloud resource — a hard-coded secret, a provider block,
  a file-level finding, or an identity that could not be resolved — so they are scored
  on severity alone and reported as informational.

Unless stated otherwise, prioritization figures in this chapter are over the 986 and
coverage figures over the 1,055. Chapter 3's measurements were taken over the 1,055,
before any deduplication was applied to the scored list; where a figure here differs
from one there for that reason, Section 6.2 gives both.

## 6.2 A defect the evaluation found, and the two recorded states

**The evaluation found a defect in the framework, and it was corrected after the
first results had been seen.** That sequence is what a reader should be most
suspicious of, so it is set out in full.

The first evaluation run returned the containers scenario inverted: a batch job
outranked the workload the oracle placed above it. The framework's own explanation
line for that job read *no resource body indexed*. The cause was a mismatch between
two indexes of the Kubernetes manifests. The index that resolves a finding's identity
gives a manifest that omits its namespace the namespace `default`; the reader that
supplies the manifest's contents to context extraction omitted that segment
altogether. The two keys never met.

Measured over corpus v0, **311 of the 579 context-eligible Kubernetes findings**, on
eight resources that omit their namespace, never reached their manifest. All three
code-derived factors fell to their unresolved defaults for every one of them. When the
extractor was built its Kubernetes body coverage was recorded as 46.3% and attributed
in part to Helm templates that do not parse. That figure was this defect in full:
with the namespace rule applied, all 579 match.

The correction is confined to that reader. **The scoring model — the rubric, the six
factors and their ranges, the band boundaries and the eight rules above — was not
touched.** Both states are committed, and where they differ both are given:

| Figure | As first measured | After the correction |
|---|---|---|
| Bands over the 986: Critical / High / Medium / Low | 0 / 531 / 451 / 4 | 0 / 235 / 747 / 4 |
| Privilege unresolved, of 986 | 303 | 6 |
| Encryption unresolved, of 986 | 631 | 334 |
| Low-confidence findings, of 986 | 762 | 740 |
| Critical/High count against the baseline's 649 | 531 (18.2% fewer) | 235 (63.8% fewer) |
| Findings promoted / demoted against the baseline | 245 / 271 | 196 / 427 |
| Promotions into High | 143, all low-confidence | 3 |
| Scenario case pairs right / tied / inverted, of 21 | 18 / 2 / 1 | 19 / 2 / 0 |
| Containers scenario τ_b | −0.5 | 0.5 |
| Contrastive pairs passed | 8 of 10 | 8 of 10 |
| Scenarios matched exactly | 2 of 5 | 2 of 5 |

Two things follow from that table. The mechanism results did not move: the pair and
exact-match figures are the same in both states. And the correction did not make the
containers scenario pass — it changed an inversion into a different mismatch, which
Section 6.4.3 describes.

What moved a great deal is the band distribution, and with it the alert-reduction
figure, which more than tripled. A result that improves this much after a
post-hoc change deserves less confidence, not more, and Section 6.7 shows
independently that the band counts are the least stable thing this evaluation
measures. The remainder of this chapter reports the corrected state.

## 6.3 Normalization and retention coverage

This metric asks what fraction of scanner findings the pipeline normalizes and
carries through. It is not detection accuracy, which is delegated to the scanners.

| Adapter run | Findings in | Findings out | Dropped | No severity supplied |
|---|---|---|---|---|
| Checkov, Terraform | 221 | 221 | 0 | 221 |
| Checkov, Kubernetes | 268 | 268 | 0 | 268 |
| Trivy, Terraform | 115 | 115 | 0 | 0 |
| Trivy, Kubernetes | 332 | 332 | 0 | 0 |
| tfsec, Terraform | 119 | 119 | 0 | 0 |
| **All five** | **1,055** | **1,055** | **0** | **489** |

**All 1,055 findings are retained and none is dropped.** Every one maps to a taxonomy
class: the unmapped count is zero. Nineteen findings (1.8%) have an identity that
could not be resolved, and 30 (2.8%) are not eligible for context.

**489 findings (46.4%) arrive with no severity at all, and every one of them is
Checkov's.** This is the figure that matters most for what follows, because it means
that for nearly half the corpus the *baseline* the framework is compared against is
not a scanner judgement. Those findings reach a baseline band through the rubric's
documented default.

The caveat of Section 4.7.5 applies: the count entering each adapter is derived from
the count leaving it plus the count dropped, so this table shows that nothing is lost
between an adapter's output and the ranked list. That the adapters read every raw
record is established separately, by tests that count the raw records independently.

## 6.4 Prioritization usefulness

### 6.4.1 Contrastive pairs

**Eight of the ten pairs pass. The severity baseline passes one.**

| Pair | Factor | Source | High case | Low case | Framework | Baseline |
|---|---|---|---|---|---|---|
| `exposure-security-group` | exposure | mined | 15 | 10 | pass | pass |
| `exposure-s3-public-access` | exposure | hand-crafted | 17 | 12 | pass | tie |
| `privilege-iam-bucket-to-account` | privilege | hand-crafted | 16 | 15 | pass | tie |
| `privilege-iam-account-to-unrestricted` | privilege | hand-crafted | 18 | 16 | pass | tie |
| `sensitivity-s3-financials` | sensitivity | mined | 17 | 13 | pass | tie |
| `sensitivity-s3-operations` | sensitivity | mined | 16 | 13 | pass | tie |
| `criticality-s3-data` | criticality | mined | 17 | 13 | pass | tie |
| `criticality-s3-data-science` | criticality | mined | 16 | 13 | pass | tie |
| `encryption-s3-data` | encryption | mined | 15 | 15 | **tie — fail** | tie |
| `encryption-s3-financials` | encryption | mined | 15 | 15 | **tie — fail** | tie |

The scores are each case's highest finding score. All ten pairs are evaluable, and
none touches a ground-truth-excluded or low-confidence case, so the clean figure is
the same as the headline: 8 of 10.

**In all eight passing pairs the factor under test moved in the predicted direction
and was the only contextual factor that moved.** A pass therefore reflects the factor
the pair names, not a coincidental difference elsewhere. In one of the eight,
`exposure-security-group`, severity moved as well, by one point; Section 6.7 shows
that this pair still passes with the exposure factor removed, so it is weaker evidence
for the exposure mechanism than its sibling.

**The baseline cannot pass a pair that differs only in context, and that is the point
of the comparison rather than a weakness of it.** Four pairs put the same resource
under two declared contexts, so the scanners' findings are identical on both sides.
In five more the two cases draw different issue classes but their most severe finding
falls in the same band. The baseline ties all nine. Its single pass is the pair where
severity happens to differ.

Two disclosures qualify the 8 of 10. **Three of the eight passes are on hand-crafted
cases**, written by the framework's author because the vendored corpus contains no
resource pairs that isolate privilege or a second exposure pattern (Section 4.3). On
the seven pairs mined entirely from third-party code the framework passes five.
And the pairs test the direction of a rank change only: every one compares scores
that sit within a few points of each other in the middle of the range.

### 6.4.2 The encryption factor is not shown to work

**Both failures are the two encryption pairs, both are 15–15 ties, and by the
criterion of Section 4.2 this is a failed mechanism test.**

Each pair sets an unencrypted S3 bucket against one that carries a server-side
encryption block. The framework's explanation lines give the cause directly. The
encrypted bucket's block sets its algorithm literally but names its key by reference
to another resource; extraction reads literals only, and records the whole block as
*unresolved*. The
unencrypted buckets declare no encryption block at all, which the extractor also
records as unresolved, on the reasoning that the platform's effective default depends
on account-level settings the source does not show. **Both sides therefore take the
same default of 2, and the factor contributes nothing to the difference.**

Three further observations make this a property of the evaluation as a whole rather
than of two pairs:

- The storage scenario matches exactly (Section 6.4.3), but encryption plays no part
  in that: all five buckets contribute 2.
- Removing the encryption factor from the model changes no pair result and no
  scenario result (Section 6.7).
- Across the 986 findings the factor takes only two values. It is 0 on 616 and 2 on
  370, and 334 of those 370 are the unresolved default.

Each of the two design decisions behind the tie is defensible on its own: literals-only
extraction is what keeps the framework from guessing, and declining to treat an absent
block as proof of an unencrypted bucket avoids a false alarm. Together they leave the
factor unable to separate the one case the corpus offers it. **This evaluation
provides no evidence that the encryption factor discriminates.**

### 6.4.3 Scenarios

**Two of the five scenarios match their expected tiers exactly; the baseline matches
none. Of the 21 case pairs the oracle places in an order, the framework orders 19
correctly, ties 2 and inverts none; the baseline orders 4, ties 16 and inverts 1.**

| Scenario | Expected | Framework (highest finding score) | Exact | τ_b | Baseline τ_b |
|---|---|---|---|---|---|
| Storage | (financials = data) > (operations = data-science) > logs | (17 = 17) > (16 = 16) > 15 | yes | 1.000 | undefined |
| IAM | unrestricted > account > bucket | 18 > 16 > 15 | yes | 1.000 | undefined |
| Networking | web-node > interpolated > (egress = default) | 15 > 13 > 11 > 10 | no | 0.913 | 0.224 |
| Compute | web-host > db-app > ebs | (17 = 17) > 14 | no | 0.816 | 0.816 |
| Containers | goat-home > (kube-bench = internal-proxy) | (13 = 13) > 11, kube-bench last | no | 0.500 | undefined |

The baseline's τ_b is undefined on three scenarios because it assigns every case the
same band there, leaving no order to correlate.

The three scenarios that do not match exactly fail in three different ways, and the
differences matter more than the count.

**Networking: every ordered pair is right, and the one expected tie is split.** The
oracle ties an unrestricted egress rule with a security group that has no rule of its
own, on the argument that neither carries a supported exposure signal. The framework
separates them by one point, and the point is scanner severity: the egress rule draws
a Critical-severity finding. No contextual factor distinguishes them. The scenario's
pre-registered rationale itself notes that a practitioner would not call the two equal
in risk and that the rubric has no factor for egress; the framework's split is that
judgement arriving through scanner severity, not through any contextual factor.

**Compute: the contested pair is tied.** The author ordered `web-host` above
`db-app`; the blinded reviewer ordered them the other way, on the ground that
`db-app` carries an instance profile with broad permissions (Section 4.4.4). The
framework scores both at 17 and produces neither order. `web-host` gains a point on
severity and `db-app` a point on declared criticality. The privilege factor, which
the reviewer's reading turns on, is 0 for both: the bounded extractor does not follow
an instance to its role and that role's policy. On this scenario the baseline scores
exactly as well as the framework.

**Containers: the framework reproduces the reviewer's ordering, not the author's.**
The author placed `goat-home` alone at the top and tied the other two. The framework
ties `goat-home` with `internal-proxy` and places `kube-bench` beneath them — the
arrangement the blinded reviewer proposed, as the scenario's disagreement note records,
and which did not replace the author's under the pre-registered rule.
The separation comes from declared context alone: `kube-bench` is declared at
sensitivity 2 and criticality 2 against 3 and 3 for the others, and the three cases
are otherwise scored identically. The host-level access that makes `kube-bench` a
concern in its own right — it shares the host's process namespace and mounts host
paths — reaches no factor, which is the factor-coverage gap of Chapter 3 appearing in
a result.

### 6.4.4 What the oracle's own uncertainty does to these figures

All five scenarios contribute to the headline, because the reviewer marked none
`disagree`. Two were marked `partial`, and they are the compute and containers
scenarios — two of the three the framework does not match. **The framework's
mismatches are concentrated where the oracle itself was uncertain.** That is
informative, but it cuts both ways: it does not make those mismatches agreements.

Three scenarios are free of both ground-truth-excluded and low-confidence cases:
storage, IAM and containers. On that clean subset the framework matches 2 of 3 and
orders 12 of 13 case pairs correctly with one tied. The networking scenario is
outside it because one of its cases has an exposure the extractor could not resolve,
and the compute scenario because one of its cases has a declared value deliberately
left absent.

The threat of Section 4.7.1 applies to every figure in this section and is not
reduced by any of them. The reviewer and the framework's design reasoning share a
model family, and no human expert has yet reviewed the orderings. These results
establish that the framework's orderings are consistent with a pre-registered oracle;
they do not establish that a practitioner would agree with either.

### 6.4.5 How much the results depend on the case-ranking rule

Rule 1 of Section 6.1.1 is a choice, so the results under the two obvious alternatives
are reported beside it.

| Case ranked by | Pairs passed, of 10 | Scenarios exact, of 5 | Ordered case pairs right / tied / inverted |
|---|---|---|---|
| **Highest finding (registered)** | **8** | **2** | **19 / 2 / 0** |
| Sum of findings | 9 | 1 | 18 / 0 / 3 |
| Mean of findings | 8 | 1 | 20 / 0 / 1 |

No rule changes the picture, but the sum deserves a comment because it passes one
more pair. It passes the two encryption pairs for a reason unrelated to encryption —
the unencrypted buckets simply carry more findings, 24 against 15 — and it fails a
privilege pair for the mirror-image reason. A rule that rewards the number of findings
rewards scanner overlap. The registered rule was fixed before these figures existed
and is the one the results are stated under.

## 6.5 Alert reduction

Alert reduction is reported as two numbers that measure two different steps.

**Deduplication removes 39 of 1,055 findings, 3.7%.** This is the exact-match tier
alone. A further 207 candidate overlaps are surfaced and deliberately not merged: 116
involve more than one scanner, and 91 are a single scanner raising findings the
fingerprint cannot tell apart. Neither count is part of the reduction (Section 4.7.5).

**Prioritization reduces the Critical/High count from 649 to 235, 63.8%**, over the 986
findings the framework makes a claim about.

| Band | Baseline | Framework |
|---|---|---|
| Critical | 16 | 0 |
| High | 633 | 235 |
| Medium | 138 | 747 |
| Low | 199 | 4 |

The table shows what the percentage alone hides: the framework does not so much
reduce the high-priority set as **compress the whole distribution into the middle**.
The High band shrinks by 398 and the Low band by 195, and 747 of 986 findings, three
quarters, land in Medium. A practitioner is handed a shorter urgent list and a far
longer undifferentiated one.

Three qualifications must travel with the 63.8%, and without them it overstates what
was shown.

1. **Most of the baseline's High band is not a scanner's judgement.** 441 of its 649
   Critical/High findings are Checkov findings with no severity, banded High by the
   rubric's default. The framework is being compared, for two thirds of that band,
   against a default it chose itself.
2. **Most of the findings are low-confidence.** 740 of the 986 have three or more of
   their five contextual factors defaulted or unresolved, including 200 of the 235 the
   framework places in High. Only 35 High findings rest on a majority of resolved
   evidence.
3. **The figure is not stable.** Section 6.7 shows that moving one band boundary by a
   single point, or one default by a single point, changes the Critical/High count
   several-fold.

**No finding reaches Critical.** The highest score in the corpus is 20, on two
findings, against a Critical boundary of 22. The arithmetic is simple: the five
contextual defaults sum to 16, so a finding with every contextual factor at its default
totals at most 21. Nothing the framework
does on this corpus exercises the band whose remediation action is to block a
deployment.

## 6.6 Baseline comparison

Of the 986 findings, **196 are promoted relative to the baseline, 427 are demoted and
363 keep their band.**

| Movement (baseline to framework) | Findings | Low-confidence | Baseline band from an absent severity |
|---|---|---|---|
| High to Medium | 411 | 260 | 286 |
| Low to Medium | 193 | 162 | 0 |
| High to High | 222 | 190 | 155 |
| Medium to Medium | 137 | 118 | 0 |
| Critical to High | 10 | 7 | 0 |
| Critical to Medium | 6 | 0 | 0 |
| Low to Low | 4 | 0 | 0 |
| Low to High | 2 | 2 | 0 |
| Medium to High | 1 | 1 | 0 |

Chapter 4 requires each movement to be justified by named factors. The record carries,
for every cell, the mean contribution of each factor and the share of findings on
which that contribution was resolved from evidence rather than taken from a default.
Three movements account for most of the table.

**High to Medium, 411 findings, is driven by privilege and encryption resolving to
zero.** Privilege is resolved on every one of them and its mean contribution is 0.00;
encryption is resolved on 79% and its mean is 0.42. Against defaults of 4 and 2, that
is where the points go. This is the movement the framework was designed to make: a
finding the scanner rated High, on a resource that grants no permissions and needs no
data protection, is not a High-priority finding.

**Low to Medium, 193 findings, is driven by defaults.** Sensitivity is resolved on
15% of them and criticality on 16%; exposure on 4%. These findings were rated Low by
a scanner and rise because three factors nobody resolved contribute 3, 3 and 4. That
follows from the rule that a missing value must never read as low, but it should be
described as what it is — **a promotion on absent evidence**.

**All 16 findings the baseline calls Critical are demoted**, ten to High and six to
Medium, because the Critical band cannot be reached (Section 6.5).

Taken together, 432 of the 623 findings that change band are low-confidence, and 286
of the 427 demotions start from a baseline band that was itself a default. **The
re-ranking is fully explainable — every point is attributable to a named factor —
but for most findings the explanation names a default.** Explainability and
evidence are different properties, and the framework has the first more securely than
the second.

## 6.7 Ranking consistency

Chapter 4 splits this metric in two and requires that the halves are not averaged.
Sections 6.7.1 to 6.7.3 report the model's sensitivity to its own parameters; Section
6.7.4 reports how closely the auto-inference mode follows the declared-context run.

The sensitivity analysis is a reported experiment, not a search. Its 63 variants were
listed in a plan, approved, and committed before any of them was computed; all 63 are
in the record and none was filtered. The frozen model is the result throughout — no
variant replaces it. The experiment covers four things: each factor's unresolved
default across its whole range, one at a time, plus every default at its minimum and
at its maximum (29 variants); each band boundary moved by one and by two points, alone
and together (16); each factor's weight dropped to zero and doubled, plus two named
emphases (14); and the low-confidence threshold from 1 to 5 (4).

### 6.7.1 The ordering results are stable

**The pair result is 8 of 10 under all 29 default variants, all 16 boundary variants,
all six doubled weights and both named weightings.** It changes only when the factor
under test is weighted to zero, where the two pairs built on that factor must fail
and do: privilege, sensitivity and criticality each lose both. Two exceptions are
informative. Dropping exposure loses only one of its two pairs, because
`exposure-security-group` passes on its one-point severity difference. And dropping
encryption loses nothing, because nothing depended on it.

The scenario result is 2 of 5 exact matches in 56 of the 63 variants, and ranges from
1 to 3 across the rest. Agreement between each variant's ranking of the 986 findings
and the frozen ranking, as Kendall's τ_b, is above 0.9 for 28 of the 43 variants that
change any score. The 15 below it are, with one exception, the variants furthest from
the frozen settings: a default moved two or more points, a factor dropped altogether,
or every default moved at once. The exception is doubling the encryption weight, at
0.857. Setting every default to its minimum is the only variant that decorrelates the
ranking entirely, at τ_b −0.13.

The two named weightings — doubling exposure and privilege, and doubling sensitivity
and criticality — leave both the pair and exact-match results unchanged, at τ_b 0.985
and 0.901 respectively. They were chosen from sources the rubric already cites and
approved by the author. **They are not independently expert-derived, which is what
Chapter 4 promises**, and the result should be read with that limit.

### 6.7.2 The band counts are not

**199 of the 235 High findings score exactly 16, the lowest score in the High band.**
Everything unstable in this evaluation follows from that one fact.

| High boundary at | 14 | 15 | **16 (frozen)** | 17 | 18 |
|---|---|---|---|---|---|
| Findings in Critical or High | 581 | 296 | **235** | 36 | 19 |

Moving the unresolved default of a single factor has the same effect. The table gives
the Critical/High count, of 986, at each value of each factor's default with the
others frozen:

| Default for | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| Absent severity | — | 82 | 88 | 92 | **235** | 244 |
| Exposure | 37 | 54 | 60 | **235** | 281 | 547 |
| Privilege | 231 | 231 | 233 | 233 | **235** | 235 |
| Sensitivity | 22 | 39 | 46 | **235** | 279 | 559 |
| Criticality | 22 | 22 | 39 | 46 | **235** | 279 |
| Encryption | 48 | 64 | **235** | 278 | — | — |

Bold marks the frozen value. **In five of the six rows, lowering the default by one
point removes between 61% and 80% of the Critical/High band.** With every default at
its minimum the band is empty; with every default at its maximum it holds 907
findings. Only the privilege default is immaterial, because after the correction of
Section 6.2 privilege is unresolved on only 6 findings.

The reason is visible in the scores. Of the 199 findings at exactly 16, 161 have one
shape: severity 4, privilege resolved to 0, and the other four contextual factors at
their defaults of 3, 3, 4 and 2. They are 16 because 4 + 3 + 0 + 3 + 4 + 2 is 16.
Change any one of those defaults and the whole group moves together.

**The band a finding lands in is, for most of the corpus, a statement about which
factors could not be resolved.** The clearest illustration is by platform: 231 of the
235 High findings are Terraform, and 547 of the 551 Kubernetes findings are Medium.
The two platforms differ in how often the encryption factor resolves — it is
unresolved on 333 of the 435 Terraform findings and on 1 of the 551 Kubernetes
findings — and that two-point default is what separates them.

Two smaller results belong here. The low-confidence threshold is as abrupt as the
band boundary: at thresholds of 1 to 5 the low-confidence count is 962, 890, 740, 210
and 2, because 530 findings have exactly three factors missing. And the Critical band
stays empty until its boundary is lowered from 22 to 20.

Because corpus v1 sets no expected band on any case, nothing in this evaluation
validates where a boundary should sit. The boundary and default sweeps show
how the distribution moves; they are not evidence that any position is correct.

### 6.7.3 The networking scenario across the exposure default

One scenario's tier separation rests on the exposure default, which is the only
default the rubric itself registers a sweep for. Across that sweep, from 2 to
5, the separation between the security group with a literal open CIDR and the rule
whose CIDR is a reference holds at 2, 3 and 4, and collapses into a shared top tier
at 5. It is never inverted in that range. Below it, the interpolated rule ties the
egress rule at 1 and falls beneath it at 0.

### 6.7.4 Auto-inference agreement

The framework's second mode replaces the declared-context input with values read from
conventions in the code itself. Criticality is read from an environment tag or label,
or a Kubernetes namespace. Sensitivity is read from a classification tag or label and,
only where none resolves, from a word in the resource's name. Three rules keep the
mode from reassuring falsely: only literal values are read; a name may raise a value
but never lower it; and criticality is never inferred at the top level, which the
rubric reserves for an explicit declaration. The conventions were registered as data,
together with the rules for measuring agreement, before the mode was run, on the same
evidence as Section 6.1.1.

**On this corpus the conventions resolve almost nothing.** Of the 81 resources that
carry a finding the framework makes a claim about, two take an inferred value — 3 of
the 986 findings. Both are sensitivity 5, from the word *secret* in the name of a
Kubernetes Role and of its binding. No tag, label or namespace resolved anything, and
no criticality value was inferred at all.

The reason lies in the corpus rather than in the mode. Where the vendored Terraform
tags a resource at all, it either builds the tags with an expression over a computed
prefix, which a literals-only reader does not evaluate, or carries only provenance
keys written by a tagging tool — a commit, a file, an author — none of which states
an environment or a classification. The Kubernetes manifests carry no environment or
classification label, and their namespaces are `default`, omitted, or an application's
own name. **Here the mode is the all-default model with two exceptions, and every
agreement figure below has to be read as that.**

Agreement is measured against corpus v1's declared values where a resource has exactly
one. Four resources that the declared-factor pairs deliberately declare two or three
ways have no single reference and are excluded.

| Factor | Resources compared | Resolved by a convention | Inferred equals declared | Inferred above declared | Inferred below declared |
|---|---|---|---|---|---|
| Sensitivity | 15 | 0 | 14 | 1 | 0 |
| Criticality | 16 | 0 | 1 | 15 | 0 |

**Every row is exactly what the rubric's defaults alone would give.** Sensitivity
agrees on 14 of 15 because corpus v1 declares most resources at 3, which is the
default. Criticality agrees on 1 of 16 because the default is 4 and the declarations
are mostly 3. Neither figure is evidence about the conventions, which resolved none of
these resources.

The direction of the error is the one finding here that favours the mode's design.
**No value in the inferred run is below its declared counterpart, and no finding scores
lower than in the declared run**: across the 986, 199 score higher, 787 the same and
none lower. Without a declared input the framework over-prioritises; it does not
under-prioritise. It does so by defaulting, though, not by inferring.

Ranking agreement between the two runs, as Kendall's τ_b over the 986 findings, is
0.754, and 891 keep their band. Most of that agreement is trivial: findings on
resources that corpus v1 never declares take the defaults in both runs. On the 204
findings whose resource is declared, 8 keep their score and 110 their band. Those 204
include the four excluded resources above, for which the corpus-level declared run
uses the last declaration in the ground truth — in each case the low side of a pair.

What the declared input was contributing is clearest from the oracle graded in both
modes by the same rules.

| | Declared context | Auto-inference |
|---|---|---|
| Pairs applicable in both modes | 6 | 6 |
| Of those, passed | 4 | 4 |
| Scenarios matched exactly, of 5 | 2 (storage, IAM) | 2 (IAM, compute) |
| Ordered case pairs right / tied / inverted, of 21 | 19 / 2 / 0 | 11 / 10 / 0 |
| Findings in High, of 986 | 235 | 326 |

Four of the ten pairs are not applicable in this mode: they put one resource under two
declarations, and the conventions give a resource one value. The other six behave
identically in both modes — the same four pass and the same two encryption pairs tie
— because none of them depended on declared context.

The scenarios show the cost. **Taking the declared input away turns eight correctly
ordered case pairs into ties.** The storage scenario, whose order was entirely
declared, collapses into a single tier, and so does the containers scenario. The
compute scenario moves the other way and matches exactly: with the one-point declared
criticality gone, scanner severity decides between the two contested cases, in the
author's favour. That is a coincidence of this scenario, not a merit of the mode.

**The conclusion is narrow and should stay narrow.** This evaluation shows that the
declared-context input does real ordering work, and that a convention-based substitute
cannot replace it on a corpus without literal tags. It does not show what the
substitute would do on an estate that tags its resources: the mode's mechanism is
established by tests on constructed resources, and this corpus gave it two names to
read.

## 6.8 What the scores rest on

The results above are easier to weigh with the composition of the scores in view.

| Factor | Resolved from evidence, of 986 | Values it takes | Most common value |
|---|---|---|---|
| Severity | 545 | 2, 3, 4, 5 | 4, on 633 |
| Exposure | 92 | 0, 1, 2, 3, 4 | 3, on 929 |
| Privilege | 980 | 0, 1, 4, 5 | 0, on 963 |
| Sensitivity | 198 | 1, 2, 3 | 3, on 921 |
| Criticality | 204 | 1, 2, 3, 4 | 4, on 790 |
| Encryption | 652 | 0, 2 | 0, on 616 |

**Every contextual factor is near-constant across the corpus.** Exposure contributes 3
to 94% of findings and privilege 0 to 98%. Sensitivity and criticality are resolved
for about a fifth: the 986 findings sit on 81 resources, and corpus v1 declares a
sensitivity for 14 of them. Only 24 of the 986 findings have all five contextual
factors resolved.

The consequence is a narrow score range. Scores run from 8 to 20 — twelve distinct
values of a possible twenty-eight — and 901 of the 986 findings fall between 12 and
16. **The framework discriminates sharply where its factors resolve and hardly at all
where they do not**, and on this corpus they mostly do not.

That is a statement about the corpus as much as about the framework. The mechanism
tests of Section 6.4.1 show the factors doing what they were designed to do on the
resources where they resolve. The corpus-wide figures show how seldom, on two
deliberately insecure teaching repositories with twenty declared resources, they get
the chance.

## 6.9 The claim against its falsification conditions

Section 4.2 stated, before the evaluation, four conditions under which the framework's
claim would fail. Each is answered here in its own terms.

**A contrastive pair does not move in the predicted direction.** Two of ten do not
move at all. By this condition the claim **fails for the encryption factor** and holds
for exposure, privilege, sensitivity and criticality, with the qualification that
three of the eight passes rest on hand-crafted cases and one of the two exposure
passes does not depend on exposure.

**The framework's scenario orderings diverge from the reviewed orderings more than the
baseline's.** They diverge less: 19 of 21 ordered case pairs correct against 4, and 2
exact matches against none. The condition is not met. The baseline's failure is that
it cannot separate cases — it ties 16 of the 21 — more than that it mis-orders them.

**The re-ranking cannot be explained by named factors.** It can, for every finding.
The condition is not met, but Section 6.6 shows the answer is narrower than it sounds:
for 432 of the 623 findings that change band, the named factor is a default.

**The alert reduction is attributable to deduplication alone.** It is not:
deduplication removes 39 findings and prioritization moves 414 out of Critical and
High. The condition is not met. The size of the second figure, however, is the least
robust number in this chapter.

**The evidence supports a narrower claim than the one the framework set out to make.**
It supports the claim that contextual enrichment separates findings that scanner
severity cannot — the baseline ties what the framework orders, in pairs and scenarios
alike, and that result survives every perturbation applied to it. It does not support
a claim about how many alerts a practitioner would be spared, because that number
depends on parameters this evaluation has no means of validating.

## 6.10 Limitations of this evaluation

The threats to validity of Section 4.7 all stand. The following are specific to the
results reported here.

**A defect was corrected after results were seen.** Section 6.2 gives both states.
The correction was to a reader, was independently measurable as a defect, and left
the mechanism results unchanged; it also moved the headline band figure
substantially, and a reader is entitled to weigh that.

**The band results rest on defaults.** Three quarters of the findings are
low-confidence, the High band is populated almost entirely by findings on its
boundary, and no result validates the boundary. The band-level figures of Sections 6.5
and 6.6 are properties of the frozen parameters as much as of the corpus.

**The Critical band is unexercised**, so nothing is known about the framework's
behaviour at the top of its range beyond constructed examples.

**The encryption factor is unevidenced** (Section 6.4.2), and one exposure pair is
confounded by severity (Section 6.7.1).

**The oracle has not been reviewed by a human expert**, and the reviewer shares a
model family with the framework's design reasoning (Section 4.7.1). Where the
framework and the author disagree, on the containers scenario, the framework agrees
with the reviewer.

**The comparison rule was fixed late.** How a case's findings become one rank was not
defined when the oracle was authored. It was fixed before any case-level score was
generated and the order is evidenced by the repository history, but it was fixed
after the scoring engine existed, and by the author.

**The sensitivity weightings are the author's.** Chapter 4 promises expert-derived
alternatives; the two tested were source-motivated and author-approved.

**Auto-inference was evaluated on a corpus that gives it almost nothing to read.** The
conventions resolved two resources of 81 (Section 6.7.4), so the agreement figures
describe the rubric's defaults far more than they describe the mode. How the mode
performs where tags are literal is untested. And an inferred value is recorded with
the same state as a declared one, so the low-confidence counts of the two modes are
not comparable as measures of evidence.

**The corpus is small and unrepresentative by design.** Twenty-six cases on two
teaching repositories support controlled validation of a mechanism. They do not
support an estimate of what the framework would do on a production estate.
