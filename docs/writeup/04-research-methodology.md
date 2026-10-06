# Chapter 4 — Research Methodology

## 4.1 Research approach

This study follows a **design-oriented** approach: a technical artifact is
constructed to address an identified problem, and the artifact is then evaluated
against the specific property it claims to improve. The artifact is the framework
described in Chapter 3; the property is **prioritization quality**.

Three methodological commitments follow from that framing, and each is defended in
this chapter:

1. **What is evaluated is prioritization, not detection.** Detection is delegated to
   the baseline scanners and is not re-implemented, so detection accuracy is not a
   claim this work makes and is not measured. The corresponding coverage metric asks
   a different question — what fraction of scanner findings the pipeline correctly
   normalizes and carries through.
2. **The evaluation is controlled artifact validation, not generalizable empirical
   proof.** The corpus is too small to support statistical inference across two
   platforms, three scanners and five resource domains, and this chapter states that
   bound rather than working around it.
3. **The model is fixed before it is evaluated.** Weights and thresholds are frozen
   a priori; their movement is reported afterwards as a sensitivity analysis. This is
   what answers the circularity objection, and Section 4.6 sets out the mechanism.

## 4.2 What would falsify the claim

Stating the failure conditions before the evaluation is what makes it a test rather
than a demonstration. The framework's claim is that contextual enrichment produces a
more useful remediation ordering than raw scanner severity. That claim fails if:

- a contrastive pair differing in exactly one contextual factor does **not** move in the predicted direction, which would show the factor does not drive the score as designed;
- the scenario orderings the framework produces diverge from independently reviewed expected orderings more than the baseline's do;
- the re-ranking cannot be explained by named factors, which would make the output unexplainable even if it happened to be agreeable;
- the reduction in alerts is attributable to deduplication alone, with prioritization contributing nothing.

Each of these maps onto a metric in Section 4.5, and the metrics are defined so that
a failure is visible rather than absorbed.

## 4.3 The evaluation corpus

Two corpora serve different purposes and should not be conflated.

**Corpus v0** is the vendored measurement corpus: TerraGoat at commit `729f8da6`
(its `terraform/aws` subtree) and Kubernetes-Goat at `723a0db4` (its `scenarios`
subtree), pinned in a lockfile. Its purpose is empirical rather than evaluative — it
produced the rule-identifier inventory of 1,055 findings from which the taxonomy's
255 rule mappings, the measured severity gap, and the deduplication figures of
Chapter 3 were derived.

**Corpus v1** is the evaluation corpus and its ground truth, authored against a
version-controlled schema. As committed it holds **26 cases — 21 drawn from the
vendored repositories and 5 hand-crafted — together with 10 contrastive pairs and 5
scenarios**, with no orphan cases (every case participates in at least one pair or
scenario). Domain coverage is storage 13, networking 4, IAM 3, compute 3 and
containers 3.

Cases are drawn from deliberately-insecure open-source repositories because those
repositories contain real, citable misconfigurations rather than invented ones. The
five hand-crafted cases exist to fill gaps the vendored corpus could not: three IAM
policies whose permission scopes nest strictly (bucket ⊂ account ⊂ unrestricted),
and two storage buckets differing by exactly one issue class. A contrastive pair
requires two configurations differing in exactly one factor, and a corpus assembled
from other people's examples cannot be relied upon to contain such pairs.

**The ground truth distinguishes two kinds of missing value, and the distinction is
load-bearing.** A finding may carry `defaulted_factors`, meaning a declared value
was absent from the declared-context input, or `unresolved_factors`, meaning the
extractor could not resolve a code-derived factor. These are separate fields because
they are reported as separate rates, and merging them — which would be the natural
simplification — makes that report impossible to reconstruct afterwards.

A per-finding flag, `excluded_from_quality_claims`, marks findings that must not
contribute to prioritization-quality figures. Three findings carry it, across two
cases: one security-group rule whose CIDR block is an interpolation rather than a
literal, and two findings on an EBS volume whose declared sensitivity is absent and
explicitly defaulted.

### 4.3.1 Two coverage numbers that are never averaged

The corpus reports its contribution as two figures, kept separate because averaging
them would conceal which part of the evaluation rests on excluded data:

- **Contrastive pairs: 10 authored, 10 contributing.** No pair touches a case carrying an excluded finding, so the pair evidence is unaffected by the exclusions.
- **Scenarios: 5 authored, 3 free of excluded findings.** The networking scenario contains the interpolated security-group rule and the compute scenario contains the defaulted EBS volume; both therefore contribute only partially.

## 4.4 The oracle — judging "better" without circularity

The central methodological risk is circularity. If the author of the scoring rubric
also sets the expected orderings against which the rubric is judged, the evaluation
measures nothing but the author's consistency with themselves. Four controls address
this.

### 4.4.1 Mechanism tests, separated from usefulness tests

**Contrastive pairs are mechanism tests.** Each pair consists of two configurations
of the same resource type whose issue-class sets differ in exactly one factor's
worth of content, with a recorded expected rank direction and expected score-delta
sign. A pair establishes that a factor *causes* a rank change. It does not establish
that the resulting ranking is useful, and no causal-validity claim is made beyond
the controlled pairs.

**Scenario-expected orderings are usefulness tests.** Each scenario is a domain-level
set of cases with an expected ordering expressed as tiers, so that a genuine tie can
be stated as a tie rather than forced into an arbitrary sequence. The containers
scenario contains such a tie deliberately.

The two are reported separately. Collapsing them would let strong mechanism results
stand in for usefulness results, which they cannot.

### 4.4.2 Pre-registration

Scenario rationales and expected orderings are registered **before any scoring
output exists**, with a registration date recorded in the ground truth. There is
consequently no path by which an ordering could be adjusted to match a score the
framework produced, because the scoring engine did not exist when the orderings were
written.

### 4.4.3 Blinding by construction

The expected orderings received an independent review from a blinded reviewer. The
blinding was enforced **by construction rather than by instruction**: the reviewer
was given purpose-built inputs — a case file stripped of all orderings, and a rubric
file stripped of both the priority bands and the citation strings that had not yet
been audited. A reviewer asked to ignore information it can see is not blinded; a
reviewer that was never given the information is.

**The resolution rule was pre-registered**: the author's ordering stands as ground
truth regardless of the reviewer's verdict, and any scenario the reviewer marked
`disagree` would be excluded from the headline figure and reported separately. Fixing
this rule in advance prevents the reviewer's verdict from being used selectively
after the fact.

### 4.4.4 Measured agreement, reported as a number rather than a claim

The review produced **3 `agree` verdicts, 2 `partial`, and 0 `disagree`** —
exact-tier agreement on 3 of 5 scenarios. Per-scenario rank correlation (Kendall's
τ_b) was storage 1.000, networking 1.000, IAM 1.000, compute 0.333 and containers
0.500. Because no scenario was marked `disagree`, all five contribute to the
headline figure under the pre-registered rule, two of them only partially.

**One scenario is contested, and the contest is reported rather than resolved.** In
the compute scenario the blinded reviewer's ordering is better grounded than the
author's: the reviewer read the IAM privilege factor directly from the source
configuration, which the author's ordering did not. Under the pre-registered rule
the author's ordering nonetheless stands. Re-authoring it would require a fresh
blinded review, because a reviewer who has already seen the orderings cannot review
their replacement blind — so the defect is documented rather than patched.

## 4.5 Metrics

Five metrics are reported. Three of them are deliberately split into two numbers
each, and in every case the split exists because the combined figure would be
misleading rather than merely less informative.

| Metric | What it measures | Reporting discipline |
|---|---|---|
| Normalization / retention coverage | Fraction of scanner findings correctly normalized and carried through | Explicitly *not* detection accuracy, which is delegated to the scanners |
| Prioritization usefulness | Contrastive-pair pass/fail, and scenario-expected ordering, against the pre-registered oracle | Mechanism and usefulness reported separately |
| Alert reduction | Reduction from deduplication, and reduction in Critical/High band count from prioritization | **Two numbers, never combined into one headline** |
| Ranking consistency | Auto-inference agreement with the declared-context ranking, and model stability under threshold and weight perturbation | **Two distinct measures, never averaged** — one tests heuristic quality, the other robustness |
| Baseline comparison | Rank-change table against the severity-normalized baseline | Every change justified by named contextual factors |

Two further reporting rules apply across all five.

**`unmapped:` findings are reported separately and excluded from
prioritization-quality claims.** Scored on severity alone, a serious but unmapped
finding would rank artificially low, so including it would depress the quality
figure for a reason unrelated to the model's merit. Its count and rate are reported
as a coverage limitation instead.

**The baseline must be normalized before it can be compared.** Raw scanner severity
is the baseline, but native severities are not equivalent across the three tools,
and Checkov contributes no severity at all in this corpus. The comparison therefore
runs against a documented, version-controlled per-scanner normalization table rather
than against raw labels, since a comparison against un-normalized severities would
measure tool convention as much as prioritization.

### 4.5.1 How the framework's output is compared with the oracle

The ground truth fixes which ordering is expected. It does not fix how a case's several
findings become the one rank that is compared with that ordering, and when the oracle
was authored that rule was undefined.

It was fixed afterwards, but before any case-level score had been generated: **a case
ranks where its highest-scoring finding ranks**, a contrastive pair passes only when
the high case scores strictly above the low one, and a scenario is compared as tiers.
Section 6.1.1 states the full set of eight rules. They were committed together with
the evaluation harness, and the repository's history shows that commit preceding the
one that first produced per-case scores; a test asserts the ancestry rather than
leaving it to be taken on trust.

The sum and the mean of a case's finding scores are reported beside the registered
rule, as a check on how far the results depend on it. They are not alternatives to it.

## 4.6 The freeze, and sensitivity analysis as a reported experiment

The six factor ranges, the 1–28 score bounds and the four band boundaries were
**fixed before any scoring output existed** and are pinned by tests. The freeze is
verifiable rather than asserted: it was computed from the score structure and
committed in advance, and the structural properties are enforced by the test suite
rather than by convention.

Afterwards, threshold and weight movement is reported as a **sensitivity analysis:
an experiment showing how the priority distribution shifts as the model's parameters
move, not a search for parameters that produce agreeable results.** The distinction
is the whole of the defence against the overfitting objection, and it depends
entirely on the ordering — a sensitivity analysis run before the freeze would be
indistinguishable from tuning.

Two elements of the analysis are worth naming specifically. First, **equal weighting
is tested against plausible expert-derived alternative weightings**, not only against
threshold moves; equal weights are a declared neutral baseline, not a claim that the
six factors matter equally, and the analysis is where that declaration is put under
pressure. Second, because the band boundaries are positioned against the score
ceiling, any change to a factor range in the analysis requires the boundaries to be
recomputed rather than held fixed.

**What was registered, and where it falls short of the paragraph above.** The analysis
was specified as a plan of 63 variants, approved, and committed before any variant was
computed; Section 6.7 reports all of them. It sweeps each factor's unresolved default
across its whole range, the three band boundaries, the weight of each factor, and the
threshold at which a finding is called low-confidence. Two of the variants are named
weightings — one emphasising exposure and privilege, the other sensitivity and
criticality — motivated by the likelihood and impact axes of sources the rubric
already cites. They were proposed and approved within the project. **They are not
independently expert-derived**, and to that extent the first commitment above is
unmet; weightings supplied by an independent expert would be a second registered round.

The second commitment was met by reporting less rather than by recomputing. A weighted
sum has a different ceiling from the unweighted one, and rescaling the band boundaries
to fit it would define a new model. The weighted variants therefore report no bands at
all and are judged on ordering alone.

A procedural rule accompanies the freeze. The rubric's structure is frozen, but its
citation strings are separately auditable and were in fact corrected after the
freeze. Those corrections were applied under a **mechanical guarantee**: the document
was hashed with every citation string blanked, edited, and re-hashed, and the edit
was permitted only because the two hashes matched. This is stronger than a reviewer
reading a diff, and it is the method by which a frozen artifact can be corrected
without weakening the freeze.

## 4.7 Threats to validity

The threats below are the ones the evaluation cannot eliminate. Each is stated with
what it would take to bound it, because a threat named without a remedy reads as a
disclaimer rather than an analysis.

### 4.7.1 The oracle and the scoring model share a model family

**This is the most serious threat, and it cannot be measured from inside the
project.** The blinded reviewer and the framework's design reasoning draw on the same
model family. Correlated blind spots are therefore possible — a shared tendency to
read ambiguous rubric language the same way, for instance — and there is no
independent instrument available inside the project to compare against, since
introducing a second automated reviewer would reproduce the same problem.

The consequence is specific: the agreement figures in Section 4.4.4 may overstate
how well an independent human expert would agree with the framework's orderings, and
nothing in the data would signal that this is happening. **The figures therefore
support a claim of internal consistency, not of external validity.** A supervisor
review of a sample by a human domain expert would bound this threat; it has not been
carried out, and the agreement figures should not be presented as validating
anything beyond internal consistency until it has.

### 4.7.2 Severity has no contrastive pair, by measurement rather than oversight

Five of the six factors have two contrastive pairs each — exposure, encryption,
sensitivity, criticality and privilege. **Severity has none, and this is a measured
result rather than a gap left unfilled.** An exhaustive enumeration over the corpus
considered 249 same-type resource pairs, of which 129 had identical issue-class sets
and 120 differed; **zero** pairs shared an identical issue-class set while differing
in maximum severity.

The reason is structural. A rule's severity is fixed, so two resources differing in
severity within one issue class implies that a *different rule* fired — which changes
the class set as well, and so fails the single-factor isolation requirement. Checkov
additionally contributes no integer severity at all in this corpus. The ground truth
asserts the zero directly rather than leaving it as an absence that a later reader
might "fix" with a pair that isolates nothing.

### 4.7.3 Single-factor purity is an authored judgement, not machine-proven

A pair's claim to isolate one factor rests on the author's reading of what the
differing issue classes mean. **No class-to-factor mapping exists anywhere in the
data**, so nothing verifies the claim mechanically. A supporting tool makes each
pair's class difference explicit and re-derivable, which is what allows the judgement
to be checked — but it does not establish that the named factor is the correct one.

Two concrete near-misses show this is a live risk rather than a theoretical one.
Both `iam-authentication-controls` and `networking-egress-exposure` read as evidence
for a factor of the same name and are not; both were caught only by inspection. The
generalisation is worth stating as a rule for anyone extending the corpus: **a class
named for a factor is not evidence of that factor.**

### 4.7.4 Corpus size bounds the claim

With 26 cases across two platforms, three scanners and five domains, no statistical
inference is available. The evaluation is controlled artifact validation, and the
write-up makes no significance claims. Per-category coverage counts are reported so
that a reader can see exactly how thin each domain is — storage at 13 cases is
comparatively well covered; IAM, compute and containers at 3 each are not.

### 4.7.5 Known limits carried forward from the artifact

Four limits established in Chapter 3 constrain what the evaluation can report, and
are repeated here because each would otherwise be mistaken for an evaluation result:

- **The deduplication figure is Tier 1 only** — 3.7% of findings — and Tier 2's 91 same-scanner candidates are a limit of the fingerprinting method, not evidence of scanner overlap. The same-scanner figure belongs in the limitations discussion and never in the alert-reduction result.
- **Cross-scanner attribute normalization is unattempted**, and would materially raise the measured deduplication figure. The reported number is a floor.
- **Fourteen of the twenty-eight taxonomy classes map to no contextual factor** (Section 3.10), so findings in those classes score on severity and declared context alone. Ten of the fourteen name a risk the model has no term for, and they cover 242 of the 986 findings the evaluation ranks (24.5%). An earlier draft of this bullet reported three classes and said no systematic sweep had been run; the sweep has since been run.
- **The citation audit is incomplete.** 69 of the rubric's 86 citation claims are verified and 6 were corrected, but the 11 NSA-CISA claims remain unverified because the primary source is unreachable from the build host. No rubric citation resting on NSA-CISA is quoted in this dissertation.

One reporting-integrity caveat belongs here too, because it concerns a metric rather
than the artifact. In the retention-coverage report, the count of findings entering a
scanner adapter is **derived** as findings-out plus findings-dropped, rather than
measured as an independent count of raw records. The retention tests close the gap by
counting raw records from the fixtures independently, so the reported coverage figure
is checked; the field itself remains derived, and plumbing a measured raw-record
count through the adapters is recorded as outstanding work.

## 4.8 Reproducibility

Every input to the evaluation is version-controlled and pinned.

- **Scanner versions** are pinned by lockfile with SHA-256 digests: Checkov 3.3.12, Trivy 0.74.0, tfsec 1.28.14. The platform–scanner applicability matrix is data in that same lockfile rather than logic in the code.
- **Corpus commits** are pinned: TerraGoat `729f8da6`, Kubernetes-Goat `723a0db4`.
- **The Python interpreter** is pinned to 3.12 by the upper bound of Checkov's declared support.
- **Golden scanner outputs** are captured as fixtures, and the comparison against them is order-insensitive by design, because the scanners reorder list elements between runs and one of them stamps a fresh timestamp and report identifier. A byte comparison would fail on every re-run for reasons unrelated to correctness; the derived inventory reproduces identical figures.
- **The specification artifacts** — taxonomy, rubric, severity-normalization table, ground-truth schema and validator, and the canonical-identity module — are committed, and the ground-truth validator **rejects a malformed case rather than skipping it**, so a case cannot silently drop out of the evaluation.

A limitation of the reproducibility story should be stated plainly. **The oracle
protocol is not auditable from the repository.** The blinded reviewer's inputs were
purpose-built and are committed, but the review transcript itself is not, so the
verdicts and the disagreement notes are recorded in the ground truth on the author's
report rather than being independently verifiable from the repository. Committing the
transcript would close this.
