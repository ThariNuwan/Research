# Chapter 7 — Conclusion

## 7.1 What was set out, and what was built

This dissertation began from an observation about the output of rule-based IaC
scanners: they detect misconfigurations competently and say little about which to fix
first. A finding arrives with a severity label and no statement of whether the affected
resource is reachable, what authority it confers, what data it holds or which
environment it serves. The work proposed that a transparent prioritization layer,
placed on top of existing scanners and replacing none of them, could order their
findings more usefully than severity alone.

What was built is that layer, as a five-layer pipeline (Chapters 3 and 5). It discovers
Terraform and Kubernetes files; runs three scanners and normalizes their output into
one finding record, mapped to a 28-class taxonomy and conservatively deduplicated;
attaches five contextual factors to each finding, three read from the code and two
declared; computes an equal-weighted additive score from 1 to 28 in which every point
is attributable to a named factor; and reports a ranked list in four priority bands.

Around the layer was built what its claim needed in order to be tested instead of
demonstrated (Chapter 4): a rubric whose levels are anchored to published sources, an
evaluation corpus whose expected orderings were registered before any score existed, a
harness that shares no code with what it grades, a sensitivity analysis whose 63
variants were registered before any was computed, and a second mode that infers the two
declared factors from conventions in the code.

The model was frozen before it was evaluated and was not adjusted afterwards. One
defect in the implementation was corrected after the first results had been seen, and
Section 6.2 reports both states.

## 7.2 The research questions and objectives

The proposal for this work posed five research questions and set six objectives. They
are answered here in the proposal's own words, each to the extent the evidence allows
and no further. Section 7.3 then states the conclusions that these answers rest on.

### 7.2.1 The research questions

**RQ1. What are the common security misconfiguration patterns found in cloud
Infrastructure-as-Code environments?** *Answered for the corpus studied, not for the
field.* The 255 rule identifiers that three scanners raised reduce to 28 classes of
misconfiguration in five categories (Section 3.3). On the corpus, container workloads
account for 55.5% of the ranked findings and storage for 29.6%; networking, IAM and
compute are each under 7%. Eight classes make up 69.4% of the total: privileged
container execution, missing security-context hardening, absent resource limits, excess
Linux capabilities, publicly accessible data stores, gaps in backup and deletion
protection, missing encryption at rest, and unverified image provenance (Section
6.3.1). These are the patterns the literature of Chapter 2 also names. But the corpus
is two repositories written to be insecure, so the frequencies describe those
repositories. This work did not study how common each pattern is in production code.

**RQ2. What limitations exist in conventional rule-based IaC security scanners when
used for remediation prioritization?** *Answered, by measurement.* Four limitations were
measured on the scanners' own output. Severity is often absent: 489 of 1,055 findings
carry none (Section 6.3). Severity is not comparable between scanners, which use
different vocabularies and need a normalization table before they can be merged
(Section 3.5). Severity is too coarse to order by: alone, it ties 16 of the 21 scenario
case pairs and nine of the ten contrastive pairs (Section 6.4). And the same problem is
reported repeatedly: 39 findings are exact duplicates and a further 207 are candidate
overlaps (Section 3.7). Beyond these, no scanner's output says whether the resource is
reachable, what authority it confers, what data it holds or which environment it
serves, which is the gap the framework was built to fill.

**RQ3. Which contextual cloud security factors are most useful for prioritizing IaC
security findings?** *Answered in part.* On this corpus the factors that did the
ordering were declared sensitivity and criticality, which alone decided nine of the
nineteen correctly ordered scenario pairs, and privilege and exposure wherever they
could be read from the code. Encryption contributed nothing (Sections 6.4.2 and 6.4.3).
The factor-removal experiment gives the same picture: removing privilege, sensitivity
or criticality from the model loses both of that factor's pairs, removing exposure
loses one, and removing encryption loses none (Section 6.7.1). Two cautions limit the
answer. A factor is useful only where it resolves, and exposure resolved on 92 of the
986 findings and sensitivity on 198 (Section 6.8). And the showing of the two declared
factors is partly by construction (conclusion 2 below). The evidence does not support a
general ranking of the six factors by usefulness.

**RQ4. How can a risk-aware scoring model improve the practical usefulness of IaC
scanner outputs?** *Answered as a mechanism; practical usefulness was not measured.*
The model improves the output in three ways that the evaluation demonstrates. It
separates findings that severity leaves tied. It attributes every point of every score
to a named factor, so that a ranking can be questioned. And it states what it does not
know, marking each value that is a default instead of evidence. What was not shown is
that engineers working from the framework's ordering remediate better than engineers
working from a scanner's. No study with practitioners was carried out, usefulness was
measured against an oracle that no human expert reviewed (Section 4.7.1), and the
priority bands, which are the output a practitioner would act on, are not yet reliable
(conclusion 4 below).

**RQ5. How does the proposed prioritization approach compare with conventional scanner
severity outputs?** *Answered.* The framework passes 8 of the 10 contrastive pairs
against severity's 1, matches 2 of the 5 scenarios exactly against none, and orders 19
of the 21 scenario case pairs correctly against 4 (Section 6.4). Of the 986
context-eligible findings it places 196 in a higher band than severity does, 427 in a
lower one and 363 in the same (Section 6.6). Conclusions 2 and 6 below qualify the
comparison: much of the framework's advantage comes from declared context, and much of
the baseline is itself a default.

### 7.2.2 The objectives

| Objective, as set in the proposal | Outcome |
|---|---|
| 1. Investigate common security misconfigurations and policy violations in cloud IaC environments | **Met for the corpus and through the literature.** Not a study of prevalence (RQ1). |
| 2. Analyze the limitations of existing rule-based IaC security scanning approaches | **Met**, by measurement on three scanners (RQ2). |
| 3. Identify contextual risk factors relevant to IaC security prioritization | **Met.** Six factors, each level anchored to a published source (Section 3.8). Two shortfalls: eleven citation claims remain unverified, and fourteen of the twenty-eight classes name a risk that no factor represents (Section 3.10). |
| 4. Design a framework that enriches scanner findings with contextual cloud security attributes | **Met** (Chapters 3 and 5). |
| 5. Develop a transparent risk-scoring approach to classify findings into Critical, High, Medium and Low | **Met in part.** The scoring is transparent and every score is explained. The classification is not validated: no finding reaches Critical, and the band counts change several-fold with a one-point change in one parameter (Section 6.7.2). |
| 6. Evaluate the framework using representative Terraform and Kubernetes examples and compare its output with conventional scanner severity | **Met, within stated bounds.** A controlled validation on a small corpus, not a generalizable result (Section 4.1). |

### 7.2.3 Where the work departed from the proposal

A reader comparing this dissertation with its proposal will find five differences. Each
is recorded here so that none has to be inferred.

**The thresholds were frozen, not adjusted.** The proposal allowed the band thresholds
to be adjusted during evaluation in the light of observed behaviour and supervisor
feedback. They were instead fixed before any score existed, and how the results move
when they are changed is reported as a sensitivity analysis (Section 4.6). Adjusting
them after seeing results would have made the evaluation circular.

**"Detection coverage" is reported as normalization and retention coverage.** The
quantity is the one the proposal defined, the share of scanner findings the framework
processes. It was renamed because the framework detects nothing itself, and the
original name invites a reading as detection accuracy (Section 4.5).

**Prioritization usefulness was judged against a registered oracle, not by manual
review.** The proposal planned a manual review of the ranked output against defined
risk criteria. The work instead registered contrastive pairs and scenario orderings
before any score existed and had them reviewed blind by an automated reviewer (Section
4.4). This is more reproducible than a manual review and lacks what one would have
supplied: a human expert's judgement. The supervisor review that was planned was not
carried out.

**Ranking consistency was given two definite meanings.** The proposal described it as a
review of repeated or similar test cases. It was measured as the stability of the
results under registered changes to the model, and as the agreement between the
declared-context mode and the inferred one (Section 6.7).

**Context is extracted and declared, not annotated.** The proposal expected contextual
attributes to be annotated manually or semi-automatically for each finding. Three are
extracted automatically from the code. Two are declared once per resource, and a second
mode infers those two from conventions.

## 7.3 Conclusions

Chapter 4 stated the claim under test — that contextual enrichment produces a more
useful remediation ordering than raw scanner severity — together with four conditions
under which it would fail, and Section 6.9 answered each condition in its own terms.
The conclusions below are narrower than the claim. Each is stated at the strength the
evidence supports and no further.

**1. Context separates findings that scanner severity cannot.** The baseline's failure
in this evaluation is less that it orders cases wrongly than that it cannot tell them
apart: it ties 16 of the 21 scenario case pairs the oracle places in an order, and nine
of the ten contrastive pairs. The framework orders 19 of the 21 correctly, ties 2 and
inverts none, and passes 8 of the 10 pairs against the baseline's 1 (Sections 6.4.1 and
6.4.3). These ordering results are stable. Across the 63 registered variants of the
model the pair result is unchanged in 59, and it moves only when the factor a pair
tests is removed altogether (Section 6.7.1).

**2. Most of that separation comes from context that was declared, not derived.** Four
of the eight passing pairs put one resource under two declarations and so pass by
construction. Nine of the nineteen correctly ordered scenario pairs are decided by
declared sensitivity and criticality alone, and three more are on hand-crafted cases.
Of the seven that remain, two are ordered by a contextual value read from the code on
both sides, and no pair mined from third-party code passes because of something the
framework extracted (Sections 6.4.1, 6.4.3 and 6.9). What is shown securely is
therefore this: the framework carries a stated business context into a ranking
faithfully and visibly, which an ordering by severity cannot do at all. What is not
shown is that it can discover a discriminating context in infrastructure code by
itself. The second mode confirms the point from the other side. On this corpus its
conventions resolved two of 81 resources, and taking the declarations away turned nine
correctly ordered pairs into ties (Section 6.7.4).

**3. Two of the three code-derived factors behave as designed where they resolve, and
the third is not shown to work.** Privilege orders the three hand-crafted IAM policies
as their breadth predicts, and exposure separates an open security group from a closed
one and a public bucket from a private one. The encryption factor fails its mechanism
test: both of its pairs tie at 15, and removing the factor from the model changes no
pair and no scenario (Sections 6.4.2 and 6.7.1). The cause is two design decisions that
are each defensible — reading literals only, and declining to treat an absent
encryption block as proof of an unencrypted resource — and that together leave the
factor unable to separate the one case the corpus offers it.

**4. The band a finding lands in is not yet a reliable output.** Critical and High
together fall from 649 findings to 235, or 63.8%, over the 986 context-eligible
findings, and from 192 to 35, or 81.8%, over the 246 that are not low-confidence
(Section 6.5). Neither figure survives a one-point move of the High boundary, which
leaves 36 findings in the band or 296, because 199 of the 235 High findings score
exactly on that boundary (Section 6.7.2). No finding reaches Critical: the highest
score in the corpus is 20 against a boundary of 22. And because the evaluation corpus
sets no expected band on any case, nothing in this work validates where a boundary
should sit. **This dissertation therefore makes no claim about how many alerts a
practitioner would be spared.**

**5. The rule that a missing value must never read as low has a cost the design did not
anticipate.** Where a factor resolves, it usually resolves below its default. Privilege
is resolved on 980 of the 986 findings and is 0 on 963 of them, against a default of 4;
encryption is 0 on 616, against a default of 2 (Section 6.8); and with the declared
context removed 199 findings scored higher and none lower (Section 6.7.4). So an
unresolved finding outranks a resolved one of the same underlying risk, and the
distribution is compressed into the middle: 747 of the 986 findings are Medium, and 740
are low-confidence (Section 6.5). For most of
the corpus the band is a statement about which factors could not be resolved. The
re-ranking is fully explainable, in that every point is attributable to a named factor,
but for 432 of the 623 findings that change band the factor named is a default (Section
6.6). **Explainability and evidence are different properties, and the framework has the
first more securely than the second.**

**6. The baseline deserves as much scrutiny as the method compared with it.** Of the
1,055 findings the three scanners report, 489 (46.4%) arrive with no severity at all,
every one of them from Checkov, and 441 of the baseline's 649 Critical or High findings
reach that band through a default (Sections 6.3 and 6.5). In a multi-scanner setting a
comparison against "scanner severity" is partly a comparison against a normalization
choice, and a reported improvement over it should say how much of the baseline was a
scanner's judgement.

**7. A check that builds both sides of a comparison cannot find that the real sides
differ.** This is a conclusion about method, and the project met it four times. Three
defects in the implementation passed a green test suite and were found only by
measuring over the real corpus: one left none of the 217 findings on container-scoped
resources matched to their manifests, one left 311 of 579 Kubernetes findings with
their code-derived factors on defaults, and one made 66 tests fail on any machine but
the one the scanner output was captured on (Section 5.9.2). The evaluation's own acceptance tests then showed the same
flaw, re-deriving figures from the records they were meant to check, and were rewritten
to recompute them by a second route (Section 5.9.1). The corresponding positive result
is that the live path, exercised as a whole only after the evaluation, returns the
recorded corpus scores finding for finding (Section 5.11).

## 7.4 Contributions

Stated at the strength of the conclusions above, this work contributes the following.

1. **An explainable prioritization layer over existing scanners.** A working artifact
   that runs three scanners over a folder and ranks what they find, in which every
   score decomposes into six named contributions and every value that is a default is
   marked as one. Its transparency is the property the evaluation supports most
   securely.
2. **Two specification artifacts that stand apart from the code.** A taxonomy of 28
   issue classes that maps all 255 rule identifiers observed across the three scanners
   onto one vocabulary (Section 3.3), and a scoring rubric whose levels cite published
   sources, with the audit of those citations reported: of 86 citation claims, 69 were
   verified, 6 were found defective and corrected, and 11 remain unverified (Section
   3.8).
3. **A method for evaluating prioritization without incident data.** Contrastive pairs
   that isolate one factor, scenario orderings with a blinded review, rules and plans
   registered before results and evidenced by the repository's history, a harness
   independent of the artifact, a baseline graded by the same rules, and a registered
   sensitivity analysis. The method is reusable for any scoring model of this kind, and
   its weaknesses are documented alongside it.
4. **Measured observations about scanner output.** That nearly half of the findings on
   this corpus carry no severity; that exact cross-finding duplication is low, at 39 of
   1,055 (3.7%), while a further 207 candidate overlaps cannot be merged safely without
   normalizing the scanners' attribute vocabularies (Section 3.7); and that fourteen of
   the twenty-eight issue classes name a risk no contextual factor represents (Section
   3.10).
5. **Negative results, reported as results.** That one factor fails its mechanism test,
   that the band counts are unstable, that most of the ordering evidence is declared,
   and that convention-based inference resolves almost nothing on a corpus without
   literal tags. Each bounds what a later study may assume.

## 7.5 Limitations

Sections 4.7 and 6.10 set out the threats to validity in full. The ones that most
restrict what may be concluded are these.

**The corpus is small and unrepresentative by design.** Twenty-six cases — twenty-one
drawn from two deliberately insecure teaching repositories and five written by hand —
support controlled validation of a mechanism. They do not support an estimate of how
the framework would behave on a production estate.

**The oracle was not reviewed by a human expert.** The expected orderings were authored
by the framework's author and reviewed by an automated reviewer that shares a model
family with the design reasoning. The supervisor review the plan called for was not
carried out. The declared context values and the expected orderings also have one
author. The agreement figures are therefore evidence of internal consistency and not of
external validity (Section 4.7.1).

**The top of the range is unexercised.** No finding reaches Critical, so the
framework's behaviour there is known only from constructed examples.

**Extraction is deliberately shallow.** Values are read as literals only; privilege is
not followed from an instance to its role and that role's policies; exposure is
resolved for a closed list of patterns and is a default elsewhere (Sections 3.6 and
5.11).

**The model's own parameters are unvalidated.** The equal weighting is a declared
neutral baseline, the two alternative weightings tested were proposed and approved
within the project instead of being derived by an independent expert, and no result
validates a band boundary or a default.

**Part of the rubric's sourcing is unverified.** Eleven citation claims rest on one
document that could not be obtained for audit, and none of them is quoted in this
dissertation.

**One correction was made after results were seen**, and the checks on the evaluation
records were strengthened after the results were known. Sections 6.1 and 6.2 give the
record of both.

## 7.6 Implications for practice

The corpus limits how far these generalize, and they are offered as what the evaluation
suggests, not what it establishes.

**Declaring context is cheap, and here it did about half the work.** Two numbers per
resource — how sensitive its data is, and how critical its environment — decided nine
of the nineteen correctly ordered scenario pairs with nothing read from the code at
all, at a fraction of the engineering cost of extraction. An organization that already
classifies its data and labels its environments holds an input a prioritization layer
can use directly.

**A ranking should show which of its inputs are defaults.** A conservative default is
the right response to a value that cannot be read, but it looks exactly like evidence
unless it is marked. On this corpus three quarters of the findings were scored mostly
on defaults, and a ranking that hid that would have overstated what was known.

**Band thresholds and alert-reduction percentages should not be adopted without local
calibration.** Both proved sensitive to a single point in a single parameter. A team
adopting a scheme of this kind should set its boundaries against cases it has labelled
itself, and should distrust a reduction figure reported without the baseline's own
coverage.

**Scanner severity is a weaker reference than it appears** wherever several scanners
are combined, because one of them may supply none.

## 7.7 Future work

The directions below are ordered by how directly the evaluation showed them to matter.

1. **Validate the oracle and the corpus.** A review of the expected orderings by human
   domain experts, and a corpus drawn from realistic estates that tag their resources,
   use modules and carry production-like configuration. Recording an expected band for
   each case would allow the boundaries and defaults to be calibrated instead of only
   swept.
2. **Make the encryption factor discriminate.** Resolving references within a
   configuration, so that a key named by reference is read; and representing the
   platform's account-level default as declared context, so that an absent block has a
   known meaning.
3. **Extract more deeply.** Following privilege across resources, from an instance to
   its profile, role and policies; resolving variables and modules; rendering Helm
   templates; and widening the exposure patterns beyond the closed list.
4. **Revisit how unresolved values are scored.** The evaluation showed the cost of a
   single conservative point value. Alternatives include ranking resolved and
   unresolved findings separately, scoring an unresolved factor as an interval, or
   calibrating each default against the values the factor takes when it resolves.
5. **Close the factor-coverage gap.** Fourteen issue classes name a risk no factor
   represents, among them unrestricted egress and host-level access from a container.
   Whether to widen the factor set, and at what cost to the model's simplicity, is an
   open design question.
6. **Normalize across scanners.** A mapping from each scanner's attribute vocabulary to
   one spelling would let many of the 207 candidate duplicates be merged, and a
   principled treatment of findings that carry no severity would strengthen the
   baseline.
7. **Extend the tool.** Folders that mix platforms, further IaC formats, a build gate
   on the top band, and an HTML report.
8. **Study usefulness with practitioners.** Whether engineers given the framework's
   ordering remediate differently, or better, than engineers given a scanner's is the
   question this work's claim finally depends on, and it cannot be answered from
   inside the project.

Beyond these lie the directions Section 3.11 placed out of scope: runtime detection,
multi-cloud production repositories, and learning-based scoring. The last would need
labelled outcomes that this work does not have, and the transparent model here could
serve as the baseline it would have to beat.

## 7.8 Closing remark

The framework set out to show that context could order scanner findings better than
severity. It showed that a stated context can — transparently, and stably under every
perturbation applied — and that on this corpus very little of the context that mattered
could be read from the code itself. Its more durable results may be the things it made
visible on the way: how much of a scanner-derived ranking is a default, how sensitive a
priority band is to where its boundary is drawn, and how readily an evaluation can pass
for the wrong reasons unless it is built so that it can fail.
