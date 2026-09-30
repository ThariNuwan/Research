# Chapter 3 — Framework Design

## 3.1 Design intent and the form of the contribution

This is design-oriented research. The deliverable is a technical artifact — a
framework — together with an evaluation of the property it claims to improve.
Working code alone would not constitute the contribution, and neither would an
evaluation of code whose design decisions could not be traced to the research
questions.

The framework's contribution is a **prioritization layer**, not a detector. Rule-based
IaC scanners already detect misconfigurations competently; what they do not do is
tell an engineer which of several hundred findings to fix first. Each finding
arrives carrying a severity label and little else: no statement of whether the
affected resource is reachable from the internet, what data it holds, which
environment it serves, or how much authority it confers. Consequently a
publicly-readable production bucket holding customer records is presented in the
same flat list, and often with the same severity label, as a missing resource tag
in a sandbox.

Three properties of that gap shaped the design:

1. **Severity is not comparable across tools.** Checkov, tfsec and Trivy assign
   severity by different conventions, so a naive merge of their outputs produces a
   ranking that reflects tool provenance as much as risk.
2. **The same underlying problem is reported repeatedly.** Multiple scanners flag
   one resource, inflating the apparent alert count and, with it, any claimed
   reduction in that count.
3. **The context that determines business risk is partly absent from the code.**
   Some of it can be parsed from the IaC source; some of it — the sensitivity of
   the data and the criticality of the environment — provably cannot.

The design therefore separates detection from prioritization and treats the
prioritization layer as independently evaluable. This separation is not merely
architectural tidiness: it is what allows the evaluation in Chapter 4 to measure
prioritization quality without having to establish detection accuracy, which is
delegated to the baseline scanners and is not a claim this work makes.

## 3.2 Architecture — a five-layer pipeline

The framework is a pipeline of five layers with an evaluation harness deliberately
placed outside it.

| # | Layer | Responsibility |
|---|---|---|
| 1 | IaC Input | Discover and classify Terraform (HCL) and Kubernetes YAML inputs |
| 2 | Security Scanning | Invoke the pinned scanners; parse each tool's JSON into one normalized finding record |
| 3 | Context Extraction | Attach the five contextual attributes to each finding |
| 4 | Risk Scoring | Apply the explainable weighted-additive model |
| 5 | Reporting | Rank findings, map scores to priority bands, emit JSON and a human-readable report |

The **evaluation harness consumes the layer-5 JSON and is not part of the
pipeline**. This is a validity control rather than a design convenience: a tool
that computed its own evaluation metrics would be grading its own output, and no
amount of care in the metric definitions would remove that circularity.

### 3.2.1 Layer 1 — IaC Input

Terraform `.tf` files and Kubernetes YAML manifests are the two supported input
platforms. CloudFormation, ARM templates and Helm charts are conceptually within
the framework's reach but are excluded from the evaluation, and the write-up does
not claim them.

Layer 1's non-obvious responsibility is building a **Kubernetes resource index**
before scanning. A Kubernetes finding frequently identifies a file and a line but
not the resource; recovering `apiVersion/kind/namespace/name` from a line number
requires having parsed the manifests independently of the scanner. The index makes
that recovery possible, and its failures are recorded rather than absorbed —
Section 3.6 returns to this.

### 3.2.2 Layer 2 — Security Scanning and the normalized finding record

The three scanners are invoked as subprocesses at pinned versions and their JSON
output parsed into a single record shape. Version pinning is a reproducibility
requirement, not hygiene: scanner rule sets change between releases, so an
unpinned corpus measurement cannot be reproduced. The pinned versions are
Checkov 3.3.12, Trivy 0.74.0 and tfsec 1.28.14, recorded with SHA-256 digests in
`tools/scanners.lock.json`.

The **platform–scanner matrix is data, not control flow.** tfsec declares support
for Terraform only, so the absence of tfsec results on a Kubernetes input is
derived from the lockfile's `platforms` list rather than from a conditional in the
code. The framework fails loudly when a scanner *required for the platform under
analysis* is missing, and stays silent when an inapplicable scanner is absent. The
distinction matters because the alternative — a hard-coded exception for tfsec —
would silently become wrong the first time another scanner's platform coverage
changed.

The normalized finding record carries the issue identifier, description, severity,
affected resource, file path, remediation suggestion and source scanner, plus the
framework's own additions: the canonical resource identity (Section 3.4), the
normalized issue class (Section 3.3), the violation fingerprint (Section 3.7) and
the explicit-state markers of Section 3.6.

### 3.2.3 Layer 3 — Context Extraction

Layer 3 attaches five contextual attributes, which together with scanner severity
make the six scoring factors. The attributes divide by provenance, and the division
is the design's most consequential honesty decision.

**Two attributes enter by declaration.** Resource sensitivity and environment
criticality are not reliably recoverable from IaC source. A bucket named
`data-prod-01` may hold regulated customer records or test fixtures, and no amount
of parsing settles which. Rather than infer them and absorb the error silently into
the headline result, the primary evaluation path takes them from an explicit
declared-context input. A convention-based **auto-inference mode**, reading tags and
naming conventions, is built and evaluated as a documented second mode, so the tool
does run end-to-end automatically — but the headline claim never rests on
heuristics.

**Three attributes are parsed** from the flagged resource and, where necessary, from
a **bounded and closed set of related resources**. Closing that set before corpus
finalization was deliberate. Public exposure in particular can in principle require
arbitrary reachability analysis, and an open-ended scope would make the extractor's
failures unbounded and its evaluation meaningless. The supported patterns are:

- security-group or NSG ingress open to `0.0.0.0/0` or `::/0`, attached to the flagged resource;
- a resource carrying a public-IP, `publicly_accessible`, or public-endpoint flag;
- storage buckets with public-access-block disabled, or a public ACL or policy;
- Kubernetes `Service` of type `LoadBalancer` or `NodePort`, and `Ingress`.

Explicitly **unsupported**, and therefore marked unresolved rather than scored as
low-exposure: multi-hop route-table, subnet and gateway reachability; VPC peering
and transit-gateway paths; and DNS-based exposure.

Two attribution rules within that scope are worth stating because getting them
wrong produces a plausible but incorrect ranking. First, a scanner may report an
open-ingress finding against the **rule resource** (`aws_security_group_rule`)
rather than the compute or storage resource it exposes; exposure is attributed to
the **target**, with the rule resource resolved through the bounded lookup, and the
violation fingerprint records which resource the scanner originally flagged so that
deduplication does not merge a rule-level with a target-level finding. Second,
bucket publicness can derive from separate ACL, policy, object-ownership and
public-access-block resources; the supported combinations are enumerated, and a
partial or cross-resource combination outside that enumeration is **unresolved, not
assumed private**.

### 3.2.4 Layer 4 — Risk Scoring

The scoring model is a transparent weighted-additive sum over six factors:

```
Risk Score = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk
```

| Factor | Range | Meaning | Provenance |
|---|---|---|---|
| Scanner severity | 1–5 | Baseline severity, normalized across tools | Scanner output |
| Public exposure | 0–5 | Reachable from the public internet? | Parsed |
| IAM privilege scope | 0–5 | Degree of sensitive or administrative permission | Parsed |
| Resource sensitivity | 0–5 | Business or data sensitivity of the affected asset | **Declared** |
| Environment criticality | 0–5 | Production versus staging versus development | **Declared** |
| Encryption risk | 0–3 | Required encryption or data protection missing? | Parsed |

The maximum attainable score is 28 and the minimum 1. The model is **not machine
learning**, and this is a design commitment rather than a limitation. Every factor
and every weight is inspectable, justifiable and adjustable, and each finding's
score decomposes into named contributions, so a reviewer can see why a finding
ranked where it did. Learning-based scoring is named future work; it would trade
the explanation for a fit, and the explanation is what the contribution rests on.

Scores map to four priority bands:

| Priority | Score | Remediation action |
|---|---|---|
| Critical | ≥ 22 | Block deployment, remediate immediately |
| High | 16–21 | Fix before production, or require approval |
| Medium | 9–15 | Schedule in normal sprint or backlog |
| Low | < 9 | Monitor, document, fix when convenient |

**The bands were defined by remediation semantics first, then mapped onto score
intervals** — not derived from the score range. This ordering matters to the
argument: a score ceiling of 28 does not by itself justify a cut at 22, whereas
"this band means block the deployment" is a claim about consequences that a cut
point can then be chosen to express. The band definitions are therefore falsifiable
in a way that arithmetic quartiles would not be.

Two structural properties are coupled and must move together. The score ceiling of
28 is the sum of the factor ranges, and the band boundaries are positioned against
that ceiling. **Changing any factor range, or adding a factor, invalidates the band
boundaries.** This coupling is recorded in the rubric configuration itself so that
the scoring engine enforces it rather than relying on a reader to remember it.

### 3.2.5 Layer 5 — Reporting

Layer 5 emits **JSON as the source of truth** and renders a human-readable report
from it. The ordering is deliberate: the evaluation harness reads the JSON, so the
machine-readable form cannot be a lossy derivative of a document formatted for
people.

## 3.3 The cross-cutting artifact — a normalized issue-class taxonomy

The framework maintains its own vocabulary of misconfiguration types, independent of
any scanner's rule identifiers. This taxonomy is **load-bearing across four
subsystems**: the context join, the scoring rubric, the test-case design and the
deduplication key. A change to it propagates to all four, which is why it is
authored as a version-controlled artifact before the code that consumes it.

As committed, the taxonomy defines **28 issue classes** across the five tested
categories — storage, networking, IAM, compute and containers — together with one
mapping row per observed `(scanner, rule_id)` pair. All **255 distinct rule
identifiers** observed across the vendored corpus map to a class.

An unseen rule does not receive a guess. It takes an explicit synthetic class
`unmapped:<scanner>:<rule_id>`, is scored on severity and default context only, and
is labelled **baseline-only informational**: surfaced for completeness, counted
once, never silently dropped, and **excluded from prioritization-quality claims**.
The exclusion is a validity requirement rather than a convenience. A serious finding
whose rule the taxonomy does not yet cover would score on severity alone and so
appear artificially low; counting it in a prioritization-quality figure would
depress that figure for a reason unrelated to the prioritization model's merit.

## 3.4 Canonical resource identity

The obvious identity key — resource type, name and file path — is insufficient for
real Terraform. It breaks on modules, on `for_each` and `count` instances, on
`moved` blocks, and on duplicate local names in different modules. Identity is
therefore defined separately per platform:

- **Terraform:** module path, resource type, resource name, and instance key where a `for_each` or `count` produces one.
- **Kubernetes:** `apiVersion/kind`, namespace and name, plus the container name for container-scoped findings.

Path normalization accompanies both, because the same file reached by different
relative paths must produce the same identity or deduplication silently
under-collapses.

An unresolvable instance key — a `for_each` over a computed value, for example — is
not quietly assigned a placeholder that could collide with a real instance. It
resolves to a documented state that is counted in the reported fallback rate.

## 3.5 Severity normalization, and what the corpus actually contains

The scoring model's Severity row presumes each finding arrives carrying a severity.
Measured over the vendored corpus, **it does not**. Of 1,055 findings,
**489 (46.4%) carry no severity at all, and every one of the 489 is from Checkov** —
221 on the Terraform scan root and 268 on the Kubernetes root. The sharper form of
the same measurement: Checkov emits exactly 489 findings over this corpus, so the
gap is not a subset of its output but the whole of it. Severity reaches
Checkov's JSON only through an API-key-gated metadata path that the public
invocation does not populate. The remaining 566 findings (Trivy 447, tfsec 119)
carry four levels: CRITICAL, HIGH, MEDIUM and LOW.

Two consequences follow, and both are design constraints rather than observations.

First, **the baseline is buildable from Trivy and tfsec severities and not from
Checkov's.** Since the baseline for the evaluation in Chapter 4 is raw scanner
severity mapped into the same four bands, a normalization decision that fills this
gap is a precondition of the comparison being fair, and it is version-controlled as
a per-scanner table mapping each native level onto the common 1–5 scale with a
justification per level.

Second, **a missing severity is an explicit `unknown` state, never a silent Low.**
This is the same discipline as Section 3.6 and is enforced in the type signature:
the normalization function returns an integer or the string `unknown`, so every
call site must branch before doing arithmetic. An unguarded addition on the return
value fails loudly rather than concatenating or silently coercing.

The four observed severity levels are a property of **this corpus as measured on
this host**, not a scanner contract — Trivy's vocabulary includes a fifth level
that the corpus does not exercise. The distinction is recorded so that a later
reader does not mistake a corpus observation for a tool guarantee.

## 3.6 Explicit-state discipline

A single principle recurs across every layer and deserves stating as a design
property in its own right: **where the framework does not know something, it says
so in a state that downstream code cannot mistake for knowledge.**

| State | Meaning | Where it arises |
|---|---|---|
| `unresolved` | The extractor could not resolve a code-derived factor | Layer 3, per factor |
| documented default | A declared value was absent from the declared-context input | Layer 3, sensitivity and criticality only |
| `unknown` | The scanner supplied no severity | Layer 2 normalization |
| `unmapped:<scanner>:<rule_id>` | The taxonomy has no class for this rule | Layer 2 classification |

Two of these are deliberately **not** merged, and merging them later would destroy
a reportable distinction. A *missing declared value* and an *extractor failure* are
different events with different causes and different remedies, so they take
different states and are reported as separate rates. Once combined into a single
"fallback rate", the two can no longer be separated after the fact.

The reason for the discipline is specific, not stylistic. A numeric default of
"low" on an unresolved exposure or IAM privilege value would not merely add noise;
it would **falsely reassure**, producing a confident low ranking for a resource
whose exposure is simply unknown. Reporting the unresolved rate alongside such a
default does not repair the individual ranking. Each factor therefore declares its
own unresolved-handling policy: conservative scoring, exclusion from
prioritization-quality claims, or bounded sensitivity analysis over the plausible
range.

## 3.7 Deduplication — a two-tier design

Deduplication collapses to one logical finding per `(canonical resource, normalized
issue class, violation fingerprint)`. The **fingerprint** — the specific affected
attribute, such as one IAM action, one security-group ingress rule, or one container
field — is what prevents materially different violations on a single resource from
being merged into one. Provenance, meaning which scanners flagged the finding, is
retained as metadata.

The design departs from the original single-key plan in one respect, and the
departure is worth recording because it changes what the alert-reduction metric can
claim. **A fingerprint is not always available.** Where it is absent, an exact-key
collapse cannot distinguish two genuinely different violations from two reports of
one. The implemented design is therefore two-tier:

- **Tier 1** collapses only where the fingerprint is resolved and the keys match exactly. This is the sole tier whose reduction is reported as deduplication.
- **Tier 2** identifies *candidates* — findings agreeing on resource and issue class that no fingerprint separates — and reports them separately, without collapsing them.

Measured over the vendored corpus, Tier 1 removes **39 of 1,055 findings (3.7%)**,
from 35 groups, exactly one of which spans two scanners.

Tier 2 yields 207 candidates, and **this figure must never be reported as a single
number.** It divides into **116 cross-scanner** candidates, which represent genuine
rule-family overlap between tools, and **91 same-scanner** candidates, which
represent one scanner raising two or more findings on one resource within one class
that no fingerprint separates. Reporting 207 as cross-scanner overlap would
mislabel the 91, and the same-scanner figure belongs in the limitations discussion
rather than in an alert-reduction result.

Three mechanisms produce the 91, not two: the taxonomy grouping many rule
identifiers into 28 classes; the absent fingerprint; and **one rule firing more than
once on one resource**, measured on exactly 3 of the 91, which carry a single
distinct rule identifier and therefore have no taxonomy-grouping cause at all. By
raising scanner the 91 split Trivy 71, Checkov 19, tfsec 1; Trivy dominates
structurally because its fingerprint field is null on every finding it emits, which
is a property of the tool's output rather than of the framework.

**Cross-scanner attribute normalization is named future work.** A mapping from each
scanner's attribute vocabulary onto one canonical spelling would move most Tier-2
candidates into Tier-1 exact collapses and so materially raise the measured
deduplication figure. It is not attempted in the current scope, and the reported
3.7% should be read as a floor that this known and unattempted improvement would
raise.

## 3.8 The rubric as a source-anchored artifact

Each of the six factors is defined level by level in a version-controlled rubric
configuration, and each level carries a citation to CVSS, NIST SP 800-30 Rev.1,
NSA-CISA Kubernetes hardening guidance, OWASP or FIPS 199. The intent is that no
score point is arbitrary: a reader disagreeing with a level can argue against a
named source rather than against the author's preference.

Two claims about this artifact are kept separate on purpose, and the separation is
itself a finding worth reporting.

**The structure is frozen and the freeze is verifiable.** Six factors, their ranges,
the 1–28 bounds and the band boundaries were fixed before any scoring output
existed, computed rather than asserted, and are pinned by tests. Later movement is
reported as sensitivity analysis, never as tuning.

**The citations are separately audited, and the audit is incomplete.** An
independent re-verification against the primary sources covered the rubric's **86
citation claims across 33 levels**, with this outcome: **69 verified supported, 6
found defective and corrected, and 11 unverified.** Four cited documents came back
entirely clean — CVSS v3.1 (26 claims), NIST SP 800-30 Rev.1 (32), the OWASP Risk
Rating Methodology (2) and OWASP A02:2021 (2). The six defective clauses comprised
three mis-locations of an OWASP A05:2021 statement that appears in its prevention
guidance rather than its vulnerability list, one citation of OWASP A01:2021 for
object storage that document does not mention, one FIPS 199 gloss contradicted by
that standard's own footnote restricting `NOT APPLICABLE` to the confidentiality
objective, and one citation naming an OWASP resource that does not exist. All six
were corrected as citation wording; no level's score, meaning or justification
moved, and the freeze was enforced by a hash comparison over the document with
every citation string blanked rather than by inspection.

The 11 unverified claims are the NSA-CISA Kubernetes hardening citations. The
document is a free public PDF that the build host cannot retrieve, and a
third-party summary of it was deliberately not substituted, because auditing a
citation against someone else's summary establishes nothing about the standard's
own words while presenting itself as verification. The rubric therefore carries
`citations_audited: false`, and the operative rule for this dissertation is narrow
and specific: **a rubric citation may be quoted unless it rests on NSA-CISA.**

## 3.9 Design decisions and accepted trade-offs

| Decision | Choice | Trade-off accepted |
|---|---|---|
| Artifact form | Automated pipeline with a declared-context seam | Full automation, but headline results rest on declared context rather than inference |
| Scanner integration | Subprocess invocation, JSON parsed to one record, versions pinned | Tool-agnostic and reproducible; depends on stable scanner output schemas |
| Scanner selection | Checkov and Trivy primary, tfsec retained as legacy and comparative | tfsec's rule families increasingly overlap Trivy's, so novelty must rest on the prioritization layer, not scanner count |
| Context join key | Per-platform canonical identity | Deterministic, but requires module, instance-key and namespace discipline |
| Scoring model | Equal-weighted additive sum | Explainable; weights and thresholds become sensitivity dimensions rather than tuned parameters |
| Weighting | Equal weights as a deliberate neutral baseline | Not a claim that criticality equals IAM privilege equals exposure; alternatives are tested in sensitivity analysis |
| Deduplication | Two-tier, collapsing only on a resolved fingerprint | An honest and low reduction figure, rather than a higher one obtained by merging distinct violations |
| Extraction fidelity | Literals only, unresolved as a first-class state | No full IaC graph resolution; unresolved rates reported per factor rather than hidden |

Equal weighting deserves one further note, because it is the decision most likely
to be challenged. It is **a neutral starting point, not an assertion that the six
factors matter equally.** The claim the framework makes is that an explicit,
inspectable, equal-weighted baseline is more defensible than an implicit weighting
chosen to produce agreeable rankings, and the sensitivity analysis tests plausible
expert-derived alternative weightings rather than only moving thresholds.

## 3.10 Implementation status

Because this chapter describes a design that is partly realised, the boundary is
stated explicitly rather than left for a reader to infer from the evaluation
chapter.

**Implemented and under test** (3,097 lines of implementation, 641 passing tests):
layer 1 file discovery and the Kubernetes resource index; layer 2's three scanner
adapters, lockfile-driven invocation and the normalized finding record; canonical
identity for both platforms with path normalization; the taxonomy and rubric as
loaded artifacts; two-tier deduplication; and the retention-coverage report.

**Specified and frozen, not yet implemented:** layer 3's bounded context extractor
and the auto-inference mode; layer 4's scoring engine, including enforcement of the
rubric's structural coherence rules and the exposure attribution precedence rule;
and layer 5's full reporting.

**Specified, awaiting the layers above:** the independent evaluation harness and the
sensitivity analysis.

One coverage gap in the factor set is known and unresolved, and it belongs in this
chapter rather than in the limitations of a later one, because it is a property of
the design. **Three taxonomy classes map to no rubric factor**: egress exposure,
which is data exfiltration and a distinct property from inbound reachability;
container host-isolation breakout; and hard-coded secrets. Findings in those
classes would score on severity plus declared context alone, with no factor
capturing the risk the class names. Two further classes read as candidates of the
same shape. The set is **not established as complete**, since no systematic sweep of
28 classes against 6 factors has been run, and closing it requires a decision
either to widen the factor set or to state the risk as out of scope. That decision
belongs to the scoring-engine work and is recorded as outstanding.

## 3.11 Scope boundaries

**In scope:** pre-deployment static analysis of Infrastructure-as-Code, with
Terraform and Kubernetes as the primary platforms.

**Out of scope, and named as future work:** runtime intrusion detection, malware
analysis, full cloud-provider monitoring, a complete enterprise CSPM platform,
multi-cloud production repositories, and machine-learning-based scoring.

These are guardrails rather than an apology. Each names a direction in which the
framework could be extended and in which this work deliberately does not claim
results.
