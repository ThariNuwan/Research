# Chapter 5 — Implementation

## 5.1 What this chapter covers

Chapter 3 describes the framework as designed. This chapter describes it as built: how
each of the five layers became code, where the scanners' real output forced the
implementation away from what the design assumed, and how the result was verified. It
closes with what was not built.

The implementation is in Python 3.12 and comprises three bodies of code with different
roles, kept apart on purpose.

| Body of code | Role | Files | Lines |
|---|---|---|---|
| `src/iacrisk/` | The artifact: the five-layer pipeline | 35 | 6,586 |
| `tools/` | Research instruments that run or replay the artifact | 11 | 2,011 |
| `eval/` | The evaluation harness that grades its output | 6 | 1,860 |
| `tests/` | The test suite, 1,108 tests | 63 | 19,190 |

The counts are of tracked Python files. Three PowerShell scripts under `tools/`, 1,701
lines together, install the scanners, vendor the corpus and capture scanner output; they
are not included above.

The test suite is larger than everything it tests put together, and nearly three times
the size of the artifact itself. That ratio is a consequence of the method rather than
a target: Section 5.9 explains why so many of the tests measure the real corpus instead
of exercising constructed inputs, and what three defects that practice found.

## 5.2 Three bodies of code, and the boundaries between them

**The artifact does not know it is being evaluated, and the harness does not know how
the artifact works.** The first two boundaries below are enforced by tests that parse
every module's imports; the third holds in the code and is not separately tested.

- `eval/` may not import anything from `iacrisk`. The harness reads the artifact's
  output as JSON. It restates the band order and the factor names as literals rather
  than importing them, because importing them would couple the grader to the graded.
- No module may import Checkov. It is installed as an isolated tool in its own
  environment and invoked as a subprocess, so its large dependency tree cannot constrain
  the framework's and the scanner-agnostic seam is structural rather than a convention.
- `tools/` imports the artifact, and the artifact imports nothing from `tools/`. An
  instrument consumes the thing it measures; the reverse would make the thing depend on
  its own measurement.

The specification artifacts — the taxonomy, the rubric, the class-to-factor table and
the inference conventions — are JSON files under `src/iacrisk/data/`, loaded by thin
modules that add no decisions of their own. Section 5.8 describes them. Keeping the
specification as data is what allows Chapter 3 to mirror it verbatim, and what allows a
test to assert that the code enforces it.

## 5.3 Toolchain and reproducibility

**Scanner versions are pinned by lockfile and verified by checksum.** Checkov 3.3.12 is
installed as an isolated tool at an exact version; Trivy 0.74.0 and tfsec 1.28.14 are
downloaded as release archives. For those two the bootstrap script compares the SHA-256
digest of each archive, and then of each extracted executable, against the lockfile
before it will run either. Hashing the
archive alone proves the download was authentic and nothing about the binary that is
later executed, so both are checked, and a mismatch stops the installation.

The same lockfile carries the platform matrix. tfsec is declared for Terraform only, so
the code that decides which scanners apply to an input reads that declaration; there is
no branch on a scanner's name. Adding a scanner without declaring its platforms makes it
applicable to nothing, which is the safe direction for an omission.

**The corpus is vendored at pinned commits**, and the scanners' output over it is
captured to disk once. Every measurement in this dissertation is computed by replaying
those captures through the pipeline rather than by re-running the scanners. A result
therefore does not depend on a scanner being installed, on network access, or on a
scanner's output being stable between runs — which it is not: all three reorder their
results, and Trivy stamps a fresh timestamp and report identifier each time.

**Every generated record carries a provenance block**: the commit it was generated at,
whether the source tree matched that commit, the interpreter version, and a SHA-256
digest of every input file. A figure in Chapter 6 can be traced to the exact bytes it
was computed from, and a test fails when one of the harness's records no longer matches
the digests of its inputs.

## 5.4 Layer 1 — input discovery

Layer 1 walks a directory and places every file in exactly one of three sets: IaC files
to be scanned, files ignored, and files that could not be parsed. There is no fourth,
silent outcome.

The third set exists because of the corpus. The Kubernetes repository contains a Helm
chart whose four templates carry Go template syntax and are not valid YAML, alongside
two chart files that parse cleanly but are not manifests. Treating both as "ignored"
would erase the distinction between a file that is not IaC and a file that is IaC the
framework cannot read. Over the three scan roots, discovery classifies 14 Terraform
files in the first, 16 Kubernetes manifests in the second with 4 ignored and 4
unparseable, and 2 Terraform files in the hand-crafted third.

For Kubernetes, layer 1 also builds a **resource index**: every manifest document, and
every container within it, with the line span it occupies. Section 5.5.2 explains why
the index is needed and Section 5.9 what went wrong when a second reader failed to
agree with it.

## 5.5 Layer 2 — scanning and normalization

Layer 2 turns three scanners' output into one record type. The design assumed this
would be a matter of mapping fields. It was not, and most of the layer's code exists
because of how the scanners actually behave.

### 5.5.1 The normalized finding

Each scanner finding becomes a `NormalizedFinding`: the scanner and its rule, the
taxonomy class the rule maps to, the native severity and its normalized level, the
platform, the canonical resource identity and what kind of identity it is, the file and
line range, a violation fingerprint, and whether the finding is eligible for context.

Three of those fields hold an **explicit state where a value might be missing**, in
keeping with the discipline of Section 3.6:

- The severity level is an integer or the literal `unknown` — never a number standing in
  for "the scanner did not say".
- The identity is the canonical string or an `unresolved` marker, component by
  component, so a partly templated resource keeps the parts that did resolve.
- The fingerprint is a value or `None`, and `None` means unresolved rather than absent.

A finding is eligible for context only if its identity names a Terraform resource or a
Kubernetes object. A hard-coded secret, a provider block or a file-level finding has no
resource whose context could be read, and is scored on severity alone.

### 5.5.2 What each scanner's output required

The three adapters share one interface and almost nothing else. The table gives the
measured shape of each scanner's output over the captured corpus, which is what each
adapter was written against.

| | Checkov | Trivy | tfsec |
|---|---|---|---|
| Findings in corpus v0 | 489 | 447 | 119 |
| Severity supplied | on none | on all | on all |
| Resource identity | one polymorphic string | a clean field for Terraform; **none at all** for Kubernetes | a clean Terraform address |
| File path | relative, with mixed separators | relative | **absolute**, on all 119 |
| Fingerprint resolved | 346 of 489 | 0 of 447 | 1 of 119 |

**Checkov's resource field does not say what it names.** The same string field holds a
Terraform address, a Dockerfile path, a provider block, a bare secret hash or a
Kubernetes kind-namespace-name triple, and the adapter has to classify it by shape.
For Kubernetes a fourth component sometimes follows the triple. An early reading took
it for a container name; measured, it is a pod-template label in every case, and
passing it to a container lookup would have resolved nothing.

**Trivy names no resource for Kubernetes.** None of its 332 Kubernetes findings carries
a resource field; the resource appears only in a prose message. The only structured
handle is a file and a start line, which is why layer 1 builds a line-span index: the
adapter looks the line up and takes the innermost span that contains it, so a line
inside a container resolves to the container and not to the workload around it. A line
that matches no span returns nothing rather than the nearest document, because a guess
returned from a lookup is indistinguishable from a fact. Nineteen Trivy findings keep
an unresolved identity as a result: 16 sit in the unparseable Helm templates, and 3
arrive with no line at all.

**tfsec reports absolute paths.** All 119 of its findings spell the file as an absolute
path on the machine that ran the scan, where the other two scanners spell the same file
relative to the scan root. Without rebasing, tfsec's findings join with nothing. The
adapter rebases each path against the scan root and raises on an absolute path outside
it, since passing one through would produce a silent mis-join. Section 5.9 records the
defect this left in the replay path.

**Severity is normalized per scanner onto one 1–5 scale**, by a table carried in the
rubric. Checkov supplies no severity on any of its 489 findings in this corpus; those
take the explicit `unknown` state, which the scoring layer later converts to the
rubric's documented default. The normalization function returns either an integer or
that string, and the scoring layer converts it at a single boundary so that no
arithmetic can meet a string.

### 5.5.3 Taxonomy mapping and canonical identity

Each `(scanner, rule)` pair maps to one of the 28 taxonomy classes through a committed
table of 255 rows — 128 for Checkov, 79 for Trivy and 48 for tfsec. All 255 pairs
observed in corpus v0 map, and all 28 classes are exercised. A rule the table does not
contain takes the class `unmapped:<scanner>:<rule>` rather than a guessed one. No
finding in corpus v0 needed it; three rules that fire on one hand-crafted case do.

Canonical identity is pure string formatting with no I/O: for Terraform the resource
type and name with any module path and instance key, for Kubernetes the API version,
kind, namespace and name with an optional container. The function renders the same
identity the same way every time. What it cannot do is make two callers pass it the
same arguments, and Section 5.9 describes the defect that followed from assuming it
could.

### 5.5.4 Deduplication

Deduplication is in two tiers, as Section 3.7 specifies. Two findings collapse only when
their resource, their class and a *resolved* fingerprint all agree. Over corpus v0 that
yields 35 groups and removes 39 findings; exactly one group spans two scanners.

Findings that share a resource and a class but cannot be told apart, because a
fingerprint is unresolved, are surfaced as candidates and never merged. There are 207:
116 involving more than one scanner and 91 involving one. The low Tier-1 figure is
largely a consequence of the fingerprint row in the table above. Trivy's fingerprint is
left unresolved on every finding by decision, not by omission: its extractable attribute
vocabulary shares no spelling with Checkov's, so extracting it would add a field that
matched nothing.

The scoring layer ranks what survives the first tier. A collapsed group is scored as
one finding, and Section 5.7 states which member represents it.

## 5.6 Layer 3 — context extraction

Layer 3 attaches the five contextual factors to each eligible finding. Three are read
from the code; two enter by declaration, or in the second mode by convention.

### 5.6.1 One return type for every factor

Every extractor returns the same small record: the factor, a level or none, one of
three states — `resolved`, `unresolved`, `defaulted` — and a sentence of evidence. The
record exposes one accessor for arithmetic, which returns the level or, where there is
none, the rubric's documented default for that factor.

This is what makes the rule "a missing value never reads as low" a property of the
type rather than of each call site. A scoring function cannot forget the unresolved
branch, because there is no way to ask for the level that would let it. And the
evidence sentence is what Chapter 6 quotes when it explains a result: the framework's
account of why a factor took the value it did is produced with the value, not
reconstructed afterwards.

`unresolved` and `defaulted` are distinct states because they are reported as distinct
rates. The first means an extractor could not read a code-derived factor; the second
means no value was declared for a declared factor.

### 5.6.2 Reading the source, literals only

Terraform is parsed with an HCL parser that leaves interpolations as literal `${...}`
strings instead of evaluating them. That is exactly what a literals-only rule needs: an
unresolved value is recognised by a substring check, not inferred.

One exception is deliberate. A reference such as `aws_s3_bucket.b.id` has an unknown
runtime value, but the *address* it names is written literally in the source. Resolving
that address is structural, not evaluation, and without it none of the bounded
cross-resource lookups of Section 3.2.3 could be implemented.

Kubernetes manifests are read as YAML. A manifest that does not parse is skipped rather
than raised, so one malformed file does not remove every other resource from
extraction; its absence appears as unresolved factors in the coverage report.

### 5.6.3 The three code-derived extractors

**Exposure** resolves only over the closed pattern list of Section 3.2.3. An ingress
rule open to any source resolves to 4; a narrower public range to 2; private ranges
only to 1; and a security group that declares no ingress to 0. A storage bucket
resolves from its public-access-block and any public policy or ACL, to 0 when fully
blocked and to 5 when the block is disabled and a public grant exists. A resource that
carries a literal public-access flag resolves from that flag. A Kubernetes Service
resolves from its type, and an Ingress to 3. A compute resource takes its exposure from
the security groups it references, which is the bounded lookup.

Two distinctions in this extractor matter to the evaluation. First, **a resolved
negative is not an unresolved value**: a security group read from literals with no
opening found resolves low, because the extractor looked and found nothing, whereas an
interpolated range is unresolved. Second, **exposure is inbound only**: an egress rule
open to any destination resolves to 0 here, and its risk belongs to a taxonomy class no
factor covers. Reading egress as inbound would have inverted one of the oracle's
scenarios.

**Privilege** reads policy documents, and neither form found in the corpus is plain
JSON. One is a heredoc whose body becomes JSON once its markers are stripped; the other
is a `jsonencode(...)` expression in HCL object syntax, which has to be re-parsed. The
level is read from action breadth and resource breadth jointly: a wildcard action on a
wildcard resource is 5, a single service's full control on a wildcard resource is 3,
and the same actions on a bounded resource set are 2. Reading action breadth alone
collapses the last two, which would have cost one of the two privilege contrastive
pairs without any test failing. A managed-policy reference, a variable or a data-source
reference is unresolved. For Kubernetes the extractor reads RBAC rules; a workload
kind grants no RBAC permission and resolves to 0.

**Encryption** reads a per-type table of 26 resource types and the attributes that
state their encryption at rest. A second table lists 32 types established to hold no
data at rest — network topology, identity objects, attachments — which resolve to 0. A
type in neither table is unresolved, because a hand-written table's silence is not
evidence that a resource holds no data. That second table was added after measurement:
before it existed, 159 findings resolved to 0 only because their type was missing from
the first, including a search domain that plainly holds data.

The encryption extractor must not read the level from the fact that an encryption rule
fired: one of the rubric's four coherence rules forbids any contextual factor from being
read off a finding's issue class. It reads attributes. Chapter 6 reports
the consequence: on an S3 bucket whose encryption block names its key by reference, and
on buckets that declare no block, the extractor returns unresolved in both cases, and
the factor separates nothing.

### 5.6.4 Declared context and its inheritance

Sensitivity and criticality are joined from the declared-context input on the canonical
identity, by exact match. There is no fuzzy matching and no fallback to a shorter key,
since a near-match would attach one resource's business context to another.

One bounded inheritance is implemented. A policy, ACL or public-access-block attached to
a bucket, and an inline policy attached to a role, take the declared values of the
resource they govern, when the attachment names that resource literally. Four
attachment types are covered and no others.

### 5.6.5 The second mode

The auto-inference mode produces the same shape of input from conventions — tags,
labels, namespaces and, for sensitivity, a word in a resource's name — and passes it
through the same join. Nothing downstream of layer 3 differs between the modes, and a
run is one mode or the other: the two are never merged, so no value in a record can be
of uncertain origin. The conventions are a committed data file, and Section 6.7.4
reports what they resolved.

## 5.7 Layers 4 and 5 — scoring, ranking and reporting

The scoring engine is short, because the rubric carries the model as data. It converts
severity into the same record type as the other five factors, sums the six accessor
values, asserts that the total lies within the frozen bounds, and asks the rubric for
the band. The band function raises on a score outside 1–28 rather than clamping it,
since such a score means a caller has broken the frozen model.

**Each scored finding carries its own explanation**: one line per factor giving its
level, its state and its evidence. Explainability is a field of the output, asserted
for every finding by an acceptance gate, and not a description of the method.

The engine accepts an optional weight per factor, defaulting to one. Any path that
produces a report refuses a score computed with any other weights, so the frozen model
cannot become weighted by accident.

Ranking is by descending score with **ties preserved as ties**: equal scores share a
rank. The order within a tie is fixed only for reproducibility and never changes a rank
number. Breaking ties arbitrarily would make the framework appear to discriminate where
it does not, and one of the oracle's scenarios contains a deliberate tie.

The severity baseline is a band assignment, not a score. A normalized severity of 5
maps to Critical, 4 to High, 3 to Medium, and 2 or 1 to Low. Scaling a five-point
severity onto a 28-point range would invent precision the scanner never supplied.

Reporting emits JSON as the source of truth and renders a human-readable report from
that JSON, so the two cannot disagree. The JSON carries, for every finding, the six
contributions, the state of each factor, the explanation lines, the baseline band and
every explicit-state flag.

**The order of the layers is fixed in one module.** It applies the first deduplication
tier, extracts context, scores, ranks and emits. Where a group of findings has
collapsed into one, the representative is a member whose severity the scanner supplied,
in preference to one that reports none, and among those the highest. In this corpus
that rule changes no score: 34 of the 35 groups are uniform in severity, and the
remaining one contributes the same value either way.

## 5.8 The specification as data

Six committed files hold what would otherwise be decisions scattered through code.

| File | Holds | Size |
|---|---|---|
| `taxonomy.json` | The issue classes and the rule-to-class mapping | 28 classes, 255 mapping rows |
| `rubric.json` | Six factors with their levels, defaults and unresolved policies; the bands; the severity-normalization table; four coherence rules | 33 levels |
| `factor_map.json` | Which factors bear on the risk each class names | 28 × 6 = 168 cells, with a rationale per class |
| `inference_conventions.json` | The keys, values, name words and rules of the auto-inference mode | — |
| `eval/sensitivity_plan.json` | The registered sensitivity analysis | 63 variants |
| `eval/ground_truth/corpus-v1.json` | The oracle | 26 cases, 10 pairs, 5 scenarios |

The loaders validate what they load and add nothing. The rubric loader, for instance,
exposes the bounds and the bands as computed from the file, and a test asserts that the
1–28 bounds follow from the factor ranges rather than being stated alongside them.

The last three files are **registrations**: each was committed before the results it
governs existed. For the conventions and the sensitivity plan a gate checks that order
(Section 5.9.1). For the oracle it is evidenced by the repository's history, in which
the ground truth precedes the scoring engine. The sensitivity plan belongs to the
harness and restates the frozen values rather than importing them from the artifact; a
test pins the restatement to the rubric so it cannot drift.

## 5.9 Verification

### 5.9.1 Tests, and the gates among them

The suite holds 1,108 tests. Fifty of the properties they assert are **acceptance
gates**: conditions stated when each part of the work was specified, which that part
had to meet before it was accepted.

| Part of the work | Gates | What they assert, in brief |
|---|---|---|
| Specification artifacts | 5 | Every observed rule maps; every rubric level is anchored; the structure is frozen |
| Evaluation corpus | 6 | The ground truth validates; every pairable factor has two pairs; no orphan cases |
| Detection and normalization | 6 | Every scanner finding is retained or counted as dropped; paths join across scanners |
| Context extraction | 7 | Every eligible finding carries five factors; no level depends on the issue class |
| Scoring and reporting | 8 | Every score is the sum of its contributions, in bounds and correctly banded |
| Evaluation harness | 8 | Every headline figure in the record is recomputed from the scored findings by separate code |
| Sensitivity analysis | 5 | Every registered variant is reported; every variant that moves a score is reproduced by the scoring engine |
| Auto-inference | 5 | The two modes differ in two factors and nothing else |

Three things about these gates deserve a note, because they are not ordinary
assertions — and the third because this section first described them wrongly.

**Some properties can only be shown by mutation.** That no factor's contribution depends
on a finding's issue class is a claim that a change has *no* effect, which no positive
assertion can establish. The gate substitutes the issue class of every finding in the
corpus and asserts that no contribution moves. The orthogonality of declared
sensitivity and code-derived encryption is tested the same way.

**Some gates check the repository's history.** Three sets of results in this
dissertation depend on rules that had to be fixed before the results were seen: how a
case is ranked, which sensitivity variants are computed, and which conventions the
auto-inference mode reads. For each, a gate asserts that the commit introducing the
rule is a strict ancestor of the commit introducing the result, and, for the two that
are data files, that the file has exactly one commit. For the case-ranking rule,
whose module has changed since, a gate compares the text of the eight rules with their
text in the registering commit. What this establishes is the order of commits and
nothing more; Section 6.1.1 says what that order does not rule out.

**Some gates were weaker than this section first claimed, and a test now checks that
they are not.** As first written, the table above said that each evaluation-harness
gate recomputed a figure in the record by a second route. A code review carried out
before the evaluation branch was merged — by a separate automated reviewer, not a
human examiner — found that several did not. They re-derived a value from the record's
own fields, or called the function under test to produce the value they expected, and
so passed for as long as the record was fresh, whatever it said. No gate recomputed a
rank correlation, an ordered-pair count, a Critical/High count or a rank-change total
at all.

The gates for the harness, the sensitivity analysis and auto-inference were rewritten
in three ways. The oracle's grading now has a second implementation in the test suite,
written to be obviously right rather than general — a rank correlation straight from
its definition, tiers as sorted distinct scores — which shares no code with the
harness, and the headline figures are recomputed with it from the scored findings.
Every sensitivity variant that moves a score, 43 of the 63, is scored again by the
framework's own engine and compared with the analysis finding by finding; the analysis
recomputes scores from JSON with arithmetic of its own, and until this existed nothing
held that arithmetic to the engine's. And a further test corrupts 32 figures in the
three evaluation records, one at a time and in memory only, and requires the gate that
owns each to fail.

The rewrite changed no figure. It is recorded because it is the lesson of Section
5.9.2 met again in the tests of the evaluation itself: **a check that derives its
expectation from the thing it checks cannot fail.**

### 5.9.2 Three defects that tests built on their own fixtures could not find

The most consequential fact about verification in this project is that **three defects
passed a green suite, and each was found only by measuring over the real corpus.**

*A container-scoped identity never matched its manifest.* When context extraction was
first built, the reader that supplies manifest contents was keyed on workload
identities, while findings on a container carry a container suffix. None of the 217
findings on a container-scoped identity matched — 14 identities in all — so every one
took the unresolved defaults on all three code-derived factors. Seven acceptance gates and 746 tests
passed, because each Kubernetes test built its own index, keyed the way the code
expected.

*An omitted namespace never matched either.* The same reader passed an omitted
namespace through as absent, while the identity index gave it the namespace `default`.
The two modules shared the function that formats an identity and were assumed to agree
for that reason; they passed it different arguments. Of 579 context-eligible Kubernetes
findings, 311 never reached their manifest. The two existing tests that touched an
un-namespaced manifest asserted the un-namespaced key, and so pinned the defect in
place. It was found by the evaluation, when one scenario came back inverted and the
framework's own explanation line read *no resource body indexed*. Section 6.2 reports
its effect on the results, which was large.

*The suite passed only on the machine that captured the fixtures.* tfsec's captured
output carries absolute paths from that machine, and every test replayed it against the
local checkout's root. On a clone at any other path 66 tests failed. The remedy
recovers the root a capture was recorded under from the capture itself.

The three share a cause, and it is worth stating as a rule. **A test that constructs
both sides of a comparison cannot discover that the real sides differ.** In each case
the code and its test agreed with each other and disagreed with the data. What catches
this class of defect is a test in which one side comes from the real adapters over the
real captures: identities the adapters actually produce, meeting an index the reader
actually builds. The regression tests added for the second and third defects take that
form, and the acceptance gates for the later parts of the work were written to measure
rates over the corpus rather than to assert over hand-built inputs.

A fourth, smaller instance occurred in the test suite itself: a module of shared test
wiring was importable from a subdirectory only when the whole suite ran, so a test
passed in a full run and failed at collection when run alone.

### 5.9.3 Static checks

The code is checked by a linter and formatter, and type-checked in strict mode, across
the artifact, the instruments, the harness and the tests. Strict typing is what makes
the explicit-state discipline hold in practice: a severity that may be an integer or
the string `unknown` cannot be added to anything until the code has said which it is.

## 5.10 The instruments and the harness

Three instruments under `tools/` run or replay the artifact.

- **The harvest** runs the pinned scanners over the vendored corpus and records every
  rule identifier observed. It preceded the taxonomy, which was then written against
  what the scanners emit rather than against their published rule catalogues. It
  deliberately defines no finding type of its own, and a test fails if it grows one.
- **The pair-candidate generator** enumerates same-type resources whose issue-class sets
  differ, and reports exactly which classes differ in each direction. It supports the
  authoring of contrastive pairs by making each pair's class difference explicit and
  re-derivable. It does not establish that a pair isolates the factor it names, which
  remains an authored judgement (Section 4.7.3).
- **The replay** runs the committed captures through the pipeline and writes the scored
  records Chapter 6 reads: the corpus, each case under its own declared context, and
  both again in auto-inference mode.

The harness under `eval/` has three modules, one per record, alongside the validator
that rejects a malformed ground-truth case (Section 4.8). The first computes
retention, the pair and scenario verdicts, alert reduction and the baseline comparison.
The second recomputes scores under the registered sensitivity variants, from the
per-factor contributions in the scored record, after first reproducing every committed
score at the frozen settings. The third compares the declared and inferred runs.

## 5.11 What was not built

**The end-to-end command was built after the evaluation, and no result came from it.**
The design sketched a command-line entry point that would take a directory and a
declared-context file and produce a report. When the evaluation was run that command
did not exist. Every result in this dissertation is computed from captured scanner
output replayed through the pipeline, and at that point the live path, though each
component was tested, had not been exercised as a whole.

The command was added afterwards, on 2026-10-08, as `iacrisk <folder>`. It adds no
layer and changes no score: it joins live scanner invocation to the composition the
replay instrument already used. For a folder it prints one line per resource, at that
resource's highest-scoring finding, with the six contributions and a mark on each one
that is a default; on request it writes every finding with its explanation lines as
JSON and Markdown.

What this establishes is narrow, and worth stating exactly. Two tests launch the real
scanners. One runs the command over the hand-crafted folder and requires the committed
per-case scores. The other scans the two corpus folders again and requires the
committed corpus record back, finding for finding: all 1,016 ranked findings, with the
same resource, class, scanner, rule, score, band, contributions and factor states. On
the machine they were run on, and at the pinned scanner versions, **the live path and
the replayed path agree exactly.** Both tests are skipped where the scanners are not
installed, so that agreement is checked only on a machine that has them.

The command has three limits, each a refusal in place of a wrong answer. It accepts
one platform per folder, because each adapter reads the platform off a whole scanner
run and a folder mixing Terraform and Kubernetes files would be misattributed. It stops
if any scanner is missing, times out or returns nothing usable, so that a folder is
never ranked on a subset of the scanners. And it runs only from a checkout in which the
pinned scanners have been installed. It has no option to fail a build on a priority
band, although the top band's remediation action is to block a deployment.

**Findings from an unseen rule are scored with full context, which is not what the
design said.** Running the framework live for the first time, on a folder whose
findings include rules outside the taxonomy, showed a disagreement between the design
and the code that the measurement corpus could not show, because it contains no such
finding. Section 3.3 records it. The code was left as it is.

**The human-readable report is Markdown only.** The design allowed Markdown or HTML.

**Helm charts are not rendered.** Templates that are not valid YAML are classified
unparseable and their findings keep an unresolved identity. Rendering them first would
resolve those identities and is recorded as future work.

**Privilege is not followed across resources.** The extractor reads the policy on the
flagged resource. It does not follow an instance to its instance profile, that profile
to its role, and the role to its attached policies. Chapter 6 shows a scenario in which
this is the deciding factor.

**Scanner attribute vocabularies are not normalized against each other.** A mapping
from each scanner's attribute names to one spelling would be expected to let many of
the 207 Tier-2 candidates collapse at the first tier, and to raise the measured
deduplication figure materially. It was not attempted, so the reported 3.7% is a floor.

**The count of findings entering an adapter is derived, not measured.** It is the count
leaving plus the count dropped. Tests count the raw records in the captures
independently, so the reported retention is checked, but the field itself is not an
independent measurement.

**There is no fourth factor state.** An inferred value is recorded with the same state
as a declared one, and the difference is carried in its evidence sentence and in the
record's mode. Adding a state would have changed what every consumer of the scored
output counts as evidence; the cost of not adding one is that low-confidence counts are
not comparable between the two modes.

None of these omissions affects the mechanism results of Chapter 6. Two points bear on
how those results should be read. The privilege limit explains one scenario. And every
result was computed by replay: the single live invocation now exists and reproduces
the corpus record on a machine with the scanners installed, but it produced no figure
reported here.
