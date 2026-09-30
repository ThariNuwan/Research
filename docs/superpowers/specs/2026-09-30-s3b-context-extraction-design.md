# S3b — Context Extraction (design)

**Project:** A Framework for Risk-Aware Security Misconfiguration Detection and Prioritization in Cloud IaC Environments
**Author:** Jayathissa E.A.T.N. (258243J) — MSc in Computer Science (Cloud Computing), University of Moratuwa
**Date:** 2026-09-30
**Scope:** Sub-project S3b — pipeline layer 3, context extraction, on the **declared-context primary path only**. Auto-inference becomes S3c.
**Authority:** `docs/PLAN.md` Q4 and Q9; `src/iacrisk/data/rubric.json` (frozen); `docs/superpowers/specs/2026-09-22-s3a-detection-normalization-design.md` §11.

---

## 0. Purpose and scope

S3a produced a normalized, deduplicated finding set carrying an issue class and a
normalized severity. It adds no contextual attributes. **S3b attaches the five
contextual attributes** to every context-eligible finding, so that S4 has six scorable
factors instead of one.

S3b computes **no risk score**. It resolves each factor to a level defined by the
frozen rubric, or to an explicit `unresolved` state, and records how it got there.
Scoring, banding and reporting are S4's; the evaluation harness is S5's.

**Why this is a specification rather than a design.** Almost every decision layer 3
would otherwise have to make is already fixed: PLAN Q9 closed the exposure pattern
list and the attribution rule, S1's rubric fixed all six factors' levels, precedence
rules, unresolved policies, unresolved defaults and the exposure sensitivity sweep,
and S3a fixed the record shape and `context_eligible`. This document's job is to state
those constraints in one place, resolve the handful that remained open, and define the
acceptance gates. §13 records the six decisions taken here and by whom.

### 0.1 Global constraints (bind every part of S3b)

- **Explicit-state discipline.** `unresolved`, `unmapped:`, `unknown`, `None` are
  first-class in the record and the output JSON. Nothing is ever silently defaulted
  to low or safe (PLAN Q9).
- **The rubric is the single source of truth for levels.** S3b resolves a factor *to
  a level the rubric defines*. It never invents a level, never interpolates between
  levels, and never adjusts a level's meaning. A construct the rubric's levels do not
  cover resolves to `unresolved`, not to the nearest-looking number.
- **The class routes; it never scores.** `severity_context_fencing` states that the
  five context factors are instance-level deltas scored **only from resolved instance
  evidence** and are **never re-derived from the rule**, and that `class_id` is never
  a term in the score. §2.3 makes this testable, because it is the constraint an
  implementer is most likely to violate while appearing to succeed.
- **Literals only.** Interpolated, variable or computed values are `unresolved`. No
  graph resolve, no variable evaluation, no module instantiation.
- **`context_eligible = False` means skip extraction entirely.** Do not default its
  factors; do not mark them unresolved. Those findings are already excluded from
  prioritization-quality claims by S3a's contract.
- **Kubernetes bodies are read by layer 3, not taken from S3a.** S3a's `ResourceEntry`
  carries `api_version`, `kind`, `namespace`, `name`, `container` and line spans and no
  spec, so it resolves identity and cannot supply a `Service`'s `spec.type`. Layer 3
  adds its own body reader keyed on the same `identity.kubernetes_identity`, leaving
  S3a untouched; the two agree by construction rather than by coincidence.
- **§G3 defect class.** A claim in the record its cited artifact does not support is a
  defect — docstrings, comments, test names, commit messages, and this spec. Measured
  facts here carry their source.
- **Windows-native host.** Always `uv run python`. Path handling is explicit character
  work.
- **Terraform is read with `python-hcl2`, added as a project dependency** (decision 8).
  Two quirks of it, both measured on this corpus and both silent if missed: block keys
  and string values **retain their surrounding quotes** (`'"aws_security_group"'`,
  `'"0.0.0.0/0"'`), so every read strips them or matches nothing; and interpolations
  arrive as literal `${...}` strings, which is exactly what literals-only needs — an
  unresolved value is a `${` substring check, not an inference. Checkov remains an
  isolated `uv tool` and must never become a project dependency; `python-hcl2` is
  unrelated to it.
- **Corpus v0 is a corpus observation, not a scanner contract.**

---

## 1. Measured facts S3b is designed around

Every figure below was measured on this host against committed artifacts, and each one
changes a design decision rather than decorating it.

**1.1 The default-fallback washout is arithmetically live.** The five context factors'
`unresolved_default` values are exposure 3, privilege 4, sensitivity 3, criticality 4,
encryption 2 — **sum 16**. Severity spans 1–5, so an **all-defaulted finding scores
17–21, which is *always* High at both ends of the range**. `unknown_resolves_to` is 4
and **all 489 Checkov rows in corpus v0 carry null severity**, so a Checkov finding
with nothing resolved lands on **exactly 20 — High**.

This is the single most important fact about layer 3: **if S3b resolves little, the
ranking collapses into one band and the framework's entire claim evaporates.** The
resolution rate is therefore not a quality metric to report afterwards; it is the
condition under which the framework works at all. §8 makes it a gate.

**1.2 Two mitigations already exist, on different axes, and neither covers the middle.**
S3a's `context_eligible = False` covers *no resource to contextualize* (8 of 489
Checkov findings, 1.6%). The `unmapped:` contract covers *no issue class*. Neither
covers **a resource that exists and a class that maps, whose factors simply do not
resolve** — which is the washout's actual population. §8's low-confidence rule is what
covers it.

**1.3 Declared context is keyed on canonical identity, and the corpus already fixes the
shape.** `eval/ground_truth/corpus-v1.json` carries `declared_context` per case as a
map from canonical identity to `{sensitivity, criticality}` — for example
`{"aws_security_group.default": {"sensitivity": 3, "criticality": 3}}`. The declared-
context input format is therefore not an open decision; it is whatever the corpus
already uses, and S3b reads that shape.

**1.4 Three taxonomy classes map to no rubric factor**, and S3b makes the gap
measurable rather than closing it: `networking-egress-exposure` (exfiltration, a
distinct property from inbound reachability), `containers-host-isolation-breakout`, and
`iam-hardcoded-secrets`. The Exposure extractor resolves **inbound** reachability; on
an egress finding it will resolve a value that does not describe the risk the class
names. Widening the factor set or declaring the risk out of scope is **S4's ruling**
(CLAUDE.md); S3b's obligation is to emit a per-class count so that ruling is made on
numbers.

**1.5 Trivy supplies no violation fingerprint, ever.** Irrelevant to factor resolution,
but it means a Trivy finding pair sharing identity and class reaches S3b as two records.
Both get contextualized independently and will resolve identically, which is correct and
not a bug to optimize away.

---

## 2. Deliverable 1 — the contextualized finding record

S3b extends S3a's `NormalizedFinding` with a context block. The record is additive:
nothing S3a wrote is modified.

| Field | Type | Meaning |
|---|---|---|
| `exposure` | `FactorValue` | Public exposure level, or unresolved |
| `privilege` | `FactorValue` | IAM privilege scope level, or unresolved |
| `sensitivity` | `FactorValue` | Resource sensitivity, declared or defaulted |
| `criticality` | `FactorValue` | Environment criticality, declared or defaulted |
| `encryption` | `FactorValue` | Encryption risk level, or unresolved |
| `defaulted_factors` | `tuple[str, ...]` | Factor keys whose **declared** value was absent (PLAN Q4) |
| `unresolved_factors` | `tuple[str, ...]` | Factor keys the **extractor** could not resolve (PLAN Q9) |
| `low_confidence` | `bool` | True when `len(defaulted) + len(unresolved) >= 3` (§8) |
| `evidence` | `tuple[Evidence, ...]` | Per-factor provenance: what was read, from where |

**2.1 `defaulted_factors` and `unresolved_factors` are never merged.** PLAN Q4's
missing-declared-value and PLAN Q9's extractor-failure are reported as separate rates,
and the ground-truth schema already carries them as separate fields. Merging them makes
that report impossible to reconstruct afterwards. The two lists are disjoint by
construction: `sensitivity` and `criticality` can only be defaulted, and `exposure`,
`privilege` and `encryption` can only be unresolved.

**2.2 `FactorValue` must make the unresolved branch unforgettable.** S1 handoff item 5
and S3a handoff item 2 both record the same trap: `normalize_severity` returns
`int | str`, and every call site must branch before arithmetic or a single unguarded
`+` concatenates or raises at runtime. S3b has **five** such factors, so the trap is
five times larger.

**Ruling: `FactorValue` is a small frozen dataclass, not `int | str`.** It carries
`level: int | None`, `state: Literal["resolved", "defaulted", "unresolved"]`, and a
`scored_level` property returning the rubric's `unresolved_default` when unresolved.
S4 then reads `scored_level` for arithmetic and `state` for reporting, and no call site
can accidentally add a string. Converting at the boundary is what S1 handoff item 5
recommended and S3a did not do; S3b is where it becomes cheap to do properly.

**2.3 The class routes; it never scores — and this is tested, not trusted.** The
failure mode is specific and plausible: resolving `encryption = 2` because the class is
`storage-encryption-at-rest`, rather than by reading the resource's actual encryption
attributes. That produces correct-looking output on the corpus while violating
`severity_context_fencing` outright, and it would make the encryption factor a
restatement of the finding's own existence rather than an independent signal.

The reconciliation with the rubric's own wording is worth stating, because they appear
to conflict. Encryption's `unresolved_rationale` says the gap "is already confirmed by
the scanner finding that produced the record; only the degree is uncertain." That
licenses the **unresolved default** — a policy about what to assume when nothing is
readable. It does not license a **resolved** value. So:

> A resolved factor level comes only from instance evidence read out of the
> configuration. The class may determine *which* extractor runs. It may never determine
> the level that extractor returns.

Gate 5 (§10) enforces this by mutation: substituting every finding's `issue_class` for
another class in the same category must not change any resolved factor level.

---

## 3. Deliverable 2 — the declared-context join (PLAN Q4)

Input is a JSON map from canonical resource identity to `{sensitivity, criticality}`,
the shape §1.3 measured from the corpus. The join is exact on canonical identity — the
same identity S3a's `identity.py` produces — with no fuzzy matching and no fallback to
a shorter key, because a near-match join would silently attach one resource's business
context to another.

**On a match**, sensitivity and criticality take the declared values; each is validated
against the rubric's range (0–5) and a value outside it is a hard error, not a clamp.

**On no match**, both take their documented defaults (sensitivity 3, criticality 4),
are added to `defaulted_factors`, and are counted in the reported default-fallback
rate. This is PLAN Q4's documented-default path and is distinct from Q9's `unresolved`.

**3.1 The IAM-governed-resource inheritance rule.** The rubric's
`iam_governed_resource_inheritance` coherence rule states that for a **resource-attached
IAM finding**, sensitivity and criticality are inherited from the **governed resource's**
declared context, reachable through the Q4 join without a graph resolve. A bucket policy
finding therefore inherits the bucket's declared sensitivity rather than defaulting.

A **pure account-level policy with no attachment** keeps the band cap and is documented
as a stated limitation of the transparent additive model. It does **not** inherit, and
it does **not** get a special value: its sensitivity and criticality default, and it is
counted as defaulted like any other unmatched resource.

The attachment relationships in scope are exactly those the bounded lookup already needs
for exposure (§4): a policy, ACL or attachment resource naming its target in a literal.
An indirect or interpolated attachment does not resolve, and the finding defaults.

---

## 4. Deliverable 3 — the Exposure extractor

Exposure is the only factor whose unresolved policy is **sensitivity-analysed** rather
than conservative-scored, with `unresolved_default = 3` and a declared sweep range of
**[2, 5]**. S3b's obligation is to record the unresolved state faithfully; the sweep
itself is S5's.

**4.1 The closed supported-pattern list** (PLAN Q9, restated in the rubric's factor
name). Resolvable:

1. security-group or NSG ingress open to `0.0.0.0/0` or `::/0`, attached to the target;
2. a public-IP, `publicly_accessible`, or public-endpoint flag on the resource;
3. storage publicness — public-access-block disabled, or a public ACL, or a public policy statement;
4. Kubernetes `Service` of type `LoadBalancer` or `NodePort`, and `Ingress`.

Explicitly **unsupported → `unresolved`, never low**: multi-hop route-table, subnet and
gateway reachability; VPC peering and transit-gateway paths; DNS-based exposure.

**4.2 The precedence rule is absolute, and it is about INGRESS.** The rubric states: a
`0.0.0.0/0` or `::/0` network-layer opening **forces exposure ≥ 4**, and identity-gating
modulates only *within* a network-openness tier, never across it — an authentication
layer can move a finding between levels inside a tier but can never pull an any-source
opening below 4. The extractor asserts this after resolution, so a future level change
cannot silently break it.

**Amended 2026-09-30 after implementation (decision 9).** The rule applies to an
**inbound** opening only. Exposure is inbound reachability: the factor's level 4 text
reads "open network path **to** the resource", and egress risk belongs to the taxonomy
class `networking-egress-exposure`, which §1.4 already records as mapping to no rubric
factor. Measured: TerraGoat's `aws_security_group_rule.egress` carries a literal
`0.0.0.0/0` with `type = "egress"`, and corpus-v1's networking scenario places that case
in its **bottom** tier. Treating an egress opening as inbound would force it to 4 and
invert the scenario's expected ordering. An `aws_security_group_rule` is therefore read
for its `type`, and an egress rule resolves to 0 with that reasoning in its evidence.

**4.3 The attribution rule — target, not rule.** A scanner may report an open-ingress
finding against the **rule resource** (`aws_security_group_rule`) rather than the
compute or storage resource it exposes. Exposure is attributed to the **target**, with
the rule resource resolved through the bounded lookup. The violation fingerprint already
records which resource the scanner originally flagged, so dedupe does not merge a
rule-level with a target-level finding — S3a built that; S3b must not undo it by
rewriting identity. **Exposure attribution changes the factor, never the identity.**

**4.4 Bucket publicness is an enumerated combination.** Supported: public-access-block
disabled; public ACL; public policy statement. Level 5 requires **public-access-block
disabled *plus* a public ACL or public policy statement**, per the rubric's L5 text. A
partial or cross-resource combination outside the enumeration is **`unresolved`, not
assumed private** — the failure this rule exists to prevent is a bucket scoring L0
because its publicness was spread across three resources the extractor read separately.

**4.5 Two rulings where the rubric's level text referenced something the extractor
cannot observe.**

**NodePort resolves to L2.** The rubric's L2 text reads "K8s NodePort exposed only
through a node firewall". No node firewall is visible in a manifest, so the condition
is unverifiable. Marking NodePort `unresolved` would be worse than wrong — a NodePort
*is* internet-reachable in principle, and unresolved would route it to the default 3,
which the rubric reserves for identity-gated managed endpoints. **Ruling: NodePort → 2,
with the firewall assumption recorded in the evidence string and carried as a stated
limitation.** Cost if wrong: NodePort services in front of no firewall are under-scored
by up to two levels.

**"Narrow public CIDR" (L2) needs no invented threshold.** L2 covers "ingress limited
to a narrow public CIDR". Rather than choose an arbitrary prefix length — which would be
a frozen parameter with no source behind it — the rule is structural: **any public
(non-RFC1918) CIDR with a non-zero prefix → 2; `0.0.0.0/0` or `::/0` → 4** by §4.2's
precedence. An RFC1918-only ingress is L1 (private/adjacent trust boundary). Cost if
wrong: a `/1` ingress scores 2 where it is nearly as open as `/0`; no such CIDR exists
in the corpus, and the alternative was an unsourced cut point.

---

**4.6 Resolved-negative is not unresolved (decision 10).** These are different states
and the distinction decides an ordering. A resource the pattern list **covers**, read
from literals, with no opening found, **resolves** to a low level — the extractor looked
and found nothing, which is evidence. `unresolved` is for two other situations: a
covered pattern whose value is interpolated, or a reachability mechanism outside the
closed list entirely.

Collapsing them is not a cosmetic error. TerraGoat's `aws_security_group.default`
declares no ingress block at all (measured: its body carries only `name`, `tags` and
`vpc_id`), so under a collapse it would be `unresolved` and score the default **3** — the
same value as the interpolated case the networking scenario places **above** it. The
scenario's bottom tier pairs it with the egress rule at 0, which only a resolved
negative produces. So §4.1's "anything outside the list is unresolved, never low" means
*outside the list*, not *inside the list and negative*.

**4.7 Resource-address references resolve structurally (decision 11).** A value of the
form `type.name.attr` resolves **as an address** to `type.name`. This is structural
resolution, not value evaluation: the address is written literally in the source, and
only the runtime value of the attribute is unknown.

**Without it, no cross-resource pattern in PLAN Q9's closed list is implementable.**
Measured on `corpus/authored/storage_public_exposure.tf`: both buckets link their
`aws_s3_bucket_public_access_block` with `bucket = aws_s3_bucket.NAME.id`, which the
literals-only check correctly classifies as interpolated. Refusing to read it leaves
bucket publicness unresolvable and makes one of the two **exposure contrastive pairs**
unreproducible.

The resolution is deliberately narrow. It refuses `var`, `data`, `local`, `module`,
`each`, `count`, `path`, `terraform` and `self` — none of which is a resource address —
and refuses anything that is not a single bare reference, so an expression, a function
call, a concatenation or a multi-element list stays unresolved. The same function backs
§3.1's IAM-governed inheritance, which has the identical need for the same reason.

---

## 5. Deliverable 4 — the Privilege extractor

The rubric's privilege levels name exact constructs, which fixes what the extractor must
read: single non-mutating verbs (L1), service-scoped write without `iam:*`, `PassRole`
or policy attach (L2), full single-service control such as `s3:*` or a scoped
escalation-adjacent action (L3), wildcard actions across services, unrestricted
`PassRole` / `CreatePolicyVersion` / `sts:AssumeRole`, or RBAC that can create or bind
roles, read secrets cluster-wide or exec into pods (L4), and `Action="*" Resource="*"`,
`cluster-admin`, or wildcard RBAC `verbs:["*"] resources:["*"]` (L5).

**5.1 IAM policy documents must be parsed, and this is not optional.** Privilege has
`unresolved_default = 4`. If policy documents are not read, privilege is unresolved on
every IAM finding, contributes 4 to every score, and feeds §1.1's washout directly.
**Ruling: parse policy JSON from `jsonencode(...)` arguments and heredoc literals in
HCL, and from `rules:` blocks in Kubernetes RBAC manifests.** Both are literal reads
consistent with the literals-only constraint — the JSON is present in the source text,
not computed.

**5.2 What does not resolve**, per the rubric's own `unresolved_rationale`: wildcards
behind variables or interpolation; indirect or managed-policy attachment; RBAC via
aggregated ClusterRoles; and conditions the bounded extractor cannot evaluate. Each
marks `unresolved` and scores 4.

**Ruling: AWS-managed policy ARNs resolve to `unresolved`.** Their contents are not in
the repository, and fetching them requires a network call to a live account — outside
static pre-deployment analysis and outside the framework's scope. Cost if wrong: an
attachment of `AdministratorAccess` scores 4 rather than the 5 it deserves, which
under-scores the worst case by one level. Recorded as a stated limitation, and the
per-factor unresolved rate makes its frequency visible.

**5.3 Conditions are not evaluated, and their presence does not reduce a level.** A
wildcard action carrying an IAM condition block is still a wildcard action; the
extractor cannot establish that a condition is restrictive. A condition that *appears*
to narrow scope therefore leaves the level where the action puts it and is noted in the
evidence. Treating an unevaluated condition as mitigating is the false-reassurance
failure mode PLAN Q9 forbids.

---

**5.4 Privilege level is action breadth AND resource breadth, jointly — and one
contrastive pair depends on it.** The rubric's L2 reads "Modify/create on a **bounded
resource set** within a single service" while L3 reads "Full control of one service
(e.g. `s3:*`)". An `s3:*` action on one bucket ARN satisfies L3's action example and
L2's resource clause at the same time, so the level is ambiguous **unless the extractor
reads action and resource together**. It must, and this is the mapping:

| Action breadth | Resource | Level | Rubric clause |
|---|---|---|---|
| single service wildcard (`s3:*`) | bounded ARN | **2** | "bounded resource set within a single service" |
| single service wildcard (`s3:*`) | `*` | **3** | "full control of one service" |
| wildcards across >1 service | `*` | **4** | "wildcard actions across multiple services" |
| `*` | `*` | **5** | "Action=\"*\" Resource=\"*\"" |

Verified against every IAM case the corpus contains: `iam-s3-bucket-scope` → 2,
`iam-s3-account-scope` → 3, `iam-unrestricted-scope` → 5, and TerraGoat's
`aws_iam_role_policy.ec2policy` (`["s3:*","ec2:*","rds:*"]` on `"*"`) → 4. All four land
on distinct levels.

**Why this is a correctness requirement and not a preference.** Read action breadth
alone and `iam-s3-bucket-scope` and `iam-s3-account-scope` both resolve to 3 — whereupon
the contrastive pair `privilege-iam-bucket-to-account` **no longer isolates the privilege
factor at all**. It would still pass on rank, because account-scope carries one extra
issue class and therefore one extra scored finding, but it would pass for a reason the
pair does not claim and `severity_context_fencing` forbids: the class difference cannot
move a factor. That pair is the stronger-evidence half of the only two privilege pairs
in the corpus (S2 spec R10), so losing it would leave the privilege factor with one
mechanism test. Gate 7 (§10) asserts the four levels above directly.

This is also the S2 handoff's warning arriving in practice: a class named for a factor is
not evidence of that factor. `iam-privilege-escalation-sensitive-perms` is named for
privilege and is still not evidence that the privilege *factor* differs between two
resources.

---

## 6. Deliverable 5 — the Encryption extractor

Encryption spans 0–3 with `unresolved_default = 2`. The extractor reads the resource's
encryption attributes directly: at-rest encryption flags and KMS key references for
storage and volumes, in-transit settings where declared, and the Kubernetes controls the
rubric's L3 names.

**6.1 L3 requires positively-established mandate evidence.** The rubric reserves L3 for
a standard-mandated hardening control — etcd Secret encryption at rest, TLS across a
trust boundary — or a regulated/customer-managed-key requirement. **A non-literal read
can never reach L3**, per the factor's own rationale; it is bounded at 2. The extractor
must therefore not promote to 3 on the strength of a resource *type* alone.

**6.2 The fencing constraint bites hardest here** (§2.3). An unencrypted-volume finding
must resolve its encryption level from the volume's `encrypted` attribute, not from the
fact that a rule named `storage-encryption-at-rest` fired. Where the attribute is absent
from the source, the correct answer is the platform's documented default if that is
literal and knowable, and `unresolved` otherwise — not 2-because-the-scanner-complained.

---

## 7. Deliverable 6 — Sensitivity and Criticality

On the declared-context path these are **not extracted**. They come from §3's join or
they default. S3b contains no tag-reading or name-pattern logic whatsoever; introducing
any would pre-empt S3c and contaminate the primary path's claim to deterministic,
defensible inputs.

---

## 8. Deliverable 7 — unresolved accounting and the low-confidence rule

**8.1 The frozen threshold.** The rubric's `unresolved_default_reporting` coherence rule
requires band distribution reported split by count-of-defaulted-factors, findings above
a threshold flagged low-confidence and excluded from prioritization-quality claims, and
the stacked-default total carried into the Q10 sensitivity analysis. **The threshold was
unspecified. It is fixed here, before any scoring output exists:**

> **A finding is `low_confidence` when 3 or more of its 5 contextual factors are
> defaulted or unresolved** — a majority of the contextual evidence absent.

Rationale, so the number is defensible rather than chosen. The primary argument is
about evidence, not arithmetic: **three of five is the point at which a majority of the
contextual evidence is absent**, and a count is the form the coherence rule asks for.
The arithmetic supports that without determining it. The mean default is 16/5 = 3.2 and
the bands span 8, 7, 6 and 7 points (Low, Medium, High, Critical), so three defaults
contribute ≈9.6 points — more than any single band's width — and the defaults alone can
therefore decide the band. Two defaults (≈6.4) already exceed the narrowest band, so the
arithmetic does **not** single out three on its own; it is the majority-of-evidence
argument that does, with the arithmetic confirming three is past the point where
defaults dominate. **This is a frozen parameter from this date** and any later movement is
reported as sensitivity analysis, never tuned to fit. Decided by the project author,
2026-09-30, on the recommendation recorded in §13.

**8.2 Reported rates, all per-factor and never aggregated into one number.** The
default-fallback rate (Q4), the extractor-unresolved rate (Q9), each split by factor;
the low-confidence population; and the band distribution split by defaulted count. PLAN
§3.5(2)'s split-by-defaulted-count report is exactly this.

**8.3 The resolution-rate gate.** Because §1.1 makes a low resolution rate fatal rather
than merely regrettable, S3b reports the **share of context-eligible findings with 0
defaulted-or-unresolved factors** and the full distribution over 0–5. This is the number
that says whether the framework can rank at all, and Gate 6 requires it be measured and
stated, not merely computed.

**8.4 Per-class factor-coverage counts** (§1.4). For each of the 28 taxonomy classes,
the count of findings and how many factors resolved. This is the artifact S4 needs to
rule on the three classes that map to no factor, and without it that ruling would be
made on argument rather than measurement.

---

## 9. Testing

Unit tests per extractor against hand-built minimal resources; integration tests over
the committed fixtures; and, for the fencing and precedence constraints, **mutation
tests** rather than assertions alone — the constraint is that a change *cannot* have an
effect, which a positive assertion cannot demonstrate.

Judge pytest by **exit code**, never by grepping for `FAILED`: `addopts` carries
`-q --strict-markers -rs`, under which a failing test prints `F` and a traceback and
emits no line beginning with `FAILED`.

---

## 10. Acceptance gates

1. **Every context-eligible finding carries five `FactorValue`s**, each either a level the rubric defines or an explicit unresolved state. No factor is ever absent, and no level exists that the rubric does not define.
2. **`context_eligible = False` findings carry no context block at all** — not defaults, not unresolved. Asserted directly, since silently defaulting them is the regression that re-opens the washout S3a closed.
3. **`defaulted_factors` and `unresolved_factors` are disjoint**, and their union is exactly the set of factors not resolved from evidence. A test asserts the disjointness on the whole corpus, not on a sample.
4. **The exposure precedence rule holds as data.** For every finding whose evidence records a `0.0.0.0/0` or `::/0` opening, `exposure.level >= 4`. The rule text is read from `rubric.json`, so the gate cannot drift from the artifact.
5. **Fencing, by mutation.** Substituting a finding's `issue_class` for another class in the same category changes no resolved factor level. Run over the whole corpus; any change is a fencing violation.
6. **The resolution-rate distribution is measured and reported** over 0–5 defaulted-or-unresolved factors, with the low-confidence population at the frozen threshold of 3, and per-class factor-coverage counts for all 28 classes.
7. **The privilege mapping of §5.4 holds on every corpus IAM case**: `iam-s3-bucket-scope` → 2, `iam-s3-account-scope` → 3, `iam-unrestricted-scope` → 5, `aws_iam_role_policy.ec2policy` → 4. Asserted as four explicit expectations, because the pair `privilege-iam-bucket-to-account` stops isolating its factor if the first two collapse to one level.

---

## 11. Deferred, explicitly

**To S3c:** the convention-based auto-inference mode for sensitivity and criticality —
its tag and naming conventions, its own acceptance gate, and the auto-inference
agreement metric that compares its ranking against the declared-context ranking.

**To S4:** all scoring, banding and reporting; enforcement of the rubric's coherence
rules at score time; and the ruling on the three taxonomy classes that map to no rubric
factor, which S3b supplies the counts for (§8.4) but does not decide.

**To S5:** the evaluation harness, the exposure sensitivity sweep over [2, 5], and the
Q10 model-sensitivity analysis.

---

## 12. Named future work, deliberately not attempted here

**Cross-scanner attribute normalization** (S3a §13) remains unattempted and out of scope
for S3b, as does **a measured `raw_records_seen`** to replace S3a's derived
`findings_in`. Multi-hop reachability, VPC peering, transit-gateway and DNS-based
exposure stay outside the closed pattern list by design, not by omission — widening it
would make the extractor's failure modes unbounded and its unresolved rate
uninterpretable.

---

## 13. Decisions taken in this document

Six decisions were open when this spec was written. Recording who took each one, and
what it costs if wrong, so a later reader can reopen any of them on evidence.

| # | Decision | Taken by | Cost if wrong |
|---|---|---|---|
| 1 | Low-confidence threshold = **3 of 5** defaulted-or-unresolved | Project author, on recommendation | Too low excludes most of a 26-case corpus from headline claims; too high lets defaults decide rankings that are then reported as prioritization quality |
| 2 | S3b is **declared-context only**; auto-inference is S3c | Project author, on recommendation | Auto-inference agreement cannot be measured until S3c lands; S3b's gates stay about extraction fidelity rather than heuristic quality |
| 3 | `FactorValue` is a **dataclass**, not `int \| str` | This spec | An `int \| str` across five factors reproduces the `normalize_severity` trap five times over |
| 4 | **NodePort → exposure 2**, firewall assumption documented | This spec | NodePort in front of no firewall is under-scored by up to two levels |
| 5 | **Narrow public CIDR** is structural (non-zero prefix → 2), no invented threshold | This spec | A `/1` ingress scores 2 despite being nearly `/0`; no such CIDR exists in the corpus |
| 6 | **IAM policy JSON is parsed**; managed-policy ARNs → `unresolved` | This spec | An `AdministratorAccess` attachment scores 4 rather than 5, under-scoring the worst case by one level |
| 7 | Privilege level reads **action breadth AND resource breadth jointly** (§5.4) | This spec, from measurement | Action-breadth-only collapses `iam-s3-bucket-scope` and `iam-s3-account-scope` to one level, and the privilege factor loses one of its two mechanism pairs without any test failing |
| 8 | **`python-hcl2`** becomes a project dependency for Terraform reads | This spec, from a spike | A hand-rolled attribute scanner misparses silently and yields a confident wrong factor value, which is the false-reassurance failure mode the framework exists to prevent |
| 9 | The precedence rule applies to **ingress** openings only (§4.2) | Implementation, from corpus-v1 | Reading egress as inbound forces `sgr-egress-unrestricted` to 4 and inverts the networking scenario's expected ordering |
| 10 | **Resolved-negative is distinct from unresolved** (§4.6) | Implementation, from corpus-v1 | Collapsing them scores a rule-less security group 3 instead of 0, placing it level with the interpolated case the scenario ranks above it |
| 11 | **Resource-address references resolve structurally** (§4.7) | Implementation, from the authored corpus | Without it bucket publicness is unresolvable and one of the two exposure contrastive pairs cannot be reproduced |

Decisions 4, 5 and 6 each trade a known, bounded, documented error for a resolved value,
in preference to an `unresolved` state that would route to a default and feed §1.1's
washout. That trade is the design's consistent answer wherever the rubric's level text
referenced evidence the extractor cannot see: **resolve conservatively and say so, rather
than default silently.**
