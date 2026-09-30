# Rubric citation audit — every source read except NSA-CISA; six clauses to reword

**Status:** PARTIAL — CVSS, NIST, all of OWASP and FIPS 199 verified; **NSA-CISA is unverifiable from this host** (§3D) and is the only standard outstanding. `citations_audited` stays **`false`**. **The six defective clauses are reworded and committed** (§4.2) — five partially-supported and one, "OWASP IaC Security", that named no real resource and is now deleted.
**Auditor:** controller session, 2026-09-30
**Subject:** all 33 `source` strings in `src/iacrisk/data/rubric.json`
**Why this exists:** `citations_note` in that file states the strings "were produced by the verification pass design spec section 3.1 describes" but that "an independent re-verification of all 33 levels against the primary sources" never happened, and that no dissertation text may quote a `source` string until it does.

---

## 0. Verdict so far

| Standard | Levels citing it | Verdict |
|---|---|---|
| **CVSS v3.1** | 26 | **all verified supported** |
| **NIST SP 800-30 Rev.1** | 32 | **all verified supported** |
| OWASP Risk Rating Methodology | 2 | **verified — both exact** |
| OWASP Top 10 A05:2021 | 4 | **verified — 1 supported, 3 partially supported** (§3A) |
| OWASP Top 10 A01:2021 | 4 | **verified — 3 supported, 1 partially supported** (§3A) |
| OWASP Top 10 A02:2021 | 2 | **verified — both supported** (§3C) |
| "OWASP IaC Security" | 1 | **verified — unsupported: no OWASP resource carries that title** (§3C) |
| FIPS 199 | 4 (`criticality` L0, L1, L4, L5) | **verified — 3 supported, 1 partially supported** (§3B) |
| NSA-CISA Kubernetes Hardening Guidance | 11 | **cannot verify — primary source unreachable from this host** (§3D) |

### Erratum, 2026-09-30 — two false claims in the first version of this table

The first version of this document listed a fifth outstanding standard, **"CIS Benchmarks | 10 levels"**, and gave FIPS 199 as **2** levels. Both are wrong, and they were wrong in the audit record whose entire purpose is catching claims a cited artifact does not support.

- **`rubric.json` cites CIS Benchmarks zero times.** The count came from a script matching the substring `CIS`, which matches inside **`NSA-CISA`** — all 11 hits were the Kubernetes Hardening Guidance. There is no CIS Benchmark citation anywhere in the file, so the paragraph the first version wrote about CIS's registration barrier described a problem this rubric does not have.
- **FIPS 199 is cited on four levels**, not two: `criticality` L0, L1, L4 and L5.

Measured directly: `CIS Benchmark` → 0 occurrences; `CIS` not preceded by `NSA-` → 0; `NSA-CISA` → 11. Levels per standard: CVSS 26, NIST 32, OWASP 12, NSA 11, FIPS 4.

**Consequence of the error, had it stood:** the audit would have reported a standard as unverifiable that is not cited, inflating the apparent outstanding work and — worse — leaving a reader to believe the rubric leans on a paywalled source. **Three** standards remain, not four, and none of them is paywalled.

### Erratum 2, 2026-09-30 — an arithmetic claim in my own section heading

§3A's heading read "**12 levels, 9 supported and 4 partially supported**". Counting its own body: Risk Rating Methodology 2 supported, A05 1 supported and 3 partial, A01 3 supported and 1 partial — that is **6** supported, 4 partial, and 3 claims then unread, over 13 claims on 12 levels (`exposure` L5 is cited by both the A01 row and the A02/IaC row). The heading's 9 was 6 plus the 3 *unread* claims, i.e. it silently counted unverified claims as supported — in a heading, where a reader takes the total on trust and the body's "remain unread" sentence is three lines further down.

This is the third false claim found in this audit's own record, after the two in Erratum 1, and all three are the same shape: a number produced by a shortcut rather than by counting the thing it names. The heading is corrected below to 8 supported, 4 partial, 1 unsupported over 13 claims, which is what the audited body now says.

**The flag stays `false`.** Every level carries claims against more than one standard, so no level is fully audited until its OWASP / NSA-CISA / CIS / FIPS components are checked too. A flag flipped now would assert an audit that covered two of six standards.

**Nothing was corrected.** Every CVSS and NIST claim checked reproduced exactly against the primary source. No citation string was edited, and no level's score, `meaning` or `justification` was touched — the structural freeze forbids the latter absolutely, and the former turned out not to need it.

---

## 1. Sources actually fetched and read

- **CVSS v3.1 Specification Document**, <https://www.first.org/cvss/v3.1/specification-document> — Table 14 (Qualitative Severity Rating Scale), Table 16 (Attack Vector weights), Table 5 (Scope), Table 12 (Confidentiality Requirement).
- **NIST SP 800-30 Rev.1**, *Guide for Conducting Risk Assessments*, <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf> — 95 pages, text extracted and read directly. Tables read verbatim: **G-2** (p82), **G-3**, **G-4**, **H-3** (p85), **I-2** (p86), **I-3** (p87), and **D-3/D-4/D-5** (p67).

- **FIPS PUB 199**, *Standards for Security Categorization of Federal Information and Information Systems*, <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf> — 13 pages, read in full, including footnote 4.
- **OWASP Top 10 A02:2021 Cryptographic Failures**, <https://top10.owasp.org/2021/A02_2021-Cryptographic_Failures/index.html> — reached through two redirect hops from the `owasp.org/Top10/` form.
- **OWASP Infrastructure as Code Security Cheatsheet**, <https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html> — read to settle what "OWASP IaC Security" could refer to.

**Not read, because it could not be retrieved:** the NSA-CISA Kubernetes Hardening Guidance v1.2. §3D records every route attempted and the exact refusals.

The NIST PDF would not render (no poppler on this host) and WebFetch returned raw stream data, so the text was extracted with an ephemeral `pypdf` under `uv run --with` — no project dependency was added. FIPS 199 was extracted the same way.

---

## 2. CVSS v3.1 — 26 levels, all supported

Verbatim from Table 14: None `0.0`, Low `0.1–3.9`, Medium `4.0–6.9`, High `7.0–8.9`, Critical `9.0–10.0`. From Table 16: Network `0.85`, Adjacent `0.62`, Local `0.55`, Physical `0.2`.

| Factor / level | Claim | Verdict |
|---|---|---|
| severity L1–L5 | the five CVSS bands, by name and range | **supported**, all five exact; L5 also names the table correctly ("Qualitative Severity Rating Scale") |
| exposure L0 | `AV:P 0.20 / AV:L 0.55` | **supported** (Physical 0.2, Local 0.55) |
| exposure L1 | `AV:A, 0.62` | **supported** |
| exposure L2 | `AV:N 0.85` | **supported** |
| exposure L3 | `AV:N` with Privileges Required present | **supported** |
| exposure L4 | `AV:N` + `PR:None` | **supported** |
| exposure L5 | `AV:N` + `PR:None` + `S:C` | **supported** |
| privilege L0 | `S:U` — "grants no authority over any component beyond its own security scope" | **supported**; Table 5 reads "can only affect resources managed by the same security authority" |
| privilege L3, L4, L5 | `S:C` — authority reaching beyond the component's own scope | **supported**; Table 5 reads "can affect resources beyond the security scope managed by the security authority of the vulnerable component" |
| sensitivity L0 | `C:N` | **supported** |
| sensitivity L2, L3, L4 | `CR:Low` / `CR:Medium` / `CR:High` | **supported**; Table 12 defines all three |

**One citation is better than it needed to be.** `privilege` L1 states: *"CVSS Privileges Required is deliberately not cited here: PR describes what an attacker must already hold, not the authority a grant confers."* That is a correct reading of CVSS semantics and a disclaimer most citations would omit. It is a *non-*claim, correctly made.

---

## 3. NIST SP 800-30 Rev.1 — 32 levels, all supported

### 3.1 The semi-quantitative scale

Every assessment scale in SP 800-30 Rev.1 uses one scale: Very High `96-100`/**10**, High `80-95`/**8**, Moderate `21-79`/**5**, Low `5-20`/**2**, Very Low `0-4`/**0**. Confirmed verbatim in Tables D-3, D-4, D-5, G-2, G-3, G-4, H-3 and I-3.

### 3.2 Table G-2 — exposure

Table G-2 is titled **"ASSESSMENT SCALE — LIKELIHOOD OF THREAT EVENT INITIATION (ADVERSARIAL)"**, which is exactly what `exposure` L0 cites. Its tiers read "Adversary is highly unlikely / unlikely / somewhat likely … to initiate the threat event."

`exposure` L0–L5 cite App. G likelihood tiers Very Low → Very High in order. **All supported.**

**`exposure` L2 is the most honest citation in the file.** It says the placement is *"interpolated between Low and Moderate; the scale defines no intermediate tier, so this is an ordinal placement rather than a quoted tier."* Verified: G-2 jumps from Low `5-20` to Moderate `21-79` with nothing between. The citation declines to claim a tier it does not have.

### 3.3 Table H-3 — sensitivity, criticality, privilege

Table H-3 is **"ASSESSMENT SCALE — IMPACT OF THREAT EVENTS"**. Read verbatim:

- Very High — "multiple severe or catastrophic adverse effects"
- High — "a severe or catastrophic adverse effect"
- Moderate — "a serious adverse effect"
- Low — "a limited adverse effect"
- Very Low — "a negligible adverse effect"

`sensitivity` L1–L5 and `criticality` L0–L1 quote these tiers, several word for word ("negligible adverse effect", "serious adverse effect", "multiple severe or catastrophic effects"). `privilege` L0–L5 cite the same tiers as impact anchors. **All supported.**

`sensitivity` L4 says "High (severe adverse effect)" where H-3 reads "severe **or catastrophic**". Narrower than the source, not contradicted by it — **supported**.

### 3.4 Appendix I — the one attribution worth explaining

`severity` L4 cites "App. I qualitative value 'High' (80–95 / representative value 8)" and L5 "Appendix I semi-quantitative crosswalk, 'Very High' (96–100 / representative value 10)".

**Appendix I contains no table named a "semi-quantitative crosswalk."** Its tables are I-1 (Inputs–Risk), I-2 (Level of Risk, the likelihood×impact matrix), I-3 (Assessment Scale–Level of Risk), I-4/I-5 and I-6/I-7 (risk table templates).

I nearly filed this as a defect. It is not one: **Table I-3 carries exactly those values**, in a column headed "Semi-Quantitative Values" — Very High `96-100`/10, High `80-95`/8, and so on. So the appendix is right, the numbers are right, and "semi-quantitative crosswalk" is a fair description of I-3's shape even though it is not I-3's title. **Supported.**

**A limitation of these two citations that is worth recording.** Because the same scale appears in at least eight tables across four appendices, citing "App. I" identifies the numbers but not uniquely — D-3, G-2 and H-3 would all yield them. Anchoring an overall *severity* term to Appendix I's **Level of Risk** rather than to Appendix H's **Impact** or G's **Likelihood** is a defensible semantic choice (severity is a composite, and I-3 is the composite scale), but it is a choice, and the citation does not say so. Not a false claim; an under-specified one.

`severity` L1–L3 cite tier names and ranges with no appendix at all. The numbers are correct against I-3, H-3 and several others. **Supported but unlocated** — worth adding the table reference for consistency with L4 and L5, which is a citation improvement rather than a correction.

### 3.5 Two more disclosed ordinal placements

`privilege` L4 says NIST "'High', placed at the upper end of that tier; the scale defines no separate tier above it." Verified: H-3's High is `80-95` and the only tier above is Very High `96-100`, so "upper end of High" is a real position and the citation says plainly that it is a placement rather than a quoted value. **Supported.**

Same shape, same honesty, as `exposure` L2.

---

## 3A. OWASP A05 and A01 — of 13 OWASP claims over 12 levels, 8 supported, 4 partially supported, 1 unsupported

Sources fetched and read: the **Risk Rating Methodology** (<https://community.owasp.org/OWASP_Risk_Rating_Methodology>), **A05:2021** and **A01:2021** (<https://top10.owasp.org/2021/…>). `A02:2021` and "OWASP IaC Security" are settled in **§3C** — the first supported on both claims, the second unsupported outright.

### Risk Rating Methodology — both claims exact

| Level | Claim | Verdict |
|---|---|---|
| `sensitivity` L4 | loss-of-confidentiality "extensive critical data disclosed, **value 7**" | **supported, verbatim** — the scale reads "extensive critical data disclosed (7)" |
| `severity` L1 | "OWASP Risk Rating Methodology **'Note'** finding" | **supported** — "Note" is a real cell in the overall severity matrix, at the low-likelihood / low-impact intersection, which coheres with this level sitting at CVSS's None band |

**I predicted `sensitivity` L4 was the claim most likely to be wrong**, because it quotes an ordinal from a less canonical scale. It is exactly right. The prediction was wrong and the citation was not.

### A05:2021 Security Misconfiguration — a real mis-location, three levels affected

A05 has two distinct lists. "The application might be vulnerable if the application is:" contains eight bullets, of which the relevant one is *"Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges)."* **"How to Prevent"** contains six, of which the first is *"A repeatable hardening process… Development, QA, and production environments should all be configured identically, with different credentials used in each environment."*

| Level | Claim | Verdict |
|---|---|---|
| `exposure` L3 | A05 "(unnecessary **public endpoints** enabled)" | **partially supported** — A05 names unnecessary *ports, services, pages*; it does not qualify them as public, and draws no public/internal distinction. "Public" is the rubric's word |
| `exposure` L4 | bare "OWASP A05:2021 Security Misconfiguration" | **supported** — unspecific, and an any-source ingress is squarely misconfiguration |
| `criticality` L1 | A05 "whose non-uniform hardening it **names as a root cause**" | **partially supported — mis-located.** The dev/QA/prod parity statement is in **How to Prevent**, a recommendation. A05's vulnerability list says "Missing appropriate security hardening across any part of the application stack", which is general, not about environment non-uniformity |
| `criticality` L3 | A05's "**environment-parity finding**" | **partially supported — same mis-location.** "Finding" is looser than "root cause" but still locates a prevention recommendation in the findings |

**Why this is worth fixing rather than waving through.** The claim is not false about the *document* — A05 does address the dev/QA/prod ladder — but it is false about *where*, and the difference matters to an examiner: a prevention recommendation is weaker evidence for an ordinal placement than a named root cause would be. The fix is a citation rewording ("A05's hardening-parity recommendation"), which the freeze permits; the level does not move.

### A01:2021 Broken Access Control — three supported, one reaching

A01 opens *"Moving up from the fifth position, 94% of applications were tested for some form of broken access control"* and its failure list includes *"Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user"*.

| Level | Claim | Verdict |
|---|---|---|
| `privilege` L5 | "A01:2021 (**top-ranked risk**)" | **supported** — A01 is first in the 2021 list, having moved up from fifth |
| `privilege` L3 | "A01:2021 **privilege-escalation**" | **supported, verbatim** — "Elevation of privilege" is a named failure type |
| `privilege` L2 | A01 "authorization confined to the function's intended scope" | **supported** — A01's least-privilege violation bullet carries it |
| `exposure` L5 | "A01:2021 Broken Access Control **and OWASP IaC Security (public object storage)**" | **partially supported.** A01 **does not mention public object or cloud storage at all** — it is application-level access control. A world-readable bucket is conceptually broken access control, so A01 supports the *category*; it does not support the parenthetical. The "OWASP IaC Security" half may carry it and is not yet read |

`exposure` L5 is the **top of the exposure ladder**, so its anchor matters more than most. The honest reading: the category anchor holds, the specific artefact claim does not, and whether the level keeps an OWASP anchor at all depends on what "OWASP IaC Security" turns out to be. **§3C settles that: it turns out to be nothing**, so L5 ends with two defective OWASP clauses and keeps its grounding from its non-OWASP anchors alone.

---

## 3B. FIPS 199 — 4 levels, 3 supported and 1 partially supported

The document's own words: *"FIPS Publication 199 defines three levels of potential impact"* — **LOW** (*"limited adverse effect"*), **MODERATE** (*"serious adverse effect"*), **HIGH** (*"severe or catastrophic adverse effect"*). A fourth *value* — not a fourth level — appears only in the security-category notation: *"the acceptable values for potential impact are LOW, MODERATE, HIGH, or NOT APPLICABLE."*

That fourth value carries **footnote 4**, which decides one of the four claims and is quoted verbatim:

> The potential impact value of not applicable only applies to the security objective of confidentiality.

| Level | Claim | Verdict |
|---|---|---|
| `criticality` L1 | "FIPS 199 **'Low' potential impact**" | **supported, verbatim** — and it coheres: FIPS's LOW is *"limited adverse effect"*, the identical phrase NIST Table H-3's Low tier uses, which this level cites beside it |
| `criticality` L4 | "FIPS 199 **'Moderate'→'High' categorization**" | **supported as a disclosed interpolation** — both level names are correct and the arrow marks a placement between them, the same notation §3.5 accepted for Table H-3's "'Low'→'Moderate' boundary". FIPS defines no such boundary construct, and the string does not claim it does |
| `criticality` L5 | "FIPS 199 **'High' potential impact**" | **supported, verbatim** — *"severe or catastrophic adverse effect"* |
| `criticality` L0 | "FIPS 199 — **below the 'Low' security-categorization floor (no meaningful confidentiality/integrity/availability objective)**" | **partially supported — the floor holds, the parenthetical is contradicted.** Three levels exist and LOW is the lowest, so there is no impact *level* beneath it. But the gloss describes NOT APPLICABLE applied across all three objectives, and footnote 4 permits it for **confidentiality only**. FIPS 199 does not admit an NA integrity or NA availability objective |

**Why L0 is worth rewording rather than waving through.** The gloss sits after the em-dash *inside* the FIPS attribution, so a reader takes it as FIPS's own construct — and FIPS has an explicit rule pointing the other way. That is the §G3 defect class exactly: a claim in the record its cited artifact does not support. The fix is available and narrower without being weaker, because FIPS genuinely does supply a below-Low value and this level genuinely is about a resource with no confidentiality stake — for instance "beneath the 'Low' floor; FIPS's NOT APPLICABLE value (confidentiality only, per footnote 4) is the nearest analogue." L0's score, `meaning` and `justification` do not move, so the freeze permits the edit.

---

## 3C. OWASP A02:2021 — both claims supported; "OWASP IaC Security" — no such resource

### A02:2021 Cryptographic Failures — 2 levels, both supported

| Level | Claim | Verdict |
|---|---|---|
| `encryption` L2 | A02 "**(formerly A03:2017 Sensitive Data Exposure)**: failure to encrypt data at rest / in transit" | **supported.** The page states it was *"previously known as Sensitive Data Exposure, which is more of a broad symptom rather than a root cause"*, and prescribes *"Make sure to encrypt all sensitive data at rest"* and *"Encrypt all data in transit with secure protocols such as TLS…"*. One qualification worth recording: the **rank** `A03:2017` is not on the A02 page, which names only the old title. The rank is corroborated from the 2017 list, where Sensitive Data Exposure was A3 — so the renaming is sourced here and the identifier is sourced elsewhere |
| `sensitivity` L5 | A02 cross-anchored for "**Secrets management**" | **supported** — A02's notable CWEs include *"CWE-259: Use of Hard-coded Password"* and *"CWE-321: Use of Hard-coded Cryptographic Key"*; its guidance names *"proper key management"* and asks whether *"crypto keys checked into source code repositories"* |

### "OWASP IaC Security" — unsupported, because no OWASP resource carries that title

`exposure` L5 cites "**OWASP IaC Security (public object storage)**". Two findings, and both run against the citation:

1. **No OWASP project or document is titled "IaC Security."** The nearest real resource is the Cheat Sheet Series' **"Infrastructure as Code Security Cheatsheet"** — that is its exact published title.
2. **That cheat sheet does not mention public object storage at all** — no publicly accessible buckets, no S3 public-access settings, no public read or write permissions on storage. Which is the one thing the rubric cites it for.

So the clause fails on both readings a charitable reader has available: as a title it names nothing, and as a pointer to the resource it most plausibly meant, it points at a document silent on the claim.

**What this costs `exposure` L5, and why the fix is still inside the freeze.** §3A already recorded L5's A01 half as partially supported, so this level's two OWASP clauses are now *both* defective — and L5 is the top of the exposure ladder, where the anchor matters most. The level nonetheless keeps its grounding: the same `source` string carries `PLAN.md` Q9's enumerated public-bucket combination, CVSS v3.1 `AV:N` + Privileges Required: None + Scope: Changed, and NIST SP 800-30 Appendix G likelihood = Very High — all verified supported in §2 and §3. **Deleting the unsupported clause removes no justification the level depends on**, which is precisely why the freeze permits it.

---

## 3D. NSA-CISA Kubernetes Hardening Guidance — cannot verify from this host

**Verdict: 11 claims unverified for want of a reachable copy of the primary source** — not because the document is paywalled (it is a free public PDF), and not for want of trying.

What was attempted, and what came back:

| Route | Result |
|---|---|
| `media.defense.gov/…/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF`, both the `/-1/-1/0/` and `/1/1/0/` path forms | HTTP **403**, body `<HTML><HEAD><TITLE>Access Denied</TITLE>` … *"You do not have permission to access … on this server"* |
| The same URLs via `curl` with a browser user-agent | the same 403 — so this is the CDN refusing automated clients, not a WebFetch limitation |
| Two `cisa.gov` paths for the same filename | HTTP **404**, a 46,886-byte HTML error page each time |

**A summary was available and was deliberately not substituted.** A MITRE-hosted GitHub mirror reproduces the guidance's control list in condensed form. Auditing a citation against a third party's summary establishes nothing about the standard's own words — it would convert this audit from verification into a transcription of someone else's reading while still *reporting* itself as verification. That is the defect class this document exists to catch, so the mirror was left unread.

The 11 claims still awaiting a primary source, recorded here so a later session need not re-derive them from the rubric:

| Level | Claim |
|---|---|
| `exposure` L2 | NodePort exposure is firewall-mediated |
| `exposure` L3 | LoadBalancer publishes a service externally |
| `exposure` L4 | "NSA cloud/network guidance" on `0.0.0.0/0` |
| `privilege` L1 | least-privilege RBAC `Role` scoped to verbs and resources (v1.2) |
| `privilege` L3 | over-permissive service account |
| `privilege` L4 | create/bind RBAC, secrets access and `pods/exec` as named escalation paths |
| `privilege` L5 | `cluster-admin` / wildcard-RBAC prohibition |
| `sensitivity` L5 | Secrets management |
| `criticality` L2 | namespace / network-policy separation of non-production from production |
| `criticality` L3 | **a negative claim** — "NSA-CISA is silent on environment ladders and is deliberately not cited at this level" |
| `encryption` L3 | etcd encryption of Secrets at rest, TLS in transit |

Two notes on that list. `criticality` L3's entry is a **negative** claim, an assertion about what the guidance does *not* say; verifying it requires reading the whole document rather than locating a passage, which makes it the most expensive of the eleven and the one least amenable to a targeted check. And `criticality` L2 and `encryption` L3 are the two whose subject matter the guidance is near-certain to cover — their risk is not existence but wording.

**What would close this**, cheapest first: a copy downloaded manually in a browser and placed on disk, after which the audit proceeds offline and this section is replaced by a verdict table; or a fetch from a different network route. Neither needs anything from the framework, and neither blocks S3b or S4.

---

## 4. What remains, and what it would take

**One standard is unverified; six clauses need rewording.**

### 4.1 The one unverified standard

**NSA-CISA Kubernetes Hardening Guidance v1.2 — 11 claims, blocked on source access** (§3D). Nothing in the framework blocks it: it needs a manually downloaded PDF or a different network route.

### 4.2 The six defective clauses — reworded, applied, committed

| Level | Clause | Defect | Section |
|---|---|---|---|
| `exposure` L3 | A05 "(unnecessary **public** endpoints enabled)" | A05 names unnecessary ports, services and pages, and draws no public/internal distinction | §3A |
| `criticality` L1 | A05 "**names as a root cause**" | mis-located — the dev/QA/prod parity statement is a How-to-Prevent recommendation | §3A |
| `criticality` L3 | A05's "**environment-parity finding**" | the same mis-location, in looser words | §3A |
| `exposure` L5 | A01 "**(public object storage)**" | A01 does not mention object or cloud storage at all | §3A |
| `exposure` L5 | "**OWASP IaC Security**" | no OWASP resource carries that title, and the nearest one is silent on the claim | §3C |
| `criticality` L0 | FIPS "**(no meaningful C/I/A objective)**" | footnote 4 permits NOT APPLICABLE for confidentiality only | §3B |

Every one was a citation-wording fix, and all six were applied in a single pass on 2026-09-30 (five `source` strings, since `exposure` L5 carried two of the clauses).

**How the freeze was enforced, rather than asserted.** The pass ran as raw-text replacement inside the JSON, and before writing anything it built a canonical snapshot of the whole document with every `source` value blanked to a placeholder, hashed it, applied the edits, and re-hashed. The two hashes are identical (`sha256 1af3d577—672fb08667`), which is a *proof* that no score, `meaning`, `justification`, range, bound or band moved — a stronger guarantee than a reviewer reading the diff, and the reason this pass needed no reviewer seat. `git diff --stat` reports 5 insertions and 5 deletions, all on `source` lines. 641 tests pass and `ruff check` is clean.

What each clause now says, in substance: `exposure` L3 names A05's actual words (ports, services, pages) and discloses that the *public* qualifier is the rubric's own; `exposure` L5 keeps A01 at category level and states plainly that A01 does not name object or cloud storage, with the "OWASP IaC Security" clause deleted outright; `criticality` L1 and L3 both attribute the dev/QA/prod parity statement to A05's *How to Prevent* guidance rather than its vulnerability list, L3 quoting it verbatim; and `criticality` L0 replaces the contradicted gloss with FIPS's real structure — beneath the LOW floor, with NOT APPLICABLE named as the nearest analogue and footnote 4's confidentiality-only restriction stated.

Note that two of the six land on `exposure` L5, the top of the exposure ladder. After the pass it keeps no OWASP anchor at all, resting on `PLAN.md` Q9, CVSS and NIST — all verified. Whether the top of that ladder *should* carry an OWASP anchor is a design question, not a citation one, and §5 puts it out of scope here.

### 4.3 When the flag flips

The six rewordings are committed, so **one condition remains**: NSA-CISA's 11 claims verified against the primary source. Until then `citations_audited` stays **`false`**, and no dissertation text quotes a `source` string that rests on NSA-CISA. The rubric's `citations_note` was updated in the same commit to say exactly this, so the artifact no longer claims that no re-verification has happened — which had itself become a claim the record did not support.

What has been established is worth stating precisely, because "verified" and "clean" are not the same claim. **Four cited documents came back with every claim supported and nothing to correct**: CVSS v3.1 (26 claims), NIST SP 800-30 Rev.1 (32), the OWASP Risk Rating Methodology (2) and OWASP A02:2021 (2) — **62 of the 86 citation claims** the rubric makes across its 33 levels. **Three yielded at least one defective clause**: OWASP A05:2021 (3 partial), OWASP A01:2021 (1 partial) and FIPS 199 (1 partial), plus the "OWASP IaC Security" clause that names nothing. That is 13 defective claims. **One could not be read at all** — NSA-CISA's 11. That is a real result on 62 claims, and it is still not the audit the flag asserts.

---

## 5. What this audit does not establish

- **That the level *definitions* are right.** The audit checks whether each `source` string accurately reports what its standard says. Whether a "0.0.0.0/0 ingress" genuinely belongs at exposure 4 rather than 3 is a design judgement the citations support but do not prove, and the structural freeze puts it out of scope here.
- **That the set of cited standards is the right set.** No check was made for a standard that *should* have been cited and was not.
- **Anything about the three taxonomy classes that map to no rubric factor** (S2's handoff, items 2, 3 and 10). That is a coverage gap in the factor set, not a citation defect, and it is S4's to rule on.
