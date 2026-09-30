# Rubric citation audit — CVSS v3.1 and NIST SP 800-30 Rev.1 complete

**Status:** PARTIAL — CVSS, NIST and most of OWASP done; NSA-CISA, FIPS 199, OWASP A02 and "OWASP IaC Security" outstanding. `citations_audited` stays **`false`**, and **four levels now carry partially-supported citations that need rewording** (§3A).
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
| OWASP A02:2021 + "OWASP IaC Security" | 3 | **not yet verified** |
| NSA-CISA Kubernetes Hardening Guidance | 11 | **not yet verified** |
| FIPS 199 | 4 (`criticality` L0, L1, L4, L5) | **not yet verified** |

### Erratum, 2026-09-30 — two false claims in the first version of this table

The first version of this document listed a fifth outstanding standard, **"CIS Benchmarks | 10 levels"**, and gave FIPS 199 as **2** levels. Both are wrong, and they were wrong in the audit record whose entire purpose is catching claims a cited artifact does not support.

- **`rubric.json` cites CIS Benchmarks zero times.** The count came from a script matching the substring `CIS`, which matches inside **`NSA-CISA`** — all 11 hits were the Kubernetes Hardening Guidance. There is no CIS Benchmark citation anywhere in the file, so the paragraph the first version wrote about CIS's registration barrier described a problem this rubric does not have.
- **FIPS 199 is cited on four levels**, not two: `criticality` L0, L1, L4 and L5.

Measured directly: `CIS Benchmark` → 0 occurrences; `CIS` not preceded by `NSA-` → 0; `NSA-CISA` → 11. Levels per standard: CVSS 26, NIST 32, OWASP 12, NSA 11, FIPS 4.

**Consequence of the error, had it stood:** the audit would have reported a standard as unverifiable that is not cited, inflating the apparent outstanding work and — worse — leaving a reader to believe the rubric leans on a paywalled source. **Three** standards remain, not four, and none of them is paywalled.

**The flag stays `false`.** Every level carries claims against more than one standard, so no level is fully audited until its OWASP / NSA-CISA / CIS / FIPS components are checked too. A flag flipped now would assert an audit that covered two of six standards.

**Nothing was corrected.** Every CVSS and NIST claim checked reproduced exactly against the primary source. No citation string was edited, and no level's score, `meaning` or `justification` was touched — the structural freeze forbids the latter absolutely, and the former turned out not to need it.

---

## 1. Sources actually fetched and read

- **CVSS v3.1 Specification Document**, <https://www.first.org/cvss/v3.1/specification-document> — Table 14 (Qualitative Severity Rating Scale), Table 16 (Attack Vector weights), Table 5 (Scope), Table 12 (Confidentiality Requirement).
- **NIST SP 800-30 Rev.1**, *Guide for Conducting Risk Assessments*, <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf> — 95 pages, text extracted and read directly. Tables read verbatim: **G-2** (p82), **G-3**, **G-4**, **H-3** (p85), **I-2** (p86), **I-3** (p87), and **D-3/D-4/D-5** (p67).

The NIST PDF would not render (no poppler on this host) and WebFetch returned raw stream data, so the text was extracted with an ephemeral `pypdf` under `uv run --with` — no project dependency was added.

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

## 3A. OWASP — 12 levels, 9 supported and 4 partially supported

Sources fetched and read: the **Risk Rating Methodology** (<https://community.owasp.org/OWASP_Risk_Rating_Methodology>), **A05:2021** and **A01:2021** (<https://top10.owasp.org/2021/…>). `A02:2021` and "OWASP IaC Security" remain unread.

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

`exposure` L5 is the **top of the exposure ladder**, so its anchor matters more than most. The honest reading: the category anchor holds, the specific artefact claim does not, and whether the level keeps an OWASP anchor at all depends on what "OWASP IaC Security" turns out to be.

---

## 4. What remains, and what it would take

Three standards are unverified, covering claims on every one of the 33 levels:

1. **OWASP A02:2021 Cryptographic Failures** (`sensitivity` L5, `encryption` L2 — the latter also claims A02 was "formerly A03:2017 Sensitive Data Exposure", a renaming claim worth checking) **and "OWASP IaC Security"** (`exposure` L5 — establish first whether this names a real OWASP resource; if it is the IaC Security Cheat Sheet, say so, and if no such resource exists the citation is unsupported).
2. **NSA-CISA Kubernetes Hardening Guidance (v1.2)** — cited for NodePort and LoadBalancer exposure semantics, least-privilege RBAC, named escalation paths (create/bind RBAC, secrets access, pods/exec), the cluster-admin / wildcard-RBAC prohibition, and Secrets management. Publicly fetchable as PDF.
3. **FIPS 199** — four levels: `criticality` L0 ("below the 'Low' security-categorization floor"), L1 ("'Low' potential impact"), L4 ("'Moderate'→'High' categorization") and L5 ("'High' potential impact"). Short document, publicly fetchable.

**The flag flips only when all three are done and every level lands at supported.** If any component ends unsupported or unverifiable, the flag stays `false` and the affected `source` strings must be corrected or the dissertation must not quote them.

---

## 5. What this audit does not establish

- **That the level *definitions* are right.** The audit checks whether each `source` string accurately reports what its standard says. Whether a "0.0.0.0/0 ingress" genuinely belongs at exposure 4 rather than 3 is a design judgement the citations support but do not prove, and the structural freeze puts it out of scope here.
- **That the set of cited standards is the right set.** No check was made for a standard that *should* have been cited and was not.
- **Anything about the three taxonomy classes that map to no rubric factor** (S2's handoff, items 2, 3 and 10). That is a coverage gap in the factor set, not a citation defect, and it is S4's to rule on.
