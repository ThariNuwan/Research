# Dissertation write-up

Chapter drafts for the MSc dissertation. Each chapter argues from the committed
specification and measurement record in this repository rather than restating the
proposal's intentions, and each states plainly which of its claims rest on
measurement, which on design reasoning, and which on work not yet done.

| File | Chapter | Depends on |
|---|---|---|
| `01-introduction.md` | Introduction | the proposal (problem, objectives, research questions, scope), `references.md` |
| `02-literature-review.md` | Literature Review | `references.md`, and only the sources listed there |
| `03-framework-design.md` | Framework Design | `docs/PLAN.md`, the S1/S3a design specs, `src/iacrisk/data/*.json` |
| `04-research-methodology.md` | Research Methodology | the S2 corpus design spec, `eval/ground_truth/corpus-v1.json`, `docs/PLAN.md` Q7/Q10 |
| `05-implementation.md` | Implementation | the code under `src/iacrisk/`, `tools/` and `eval/`, the committed captures under `tests/harvest/fixtures/`, and the test suite |
| `06-evaluation.md` | Evaluation | the seven records under `artifacts/` that its Section 6.1 lists, `eval/sensitivity_plan.json`, `src/iacrisk/data/inference_conventions.json` |
| `07-conclusion.md` | Conclusion | Chapters 3 to 6, and through them the records under `artifacts/` |
| `references.md` | References | 35 sources, each with how far it was checked |

**All seven chapters are drafted.** Chapters 1 and 2 were drafted on 2026-10-08 from the
proposal's text and a reference list rebuilt source by source. Chapters 3 to 7 do not yet
use the citation keys: they name their standards in prose, and bringing them onto
`references.md` is a pass still to do. **Chapter 7 is drafted in full.** Its Section 7.2
answers the five research questions and six objectives in the proposal's own words, and
records five places where the work departed from the proposal. Chapter 7 introduces no
figure of its own: every number in it is one Chapters 3 to 6 already report, cited by
section, so a figure that changes there must be changed in Chapter 7 too.

**The proposal is the source for the research questions, the objectives and the first
drafts of Chapters 1 and 2, and its reference list cannot be reused as it stands.** Of
its 47 entries, 27 are cited in the text and 20 are never cited. Among the 27, about
ten citations point to a different work from the one the sentence describes: the
citations given for Checkov, Trivy, tfsec, Open Policy Agent, the NSA and CISA cloud
guidance, NIST SP 800-30 and CVSS all resolve to unrelated papers. Two table references
are unresolved. Chapters 1 and 2 must therefore be written against sources that have
each been checked, not by carrying the proposal's citation numbers across. The proposal
also describes itself in places as a postgraduate diploma project; that wording must
not reach the MSc dissertation.

**Three rules for the reference list.** `references.md` records, for every source, how
far it was checked: primary text read, abstract read, or bibliographic record confirmed.
No paper's full text was read in building it, so every sentence about a paper in
Chapters 1 and 2 claims only what the paper's abstract supports, and the author must
read each cited work before submission. A source is added by checking it and recording
the level, never by copying an entry from a search result or a reference manager. And a
source that cannot be checked is listed as such and not cited: two are, both NSA
documents this host cannot retrieve.

**Chapter 5's counts are of the repository as it stood on 2026-10-08**, at the commit
that introduced `src/iacrisk/cli.py`, and each is re-derivable: file and line counts from `git ls-files`
over `src/iacrisk`, `tools`, `eval` and `tests`; the test count from `uv run pytest
--collect-only`; the gate count from the distinct `test_gate_<n>` numbers in each
`tests/test_s*_gates.py`; and the scanner-shape figures of its Section 5.5.2 from the
captures. They will drift as code is added, so re-count before submission.

**Chapter 6's figures are regenerable, and regenerating them is how to check one.** Run
`uv run python -m tools.score.run corpus`, then `cases`, then `inferred`; then `uv run
python -m eval.run`, `eval.sensitivity` and `eval.agreement`; and read the figure from
the JSON.
Where the chapter gives a figure "as first measured", that state is the record
committed at `9b9de59`, before the Kubernetes manifest-reader defect was corrected.

**Chapter 6 was revised after a pre-merge code review, and says where.** The review was
by a separate automated reviewer. It changed no figure; it added the figures over the
246 findings that are not low-confidence, and the passages marked "added after review"
that say how much of the ordering evidence is declared instead of derived. Those
passages are the ones a later edit is most likely to soften. Do not: each states
something the records show.

**Chapter numbering is provisional.** It assumes 1 Introduction, 2 Literature
Review, 3 Design, 4 Methodology, 5 Implementation, 6 Evaluation, 7 Conclusion.
If the final structure merges design and methodology, or places implementation
before methodology, renumber both files and the cross-references inside them.

## Two standing rules for editing these chapters

**Every number traces to a committed artifact.** Figures in these chapters were
read from `artifacts/rule-inventory.json`, `eval/ground_truth/corpus-v1.json`,
`src/iacrisk/data/rubric.json`, or a named spec, not carried over from an earlier
draft. When a figure changes in the artifact, change it here and re-derive
anything computed from it. Four false numbers were found in this project's own
citation-audit record, every one of them a figure produced by a shortcut rather
than by counting the thing the sentence named; the same failure in a submitted
chapter is an examiner's finding, not a housekeeping note.

**Do not quote a rubric `source` string that rests on NSA-CISA.** The citation
audit (`docs/superpowers/specs/2026-09-30-rubric-citation-audit.md`) verified 69
of the rubric's 86 citation claims and corrected 6, but the 11 NSA-CISA claims
remain unverified because the primary source is unreachable from the build host.
`rubric.json` carries `citations_audited: false` for that reason alone.
