# Dissertation write-up

Chapter drafts for the MSc dissertation. Each chapter argues from the committed
specification and measurement record in this repository rather than restating the
proposal's intentions, and each states plainly which of its claims rest on
measurement, which on design reasoning, and which on work not yet done.

| File | Chapter | Depends on |
|---|---|---|
| `03-framework-design.md` | Framework Design | `docs/PLAN.md`, the S1/S3a design specs, `src/iacrisk/data/*.json` |
| `04-research-methodology.md` | Research Methodology | the S2 corpus design spec, `eval/ground_truth/corpus-v1.json`, `docs/PLAN.md` Q7/Q10 |
| `06-evaluation.md` | Evaluation | `artifacts/scored-corpus-v0.json`, `artifacts/scored-cases-v1.json`, `artifacts/evaluation-v1.json`, `artifacts/sensitivity-v1.json`, `eval/sensitivity_plan.json` |

Chapters 1, 2, 5 and 7 are not drafted. Chapter 6 reports the auto-inference agreement
metric as unmeasured, because the mode it measures has not been built; that section
needs revisiting if it is.

**Chapter 6's figures are regenerable, and regenerating them is how to check one.** Run
`uv run python -m tools.score.run corpus`, then `cases`, then `uv run python -m
eval.run` and `uv run python -m eval.sensitivity`, and read the figure from the JSON.
Where the chapter gives a figure "as first measured", that state is the record
committed at `9b9de59`, before the Kubernetes manifest-reader defect was corrected.

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
