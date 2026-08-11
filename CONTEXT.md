# CONTEXT.md — Ubiquitous Language

Glossary for the risk-aware IaC misconfiguration prioritization framework (MSc, Univ. of Moratuwa). Terms only — no implementation details. Kept honest during design grilling.

## Finding
A single security misconfiguration reported by a baseline scanner (Checkov, tfsec, or Trivy), normalized into a common record: issue id, description, severity, affected resource, file path, remediation suggestion.

## Baseline scanner
An existing rule-based IaC scanner (Checkov / tfsec / Trivy) whose raw output the framework consumes. The framework **does not** replace these; it re-ranks their findings. Detection accuracy is delegated to them, not evaluated.

## Prioritization layer
The main research contribution. Consumes normalized Findings, enriches each with Context, computes a Risk Score, and produces ranked remediation categories. Kept separable from detection.

## Context (contextual attributes)
The non-severity risk factors attached to a Finding: Public Exposure, IAM Privilege Scope, Resource Sensitivity, Environment Criticality, Encryption Risk. Some are derivable from the IaC code; Resource Sensitivity and Environment Criticality are **not** reliably in the IaC and enter through a declared source.

## Declared context
Per-resource Context values supplied to the tool as an input (not inferred), consumed automatically. The primary evaluation path. Makes the context-entry seam explicit and testable.

## Auto-inference (second mode)
Optional mode where Resource Sensitivity / Environment Criticality are inferred from resource tags and naming conventions, with a documented default when absent. Evaluated as a limitation/future-work probe, not the primary result path.

## Risk Score
Explainable weighted-additive score over six factors (Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk). NOT machine learning. Every factor and weight is inspectable and adjustable.

## Priority category
Critical / High / Medium / Low — the mapping of a Risk Score to a remediation action band, defined by remediation *semantics* first (block deploy / fix before prod / backlog / monitor). Thresholds are **fixed a priori** from the score structure and **frozen** for the primary model; they are varied **only** in a reported sensitivity analysis, never tuned to fit the test data.

## Normalized issue-class (issue-class taxonomy)
The framework's own vocabulary of misconfiguration types, independent of any single scanner's rule IDs. Each scanner rule maps into one issue-class. Load-bearing: it is the shared key across context join, the scoring rubric, test-case design, and the dedupe key `(canonical resource, normalized issue-class, violation fingerprint)`. Scoped to the tested categories; unmapped rules become `unmapped:<scanner>:<rule_id>`, scored severity-only, reported separately as **"baseline-only informational" and excluded from prioritization-quality claims**. A change to the taxonomy ripples through all subsystems — treat it as a single source of truth.

## Violation fingerprint
The specific affected attribute or config path within a resource (e.g. one IAM action, a single security-group ingress rule, one Kubernetes container field). Part of the dedupe key so that materially different violations on the *same* resource are not collapsed into one finding.
