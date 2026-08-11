# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**A framework for risk-aware security misconfiguration detection and prioritization in cloud Infrastructure-as-Code (IaC) environments.**

MSc in Computer Science (Cloud Computing) research project, University of Moratuwa — Jayathissa E.A.T.N. (258243J), May 2026. This is a **design-oriented research** project: the deliverable is a technical artifact (the framework) *plus* its evaluation, not just working code. Design/implementation decisions should trace back to the research questions and objectives below.

### Core idea

Existing rule-based IaC scanners (Checkov, tfsec, Trivy) detect *many* misconfigurations but emit flat, severity-labeled findings with little context — causing alert overload and weak remediation prioritization. This framework **does not replace scanners**; it adds a prioritization layer on top of their output, enriching each finding with cloud context and producing ranked remediation categories (Critical / High / Medium / Low).

The prioritization layer is the **main research contribution**. Keep it separable from detection — it will be evaluated and revised independently.

## Architecture (5 layers)

The framework is a pipeline. Preserve this separation of concerns when implementing:

1. **IaC Input** — accept Terraform files and Kubernetes YAML manifests (CloudFormation / ARM / Helm are conceptually in scope but not the evaluation focus).
2. **Security Scanning** — run existing scanners (Checkov, tfsec, Trivy) to produce baseline findings. Tool-agnostic: parse each scanner's output into a common finding record (issue id, description, severity, affected resource, file path, remediation suggestion).
3. **Context Extraction** — enrich each finding with contextual attributes. The two factors not reliably derivable from IaC code (Resource Sensitivity, Environment Criticality) enter via a **declared-context** input on the primary evaluation path; a convention-based **auto-inference** mode is built and evaluated as a second mode. Other factors are parsed from the flagged resource definition **and bounded related resources for a closed list of supported exposure patterns** (literals-only; unresolved values are represented as an explicit `unresolved` state — conservatively scored, excluded from prioritization-quality claims, or sensitivity-analysed — never silently defaulted to low).
4. **Risk Scoring** — apply the transparent weighted additive model (below) to compute a priority score.
5. **Reporting** — rank findings and map scores to remediation priority categories.

## Risk scoring model

**Explainable weighted additive model — NOT machine learning.** Every factor and weight must be inspectable, justifiable, and adjustable. (Learning-based scoring is explicitly future work.)

```
Risk Score = Severity + Exposure + Privilege + Sensitivity + Criticality + EncryptionRisk
```

Contextual risk factors and their scoring ranges:

| Factor | Range | Meaning |
|---|---|---|
| Scanner severity | 1–5 | Baseline severity from the IaC scanner |
| Public exposure | 0–5 | Reachable from the public internet? |
| IAM privilege scope | 0–5 | Degree of sensitive/administrative permission |
| Resource sensitivity | 0–5 | Business/data sensitivity of the affected asset |
| Environment criticality | 0–5 | production vs staging vs development |
| Encryption risk | 0–3 | Required encryption/data-protection missing? |

Priority mapping (thresholds fixed a priori from the score structure and frozen before evaluation; threshold/weight movement is reported as a *sensitivity analysis*, not tuned to fit the test data):

| Priority | Score | Action |
|---|---|---|
| Critical | ≥ 22 | Block deployment, remediate immediately |
| High | 16–21 | Fix before production / require approval |
| Medium | 9–15 | Schedule in normal sprint/backlog |
| Low | < 9 | Monitor / document / fix when convenient |

Note: the additive model has a max possible score of 28 (5+5+5+5+5+3) and min of 1. If you change any factor range or add a factor, revisit the priority thresholds — they are coupled to the score ceiling.

## Evaluation

The framework is evaluated on **prioritization quality**, not detection accuracy (detection is delegated to the baseline scanners). Baseline = raw scanner severity output; framework output = the contextually re-ranked list. Test cases cover storage, networking, IAM, compute, and container workloads, built from open-source examples, benchmark repos, and deliberately-insecure configs.

Evaluation metrics: **normalization/retention coverage** (not detection accuracy — that is delegated to the scanners), **prioritization usefulness** (measured against a defined oracle: contrastive-pair pass/fail + scenario-expected ordering), **alert reduction** (reported as two separate numbers — deduplication reduction vs. Critical/High priority-band reduction, never combined), **ranking consistency** (split into auto-inference agreement and model sensitivity), and **baseline comparison** (rank-change table vs. a scanner-severity-normalized baseline, each change justified by contextual factors).

## Scope guardrails

- **In scope:** pre-deployment (static) analysis of IaC. Terraform + Kubernetes primary.
- **Out of scope:** runtime intrusion detection, malware analysis, full cloud-provider monitoring, a complete enterprise CSPM platform, multi-cloud production repos, ML-based scoring. Don't let feature work drift into these — they are named as future work.

## Current state

The repository is currently **empty** (no code, not yet under version control). No build/lint/test tooling exists yet. When it's established, update this file with the real commands — do not invent them. Python is the natural fit given the scanner ecosystem (Checkov/Trivy are Python/Go tools with JSON output), but the toolchain is not yet decided.
