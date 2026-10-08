# Chapter 2 — Literature Review

## 2.1 Introduction

This chapter reviews the work that the research builds on and is positioned against. It
follows the path a finding takes: from the practice of defining infrastructure in code
(Section 2.2), through the security weaknesses that practice admits (Sections 2.3 and
2.4), the tools that detect them (Sections 2.5 and 2.6) and one class of weakness that
resists simple detection (Section 2.7), to the question this dissertation is about, how
security findings are prioritized (Section 2.8). Section 2.9 compares the approaches,
and Section 2.10 states the gap.

The review draws on peer-reviewed studies, standards and the documentation of the tools
themselves. Four of the sources are preprints, for which no peer-reviewed version was
found when this chapter was written, and each is identified as such where it is used.

## 2.2 Cloud security, DevSecOps and Infrastructure as Code

Infrastructure as Code is the practice of defining infrastructure in machine-readable
files that are versioned, reviewed and applied automatically, in place of configuring
it by hand [Morris2020]. In Terraform, for example, the files are declarative: they
describe the end state of the infrastructure, and the tool works out the changes
needed to reach it [Terraform]. An interview study with 44 senior developers, from as
many companies, describes how the practice has been adopted in industry and the
engineering challenges that remain in developing, maintaining and evolving
infrastructure code [Guerriero2019].

Treating infrastructure as software makes it subject to the security practices applied
to software. The Secure Software Development Framework of NIST SP 800-218 sets out
high-level practices that are meant to be integrated into whatever development
lifecycle an organization uses, with the aim of reducing vulnerabilities in what is
released and addressing their root causes [NIST800-218]. The pipelines that apply
infrastructure code are themselves a security concern. The OWASP Top 10 CI/CD Security
Risks describes such pipelines as an efficient path to an organization's most valuable
assets, and lists insecure system configuration and inadequate identity and access
management among the ten risks [OWASP-CICD].

Within cloud security generally, misconfiguration is prominent. In the Cloud Security
Alliance's 2024 survey of more than 500 industry experts, misconfiguration and
inadequate change control ranked first among eleven threats to cloud computing, having
ranked third in the previous edition, with identity and access management second
[CSA2024]. OWASP's 2021 Top 10 likewise includes security misconfiguration as a
category of its own [OWASP-A05]. For at least one resource type the problem has been
measured at scale, in a large-scale analysis of misconfigured Amazon S3 buckets
[Continella2018].

IaC places these configuration decisions in files that exist before anything is
deployed, which is what makes pre-deployment checking possible. It is also what makes
an error reproducible across every environment a file is applied to.

## 2.3 Security weaknesses in infrastructure code

A systematic mapping study of IaC research identified defects and security flaws in
infrastructure code as areas needing further work [Rahman2019b], and a line of
empirical studies has since characterized them.

Rahman, Parnin and Williams introduced the notion of a *security smell* in IaC: a
recurring coding pattern that indicates a security weakness. From a qualitative
analysis of 1,726 scripts they identified seven such smells, including hard-coded
secrets, administrative privileges by default and the use of weak cryptographic
algorithms, and with a static analysis tool they found 21,201 occurrences in 15,232
scripts from 293 open-source repositories [Rahman2019a]. Later work generalized the
detection across languages: GLITCH translates Ansible, Chef and Puppet scripts into one
intermediate representation and detects nine smells on it, so that a detector written
once applies to all three [Saavedra2022].

For Terraform, Verdet and colleagues studied the adoption of security practices in 812
open-source projects across AWS, Azure and Google Cloud, by scanning each project with
Checkov. Access-policy practices were the most widely adopted on every provider and
encryption at rest the most neglected. Their starting observation is the one this
dissertation shares: scripting infrastructure does not automatically prevent
practitioners from introducing misconfigurations, vulnerabilities or privacy risks
[Verdet2025].

These studies establish that insecure patterns in infrastructure code are common and
detectable. Their concern is detection and prevalence. None of them addresses the order
in which detected weaknesses should be remediated.

## 2.4 Cloud and Kubernetes misconfigurations

The misconfigurations that matter in IaC fall into recognizable groups: storage that is
publicly accessible or unencrypted, network rules that admit unrestricted access,
identity policies that grant more than is needed, and container workloads that run with
more privilege than they require.

Container workloads have received the most systematic treatment. NIST SP 800-190
explains the security concerns that containers raise and makes recommendations for
addressing them when planning, implementing and maintaining container deployments
[NIST800-190]. Kubernetes itself publishes Pod Security Standards in three profiles,
Privileged, Baseline and Restricted; the Baseline profile, described as preventing
known privilege escalations, disallows privileged containers and the sharing of host
namespaces [K8s-PSS]. Empirically, Rahman and colleagues examined 2,039 Kubernetes
manifests from 92 open-source repositories and identified eleven categories of security
misconfiguration, among them absent resource limits, absent security contexts and the
activation of host IPC, with 1,051 instances in all. When ten of these were reported to
practitioners, they agreed to fix six [Rahman2023].

That last result is worth dwelling on, because it bears directly on prioritization.
Even among misconfigurations that researchers judged worth reporting, practitioners
accepted some and not others. A finding's presence in a scanner's output does not
settle whether, or how urgently, it should be fixed.

Chapter 6 reports which of these groups appear in the corpus studied here (Section
6.3.1). Its three most frequent classes are privileged container execution, missing
security contexts and absent resource limits, and the last two are among the categories
that study names.

## 2.5 Rule-based IaC security scanning

Rule-based scanners detect known misconfiguration patterns by comparing infrastructure
definitions against predefined checks. Three are used in this research.

**Checkov** describes itself as a static code analysis tool for infrastructure as code.
It supports Terraform, CloudFormation, Kubernetes, Helm, ARM templates and several
other formats, and it includes policies that relate resources to one another through an
in-memory graph of the configuration [Checkov]. **Trivy** is a general security scanner
whose scope covers container images, file systems, repositories and Kubernetes
clusters, and which reports IaC misconfigurations alongside vulnerabilities, secrets
and licences [Trivy]. **tfsec** applies static analysis to Terraform code; its
maintainers have made it part of Trivy and direct users there [tfsec].

These tools are easy to automate and run without access to a deployed environment,
which is why they suit pre-deployment checking. Their limitations for remediation
planning are of three kinds.

*Volume.* Static analysis tools have long been known to be under-used for reasons that
are not about what they detect. In an interview study of 20 developers, all of whom
considered static analysis beneficial, false positives and the way warnings were
presented were among the barriers to use [Johnson2013]. For Terraform specifically, an
experience report characterized 491 static analysis alerts from eleven repositories
into ten categories, five of them related to security, and found that practitioners'
perceptions of the alerts varied from one category to another [Hu2023b].

*Inconsistency.* Scanners disagree. A 2026 preprint compared eight Kubernetes hardening
guidelines, derived a benchmark of 79 configuration recommendations from them, and
evaluated ten static configuration scanners against it. It found substantial
disparities in which issues the scanners cover and inconsistencies in how they score
and rank the same issues, and it concluded that more standardized, transparent and
consistent approaches to risk and severity assessment are needed [Krieger2026]. This is
the closest published work to the present study's concern, and its conclusion is
effectively this dissertation's starting point. It evaluates how scanners score; it
does not propose a scoring method.

*Absence of context.* A rule fires on a pattern in a resource definition. Its severity
belongs to the rule and is the same wherever the rule fires. Whether the resource is
reachable from the internet, what it stores, and whether it serves production are not
part of the finding. Chapter 6 measures all three limitations on the scanners used
here: how often a severity is absent, how far the scanners' findings overlap, and how
often severity alone fails to distinguish cases that differ in risk.

## 2.6 Policy-as-code and governance

Policy-as-code expresses governance and security requirements as executable policies.
Open Policy Agent (OPA) is a general-purpose policy engine, a graduated project of the
Cloud Native Computing Foundation, with policies written in its own language, Rego
[OPA]. Gatekeeper brings OPA to Kubernetes as a customizable admission webhook, so that
a workload violating a policy can be refused before it is admitted to a cluster
[Gatekeeper2019].

A 2026 preprint reports what is described as the first large-scale study of
policy-as-code in open-source software, covering 399 repositories and nine tools. It
finds the tools used chiefly for governance and configuration control, and often
together, OPA with Gatekeeper in particular [Foalem2026].

Policy-as-code and rule-based scanning share a structure and a limitation. Both
evaluate a configuration against rules and report violations, and neither ranks the
violations it reports. A pipeline that fails twenty policies has told its user that
twenty things are wrong, and not which matters most. Nor are policies adopted evenly:
the study of Terraform security practices cited above reports policies that have yet to
be widely embraced in practice [Verdet2025].

## 2.7 IAM risk and privilege escalation

Identity and access management deserves separate treatment because its risks are the
least amenable to pattern matching. Whether a set of permissions is dangerous depends
on how permissions combine.

Hu and colleagues address the detection of IAM privilege escalation, in which a
principal uses the permissions it has to obtain permissions it was not meant to have.
Their approach, TAC, described in a preprint, tests for escalations from partial
knowledge of a configuration
and achieves false-negative rates competitive with approaches that require the whole
configuration [Hu2023a]. The existence of such work is itself evidence that escalation
cannot be read off a single policy statement. The difficulty is confirmed from the
provider's side: a formal model of the AWS authorization engine had to compose policies
of several types, and testing the model against the implementation and its
documentation uncovered corner cases that led to changes in the official documentation
[Barnett2025].

Two consequences follow for this research. Privilege belongs among the factors a
prioritization method considers, because a finding on a resource that confers broad
authority is more urgent than the same finding on one that confers little. And a static
reading of one policy document is a coarse estimate of privilege. The framework
presented here makes that estimate and no more (Section 5.11), and Chapter 6 shows a
case in which the coarseness decided the result.

## 2.8 Risk assessment and prioritization

Prioritizing security findings is an established problem outside IaC, and its
literature supplies both the concepts and the cautions this work relies on.

**Risk as likelihood and impact.** NIST SP 800-30 treats risk as a function of the
likelihood of a threat event and the impact should it occur, and provides
semi-quantitative scales for assessing both [NIST800-30]. The OWASP Risk Rating
Methodology applies the same decomposition to application security, estimating
likelihood and impact from named factors [OWASP-RR]. FIPS 199 categorizes information
and systems by the potential impact of a loss of confidentiality, integrity or
availability [FIPS199]. These are the sources from which the levels of the framework's
factors are drawn (Section 3.8).

**Severity scoring.** The Common Vulnerability Scoring System assigns a vulnerability a
base score from its intrinsic characteristics and maps scores to qualitative ratings.
It also defines environmental metrics, which let an organization adjust a score for its
own setting [CVSS31]. The idea that a score should be adjusted for context is thus
present in CVSS itself, although CVSS scores vulnerabilities in software and IaC
misconfigurations are generally not vulnerabilities of that kind.

**Beyond severity.** Two developments in vulnerability management are instructive. The
Exploit Prediction Scoring System estimates the probability that a vulnerability will
be exploited in the wild within twelve months of disclosure, a data-driven measure of
threat as distinct from severity [Jacobs2021]. The
Stakeholder-Specific Vulnerability Categorization replaces a numeric score with
decision trees whose outcome is a priority, one of defer, scheduled, out-of-band or
immediate, and was proposed in part to avoid problems its authors identify in the use
of CVSS [Spring2019]. A 2025 preprint surveying 82 studies of vulnerability
prioritization classifies the approaches into severity, exploitability, contextual,
predictive and aggregation methods, and concludes that adaptive, context-aware
prioritization remains an open need [Jiang2025].

Three lessons carry over. Severity is a starting point for prioritization and not a
substitute for it. Context is recognized as necessary and is the part most often left
to the user. And the output a practitioner needs is a decision about what to do, which
is why this framework maps its score to remediation categories. None of this work
concerns IaC findings, for which no exploitation data exists and the context has to be
found in, or declared alongside, the infrastructure code.

## 2.9 Comparative analysis

Table 2.1 compares the approaches reviewed against what remediation planning for IaC
findings requires.

| Approach | What it provides | What it leaves open | Role in this research |
|---|---|---|---|
| Security-smell and misconfiguration studies [Rahman2019a], [Saavedra2022], [Rahman2023], [Verdet2025] | Evidence of which insecure patterns occur and how often; detectors for them | The order in which detected weaknesses should be fixed | Motivation, and the categories of the taxonomy |
| Rule-based scanners [Checkov], [Trivy], [tfsec] | Automated pre-deployment detection of known patterns | Severity per rule, not per situation; scanners score inconsistently [Krieger2026] | The detection layer, used unchanged |
| Policy-as-code [OPA], [Gatekeeper2019] | Enforcement of organizational rules before deployment | No ranking of the violations reported | Related practice; not used |
| IAM analysis [Hu2023a], [Barnett2025] | Detection of escalation paths; exact models of authorization | Specific to IAM; not a general prioritization of findings | Justifies privilege as a factor, and marks the limit of static reading |
| Risk-assessment standards [NIST800-30], [OWASP-RR], [FIPS199] | Concepts and scales for likelihood and impact | General; not operationalized for IaC findings | Source of the factor levels |
| Vulnerability prioritization [CVSS31], [Jacobs2021], [Spring2019] | Scoring, exploit prediction and decision-oriented prioritization | Applies to software vulnerabilities, with data IaC findings lack | Model for moving beyond severity |

*Table 2.1: Approaches reviewed, against the needs of remediation planning.*

## 2.10 Research gap and summary

The literature establishes four things. Insecure patterns in infrastructure code are
common and can be detected automatically. The scanners that detect them report in
volume, disagree with one another, and attach severity to rules instead of situations.
Practitioners do not regard all reported findings as equally worth fixing. And in the
neighbouring field of vulnerability management, moving from severity towards
context-aware, decision-oriented prioritization is the recognized direction.

What this review did not find is a published method that brings these together for
IaC: one that takes the findings of several scanners, enriches each with the context of
the resource it concerns, ranks them by a scoring model whose every step can be
inspected, and is evaluated against an ordering fixed in advance. The closest work
measures the inconsistency of scanner scoring and calls for transparent and consistent
risk assessment without proposing one [Krieger2026]. This is a statement about what a
bounded search found, not a proof of absence. Commercial products that advertise
contextual prioritization were not examined.

The gap this dissertation addresses is therefore the following: **existing approaches
detect IaC misconfigurations but offer limited, and inconsistent, support for deciding
which to remediate first, and no openly specified method prioritizes multi-scanner IaC
findings by resource context.** Chapter 3 presents a framework designed to fill it, and
Chapter 4 the method by which the framework is put to the test.
