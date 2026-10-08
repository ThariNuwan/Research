# Chapter 1 — Introduction

## 1.1 Background

Cloud infrastructure is now largely defined in code. Networks, storage, identity
policies, compute and container workloads are described in machine-readable files that
are kept in version control, reviewed, and applied by automated pipelines, a practice
known as Infrastructure as Code (IaC) [Morris2020]. Terraform is a widely used example:
its configuration files are declarative, describing the end state of the infrastructure,
and one tool manages resources across many providers [Terraform]. Kubernetes manifests
play the same role for containerized workloads.

Defining infrastructure in code moves security decisions into that code. Whether a
storage bucket is public, which ports a security group opens, how broad an IAM policy
is, and whether a container runs privileged are all lines in a file, and a mistake in
one file is reproduced in every environment the file is applied to. Scripting
infrastructure does not by itself prevent such mistakes. A study of 812 open-source
Terraform projects found that adoption of security practices is uneven, with access
policies the most widely adopted and encryption at rest the most neglected
[Verdet2025], and a study of 2,039 Kubernetes manifests found 1,051 security
misconfigurations in eleven categories [Rahman2023]. Misconfiguration is not a minor
class of cloud risk: in the Cloud Security Alliance's 2024 survey of more than 500
industry experts it ranked first among the threats to cloud computing, ahead of
identity and access management [CSA2024].

Because the code exists before the infrastructure does, it can be checked before
deployment. Secure-development guidance recommends building such checks into the
development lifecycle [NIST800-218], and guidance specific to IaC recommends static
analysis of the configuration files as one of them [OWASP-IaC]. A family of open-source
scanners serves this purpose. Checkov is a static analysis tool for IaC covering
Terraform, CloudFormation, Kubernetes, Helm and other formats [Checkov]; Trivy is a
general security scanner whose scope includes IaC misconfigurations [Trivy]; and tfsec
analyses Terraform code and is now part of Trivy [tfsec]. Each compares a configuration
against a set of predefined rules and reports the violations.

Detection, however, is only the first half of the problem. A scanner run over a
realistic repository returns hundreds of findings, each with a rule identifier and, at
most, a severity label. The label is attached to the rule, not to the situation: a
finding on a publicly reachable production database holding customer records carries
the same label as the same finding on a private test resource. Which finding to fix
first is left to the reader. This dissertation is about that second half.

## 1.2 Research problem

Rule-based IaC scanners detect many misconfigurations and provide little help in
deciding their order of remediation. Three observations make the problem concrete, and
each is examined in the literature review of Chapter 2.

First, a severity label says nothing about the context that determines risk: whether
the resource is exposed, how much authority it confers, how sensitive its data is, and
how critical its environment is. Second, scanners do not agree with each other. A
recent comparison of ten Kubernetes configuration scanners found substantial
disparities in which issues they cover and inconsistencies in how they score and rank
the same issues [Krieger2026]. Third, practitioners do not treat all findings alike: a
study of 491 static analysis alerts on Terraform repositories found that practitioners'
willingness to act varied from one category of alert to another [Hu2023b]. A flat list
ordered by a tool's severity is therefore a poor guide to what should be done first.

The research problem is this: **existing IaC security scanners detect many
misconfigurations but provide limited contextual prioritization to support remediation
decisions.** A framework is needed that combines scanner findings with contextual
attributes of the affected resources and produces a justified remediation order.

## 1.3 Aim and objectives

The aim of this research is to design and evaluate a framework for risk-aware security
misconfiguration detection and prioritization in cloud Infrastructure-as-Code
environments.

The specific objectives are to:

1. Investigate common security misconfigurations and policy violations in cloud IaC
   environments.
2. Analyze the limitations of existing rule-based IaC security scanning approaches.
3. Identify contextual risk factors relevant to IaC security prioritization, including
   scanner severity, public exposure, IAM privilege scope, resource sensitivity,
   encryption status and deployment environment.
4. Design a framework that enriches scanner findings with contextual cloud security
   attributes.
5. Develop a transparent risk-scoring approach to classify findings into Critical,
   High, Medium and Low remediation priorities.
6. Evaluate the proposed framework using representative Terraform and Kubernetes
   configuration examples and compare its output with conventional scanner severity
   results.

## 1.4 Research questions

The research is guided by five questions.

1. What are the common security misconfiguration patterns found in cloud
   Infrastructure-as-Code environments?
2. What limitations exist in conventional rule-based IaC security scanners when used
   for remediation prioritization?
3. Which contextual cloud security factors are most useful for prioritizing IaC
   security findings?
4. How can a risk-aware scoring model improve the practical usefulness of IaC scanner
   outputs?
5. How does the proposed prioritization approach compare with conventional scanner
   severity outputs?

Section 7.2 answers each question and reports the outcome of each objective.

## 1.5 Research approach

The work follows a design-oriented approach, in which knowledge of a problem and its
solution is gained by building an artifact and evaluating it [Hevner2004]. The artifact
is a five-layer framework that runs existing scanners, normalizes their findings,
attaches contextual factors to each one, computes a transparent additive score and
reports a ranked list (Chapter 3). Detection is delegated to the scanners throughout:
the framework replaces none of them.

What is evaluated is the quality of the prioritization, not the accuracy of detection.
Two commitments shape the evaluation (Chapter 4). The scoring model was fixed before it
was evaluated, so that it could not be tuned towards the results. And the conditions
under which the framework's claim would fail were stated in advance, so that the
evaluation is a test and not a demonstration.

## 1.6 Scope and limitations

The research concerns pre-deployment, static analysis of IaC artifacts. The formats
evaluated are Terraform configurations and Kubernetes manifests. CloudFormation, Azure
Resource Manager templates and Helm charts fall within the framework's concept and
outside its evaluation.

Checkov, tfsec and Trivy are used as baseline scanners. The purpose is to extend the
usefulness of their output, not to replace or outperform them, and no claim is made
about detection accuracy.

The research does not attempt a complete cloud security posture management platform,
and it does not address runtime intrusion detection, malware analysis or monitoring of
deployed cloud resources. The scoring model is deliberately explainable and is not
learned from data.

The evaluation is a controlled validation on a small corpus of representative and
deliberately insecure configurations. It supports conclusions about whether the
mechanism works as designed. It does not support an estimate of the framework's
behaviour on production infrastructure, and Chapter 7 states the further limits that
the evaluation itself revealed.

## 1.7 Contributions

The dissertation makes five contributions, each stated here at the strength the
evaluation supports and set out in full in Section 7.4.

1. An explainable prioritization layer over three existing scanners, in which every
   score decomposes into six named contributions and every value that is a default is
   marked as one.
2. Two specification artifacts that stand apart from the code: a taxonomy that maps
   the rules of three scanners onto one vocabulary of misconfiguration classes, and a
   scoring rubric whose levels are anchored to published sources.
3. A method for evaluating prioritization without incident data, built on contrastive
   pairs, scenario orderings, registration of rules before results, and a harness
   independent of the artifact.
4. Measured observations about scanner output on the corpus studied, including how
   often a severity is absent and how far findings overlap.
5. Negative results reported as results: one factor that is not shown to work, priority
   bands that are not yet reliable, and an ordering that owes more to declared context
   than to context derived from code.

## 1.8 Structure of the dissertation

Chapter 2 reviews the literature on cloud and IaC security, rule-based scanning,
policy-as-code, IAM risk and risk prioritization, and identifies the gap this work
addresses. Chapter 3 presents the design of the framework and the decisions behind it.
Chapter 4 sets out the research methodology: the evaluation corpus, the oracle, the
metrics and the threats to validity. Chapter 5 describes the implementation and how it
was verified. Chapter 6 reports the evaluation. Chapter 7 answers the research
questions, states the conclusions and their limits, and proposes future work.

Sources are cited by key, in square brackets, and listed in the References.
