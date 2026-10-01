"""Layers 4 and 5 — risk scoring, banding, ranking and reporting (S4).

Enforces what the rubric already carries as data: the formula, the frozen 1-28 bounds, the
four bands with their remediation actions, four coherence rules and the per-scanner severity
table. It adds no factor and moves no boundary — the S1 structural freeze is absolute, and a
change to either is reported as sensitivity analysis (PLAN Q10), never applied here.
"""
