"""Rule-ID inventory harvest - a research instrument, NOT pipeline code.

Invokes each pinned scanner over corpus v0, stores raw JSON, and tallies
observed rule IDs and native severities.

This package deliberately does NOT build the normalized finding record of
PLAN.md layer 2. That is sub-project S3 and depends on the issue-class
taxonomy, which does not exist yet. `InventoryRow` is named to keep that
boundary visible; tests/test_architecture.py enforces it.
"""
