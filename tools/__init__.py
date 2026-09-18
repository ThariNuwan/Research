"""Package marker so `tools.harvest` is importable from tests and from `eval/`.

`tools/` is otherwise a scripts directory - `bootstrap.ps1`, `vendor_corpus.ps1`,
`capture_fixtures.ps1` and the three lockfiles. Nothing is exported here on
purpose: the only Python under `tools/` is the harvest research instrument, and
it lives in `tools.harvest`.

This file is also what makes `[tool.mypy] files = [..., "tools", ...]`
meaningful. With `tools/bin/` and `tools/cache/` excluded and no tracked Python
here, mypy exits 2 with `There are no .py[i] files in directory 'tools'`.
"""
