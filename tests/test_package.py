"""Smoke test: the package imports and the interpreter is the pinned one."""

import sys


def test_package_exposes_version() -> None:
    import iacrisk

    assert isinstance(iacrisk.__version__, str)
    assert iacrisk.__version__ == "0.1.0"


def test_interpreter_is_pinned_to_312() -> None:
    # Checkov 3.3.12 classifiers stop at 3.12; running 3.13 is unsupported.
    assert sys.version_info[:2] == (3, 12), (
        f"expected Python 3.12, got {sys.version_info[:2]}; run 'uv python pin 3.12' then 'uv sync'"
    )
