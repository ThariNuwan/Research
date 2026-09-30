"""Reading Terraform resource bodies, literals only.

Two measured properties of python-hcl2 8.1.4 on this corpus drive this module:

1. Block keys and string values retain their surrounding quotes, so a caller gets
   `'"aws_security_group"'` and `'"0.0.0.0/0"'`. `unquote` is therefore applied on
   every read, not occasionally.
2. Interpolations arrive as literal `${...}` strings rather than being evaluated,
   which is exactly what PLAN Q9's literals-only rule needs: an unresolved value is
   a substring check, not an inference.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2

__all__ = ["TerraformResource", "attribute", "build_index", "is_literal", "unquote"]

INTERPOLATION = "${"


def unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def is_literal(value: object) -> bool:
    """False if an interpolation appears anywhere inside `value`, at any depth."""
    if isinstance(value, str):
        return INTERPOLATION not in value
    if isinstance(value, dict):
        return all(is_literal(k) and is_literal(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(is_literal(v) for v in value)
    return True


@dataclass(frozen=True, slots=True)
class TerraformResource:
    identity: str
    type: str
    name: str
    body: dict[str, Any]
    file_path: str


def build_index(files: Iterable[Path], scan_root: Path) -> dict[str, TerraformResource]:
    """Map canonical Terraform identity to its resource body.

    A file that will not parse is skipped rather than raised, so one malformed file
    does not remove every other resource from context extraction. Its absence shows
    up as unresolved factors, which the coverage report counts.
    """
    index: dict[str, TerraformResource] = {}
    for path in files:
        try:
            with path.open(encoding="utf-8") as handle:
                document = hcl2.load(handle)
        except Exception:  # noqa: BLE001 - any parse failure is the same outcome here
            continue
        try:
            relative = path.relative_to(scan_root).as_posix()
        except ValueError:
            relative = path.name
        for block in document.get("resource", []):
            if not isinstance(block, dict):
                continue
            for raw_type, bodies in block.items():
                rtype = unquote(str(raw_type))
                if not isinstance(bodies, dict):
                    continue
                for raw_name, body in bodies.items():
                    rname = unquote(str(raw_name))
                    index[f"{rtype}.{rname}"] = TerraformResource(
                        identity=f"{rtype}.{rname}",
                        type=rtype,
                        name=rname,
                        body=body if isinstance(body, dict) else {},
                        file_path=relative,
                    )
    return index


def attribute(resource: TerraformResource, name: str) -> object | None:
    """One attribute off a resource body, or None when absent.

    Returns the raw hcl2 value, quotes and all. Callers decide whether to `unquote`
    a scalar or check `is_literal` first, because those are different questions.
    """
    if name in resource.body:
        return resource.body[name]
    return None
