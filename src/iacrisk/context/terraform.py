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

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2

from iacrisk.identity import terraform_identity

__all__ = [
    "TerraformResource",
    "attribute",
    "build_index",
    "is_literal",
    "resource_reference",
    "unquote",
]

INTERPOLATION = "${"

# A reference whose FIRST segment is one of these names a variable, a data source, a
# local, a module output or a meta-argument - none of which is a resource address, and
# none of which a literals-only read can resolve.
_NON_RESOURCE_ROOTS = frozenset(
    {"var", "data", "local", "locals", "module", "each", "count", "path", "terraform", "self"}
)

_REFERENCE = re.compile(
    r"^\$\{\s*([a-z][a-z0-9_]*)\.([A-Za-z0-9_\-]+)((?:\.[A-Za-z0-9_\-]+)*)\s*\}$"
)


def resource_reference(value: object) -> str | None:
    """The resource address a `${type.name.attr}` reference points at, or None.

    Resolving an address is **structural**, not value evaluation, and the distinction is
    what makes PLAN Q9's bounded cross-resource lookups implementable at all. In
    `bucket = aws_s3_bucket.b.id` the address `aws_s3_bucket.b` is written literally in
    the source; only the runtime value of `.id` is unknown. Refusing to read it would
    make every cross-resource pattern in the closed list unresolvable - measured on
    `corpus/authored/storage_public_exposure.tf`, where both buckets link their
    public-access-block this way, which is one of the two exposure contrastive pairs.

    Returns None for a variable, data source, local, module output or meta-argument, and
    for anything that is not a single bare reference - an expression, a function call or
    a concatenation stays unresolved.
    """
    if isinstance(value, list):
        if len(value) != 1:
            return None
        value = value[0]
    if not isinstance(value, str):
        return None
    match = _REFERENCE.match(unquote(value))
    if match is None:
        return None
    root, name, _rest = match.groups()
    if root in _NON_RESOURCE_ROOTS:
        return None
    return terraform_identity(root, name)


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
        except Exception:
            # Any parse failure is the same outcome here: skip the file. Catching
            # broadly is deliberate - hcl2 raises lark's UnexpectedToken and friends,
            # and enumerating a third-party grammar's exception types would couple this
            # module to lark's internals for no gain.
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
                    # The canonical function, not an f-string: a hand-rolled duplicate
                    # of identity.terraform_identity would drift from it silently, and
                    # the declared-context join matches on exactly its output.
                    resource_identity = terraform_identity(rtype, rname)
                    index[resource_identity] = TerraformResource(
                        identity=resource_identity,
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
        # Annotated rather than returned directly: `body` is dict[str, Any], so a bare
        # return leaks Any across this boundary and strict mypy rejects it. Widening to
        # `object` here is the point of the accessor - callers must narrow deliberately.
        value: object = resource.body[name]
        return value
    return None
