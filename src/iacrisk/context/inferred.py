"""Auto-inference: sensitivity and criticality read from conventions instead of declared.

The framework's second mode (PLAN, root decision B+). On the primary path the two factors
that are not recoverable from IaC source enter by declaration; here they are read from the
conventions in `data/inference_conventions.json` - explicit tags, labels and namespaces,
and, for sensitivity only, a word in the resource's name. Nothing else in the pipeline
changes: the result is shaped like a declared-context input and goes through the same
join, so the IAM-governed inheritance rule applies to an inferred value exactly as it does
to a declared one.

**The conventions are data, and were registered before any inferred result existed.** This
module applies them and decides nothing: every key, value, word and rule is in the JSON.

Three properties keep the mode from reassuring falsely, and each is a rule in that file
rather than a habit of this code:

- **Literals only.** An interpolated tag value is not read.
- **Explicit before hint, and a hint may only raise.** A tag is used as written. A name is
  consulted only when no tag resolved, and applied only where it places the value above
  the rubric's default.
- **Ambiguity resolves nothing.** Signals that disagree fall through to the next signal
  or to the default.

**An inferred value is reported as `resolved`.** `FactorState` has no fourth state, and
adding one would change what every consumer of the scored JSON counts as evidence. The
difference is carried in the evidence string, which names the tag or word, and at document
level: an inferred run is written to its own artifact and marked `auto-inference`. A reader
must therefore not compare a low-confidence count across the two modes as though "resolved"
meant the same strength of evidence in both.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from iacrisk import rubric
from iacrisk.context.declared import join
from iacrisk.context.terraform import TerraformResource, attribute, is_literal, unquote
from iacrisk.context.value import FactorValue

__all__ = ["ORIGIN", "PATH", "Inference", "InferredValue", "conventions", "infer", "join_inferred"]

PATH = Path(__file__).resolve().parent.parent / "data" / "inference_conventions.json"

ORIGIN = "convention-inferred context"

_CONTAINER_SUFFIX = " [container="
_SEPARATORS = re.compile(r"[\s\-_.]+")
_NON_WORD = re.compile(r"[^a-z0-9]+")


@lru_cache(maxsize=1)
def conventions() -> Mapping[str, Any]:
    return MappingProxyType(json.loads(PATH.read_text(encoding="utf-8")))


def _normalize(value: str) -> str:
    return _SEPARATORS.sub("", value.lower())


def _level_table(levels: Mapping[str, Sequence[str]]) -> dict[str, int]:
    """`{normalized value: level}`. A value listed under two levels is a defect in the data
    and raises: resolving it either way would be this code choosing, not the conventions."""
    table: dict[str, int] = {}
    for level, values in levels.items():
        for value in values:
            key = _normalize(value)
            if table.setdefault(key, int(level)) != int(level):
                raise ValueError(f"{value!r} is listed under levels {table[key]} and {level}")
    return table


@dataclass(frozen=True, slots=True)
class InferredValue:
    """One inferred level, and what it was read from."""

    level: int
    source: str
    evidence: str


@dataclass(frozen=True)
class Inference:
    """Every resource the conventions resolved anything for.

    `values` holds only what was inferred: a resource with no entry, or an entry missing a
    factor, takes the default at the join. `declared` and `notes` are the two shapes
    `declared.join` consumes.
    """

    values: Mapping[str, Mapping[str, InferredValue]]

    @property
    def declared(self) -> dict[str, dict[str, int]]:
        return {
            identity: {key: value.level for key, value in entry.items()}
            for identity, entry in self.values.items()
        }

    @property
    def notes(self) -> dict[str, dict[str, str]]:
        return {
            identity: {key: value.evidence for key, value in entry.items()}
            for identity, entry in self.values.items()
        }

    def to_json(self) -> dict[str, Any]:
        return {
            identity: {
                key: {"level": value.level, "source": value.source, "evidence": value.evidence}
                for key, value in sorted(entry.items())
            }
            for identity, entry in sorted(self.values.items())
        }


# --- reading the signals --------------------------------------------------------------

_Found = dict[int, tuple[str, str]]
"""`{level: (source, evidence)}` - every distinct level a set of signals resolved to."""


def _literal_pairs(mapping: object) -> dict[str, tuple[str, str]]:
    """The literal string entries of a tag or label map: `{normalized key: (key, value)}`.

    python-hcl2 wraps some values in a one-element list and keeps the quotes on strings,
    so both are undone here. A `tags = merge(...)` expression arrives as one interpolated
    string, not a map, and yields nothing - which is the literals-only rule doing its job.
    """
    if isinstance(mapping, list) and len(mapping) == 1:
        mapping = mapping[0]
    if not isinstance(mapping, dict):
        return {}
    pairs: dict[str, tuple[str, str]] = {}
    for raw_key, raw_value in mapping.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            continue
        if not is_literal(raw_key) or not is_literal(raw_value):
            continue
        key = unquote(raw_key)
        pairs[_normalize(key)] = (key, unquote(raw_value))
    return pairs


def _explicit(
    pairs: Mapping[str, tuple[str, str]], keys: Sequence[str], table: Mapping[str, int], kind: str
) -> _Found:
    """Every level the tags or labels named by `keys` resolve to."""
    found: _Found = {}
    for convention_key in keys:
        pair = pairs.get(_normalize(convention_key))
        if pair is None:
            continue
        key, value = pair
        level = table.get(_normalize(value))
        if level is not None:
            found.setdefault(level, (kind, f"{kind} {key} = {value!r}"))
    return found


def _name_words(name: str, table: Mapping[str, int]) -> _Found:
    """Every level a whole word of `name` suggests."""
    found: _Found = {}
    for word in _NON_WORD.split(name.lower()):
        level = table.get(word)
        if level is not None:
            found.setdefault(level, ("name", f"the word {word!r} in the name {name!r}"))
    return found


def _single(found: _Found) -> InferredValue | None:
    """The one level `found` holds, or None when it holds none or several (ambiguity)."""
    if len(found) != 1:
        return None
    ((level, (source, evidence)),) = found.items()
    return InferredValue(level=level, source=source, evidence=evidence)


def _infer_one(
    pairs: Mapping[str, tuple[str, str]], namespace: str | None, name: str, kind: str
) -> dict[str, InferredValue]:
    """Both factors for one resource, by the registered order of signals."""
    rules = conventions()
    result: dict[str, InferredValue] = {}

    criticality_rules = rules["criticality"]
    criticality_table = _level_table(criticality_rules["values"])
    explicit = _explicit(pairs, criticality_rules["keys"], criticality_table, kind)
    if namespace is not None and criticality_rules["kubernetes_namespace"]:
        level = criticality_table.get(_normalize(namespace))
        if level is not None:
            explicit.setdefault(level, ("namespace", f"namespace {namespace!r}"))
    criticality = _single(explicit)
    if criticality is not None:
        result["criticality"] = criticality

    sensitivity_rules = rules["sensitivity"]
    sensitivity = _single(
        _explicit(pairs, sensitivity_rules["keys"], _level_table(sensitivity_rules["values"]), kind)
    )
    if sensitivity is None:
        # A hint is consulted only when no explicit signal resolved, and may only raise:
        # a word at or below the default is ignored rather than applied.
        hint = _single(_name_words(name, _level_table(sensitivity_rules["name_words"])))
        default = int(rubric.factors()["sensitivity"].unresolved_default)
        if hint is not None and hint.level > default:
            sensitivity = hint
    if sensitivity is not None:
        result["sensitivity"] = sensitivity
    return result


def infer(
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> Inference:
    """Apply the conventions to every indexed resource.

    Terraform reads the resource's literal `tags` and its local name. Kubernetes reads the
    resource's own `metadata.labels`, `metadata.namespace` and `metadata.name`; a
    container-scoped finding takes its workload's values at the join.
    """
    values: dict[str, Mapping[str, InferredValue]] = {}
    for identity, resource in tf_index.items():
        inferred = _infer_one(
            _literal_pairs(attribute(resource, "tags")), None, resource.name, "tag"
        )
        if inferred:
            values[identity] = inferred
    for identity, body in (k8s_index or {}).items():
        metadata = body.get("metadata")
        if not isinstance(metadata, dict):
            continue
        namespace = metadata.get("namespace")
        name = metadata.get("name")
        inferred = _infer_one(
            _literal_pairs(metadata.get("labels")),
            namespace if isinstance(namespace, str) else None,
            name if isinstance(name, str) else "",
            "label",
        )
        if inferred:
            values[identity] = inferred
    return Inference(values=values)


def join_inferred(
    identity: str, inference: Inference, tf_index: Mapping[str, TerraformResource]
) -> tuple[FactorValue, FactorValue]:
    """(sensitivity, criticality) for one finding's resource, from the inference.

    The declared-context join does the work, so an attachment resource inherits its
    governed resource's inferred values by the same rule as on the primary path. The one
    addition is Kubernetes: a container-scoped identity has no entry of its own, and reads
    its enclosing workload's.
    """
    key = identity
    if key not in inference.values:
        marker = identity.find(_CONTAINER_SUFFIX)
        if marker != -1:
            key = identity[:marker]
    return join(key, inference.declared, tf_index, origin=ORIGIN, notes=inference.notes)
