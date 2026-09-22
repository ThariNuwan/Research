"""Layer 1: discover IaC files under a scan root and classify their platform (design spec §3).

Platform classification is what decides which scanners are applicable later in
the pipeline, so it is not cosmetic: `tools/scanners.lock.json` declares tfsec
as `["terraform"]` only, so a file misclassified here changes what actually
gets scanned. This module only decides *what* a file is; it never runs a
scanner and never reads that lockfile itself - that matrix belongs to Task 10.

Every file under the scan root must land in exactly one of `files`, `ignored`
or `unparseable` - there is no fourth, silent bucket. The Kubernetes corpus is
why that partition has to be enforced rather than assumed: `Chart.yaml` and
`values.yaml` parse cleanly but carry no `kind`, so they are `ignored`; the
`metadata-db` Helm chart's four templates carry Go template syntax that is not
valid YAML at all, so they are `unparseable` - a distinct outcome, not folded
into `ignored`, because collapsing them would erase the one case in the corpus
that exercises `identity.UNRESOLVED` for real rather than in theory.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TERRAFORM_SUFFIXES = (".tf",)
MANIFEST_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True)
class DiscoveredFile:
    """One file discovery has classified as IaC, ready to hand to a scanner adapter.

    `relative_path` is scan-root-relative and POSIX-style - the join key this
    sub-project standardizes on (spec §5.1), because it is the one spelling
    checkov and trivy already emit natively, and the one tfsec's absolute
    paths are rebased onto by Task 4's path handling.
    """

    path: Path
    relative_path: str
    platform: str


@dataclass(frozen=True)
class DiscoveryResult:
    """The full accounting of one `discover()` walk: a partition, not just a hit list.

    `files`, `ignored` and `unparseable` are disjoint and exhaustive over every
    file under the scan root. Task 9's retention report computes coverage rates
    from these three collections, so a file that fell out of all of them here
    would silently inflate every rate downstream rather than showing up as a gap.
    """

    files: tuple[DiscoveredFile, ...]
    ignored: tuple[str, ...]
    unparseable: tuple[str, ...]


def is_manifest_document(doc: object) -> bool:
    """Whether a parsed YAML document is a Kubernetes manifest rather than incidental YAML.

    Requires both `apiVersion` and `kind` to be present and truthy (spec §3).
    That two-field test is what excludes `Chart.yaml`, which carries an
    `apiVersion` but no `kind`, and `values.yaml`, which carries neither - both
    parse without error and both are real files in the corpus, so the test has
    to be positive evidence of "this is a manifest" rather than absence of a
    reason to reject it.
    """
    return isinstance(doc, dict) and bool(doc.get("apiVersion")) and bool(doc.get("kind"))


def discover(scan_root: Path) -> DiscoveryResult:
    """Walk `scan_root` and classify every file into exactly one output bucket.

    `*.tf` is terraform unconditionally. `*.yaml`/`*.yml` is a *candidate*
    Kubernetes manifest, confirmed only if at least one parsed document in the
    file satisfies `is_manifest_document` - a multi-document file (`---`
    separated) counts as a manifest file if any document in it does, since the
    file as a whole is what a scanner operates on. A YAML file that fails to
    parse at all is `unparseable`, distinct from one that parses but contains
    no manifest document (`ignored`). Everything else (READMEs, Dockerfiles,
    lockfiles, ...) is `ignored` too.

    Raises `FileNotFoundError` for a missing or non-directory root rather than
    returning an empty `DiscoveryResult`, which would be indistinguishable from
    a scan that found nothing to flag.
    """
    if not scan_root.is_dir():
        raise FileNotFoundError(f"scan root does not exist or is not a directory: {scan_root}")

    files: list[DiscoveredFile] = []
    ignored: list[str] = []
    unparseable: list[str] = []

    for path in sorted(p for p in scan_root.rglob("*") if p.is_file()):
        rel = path.relative_to(scan_root).as_posix()
        suffix = path.suffix.lower()

        if suffix in TERRAFORM_SUFFIXES:
            files.append(DiscoveredFile(path=path, relative_path=rel, platform="terraform"))
            continue

        if suffix not in MANIFEST_SUFFIXES:
            ignored.append(rel)
            continue

        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
        except yaml.YAMLError:
            unparseable.append(rel)
            continue

        if any(is_manifest_document(d) for d in docs):
            files.append(DiscoveredFile(path=path, relative_path=rel, platform="kubernetes"))
        else:
            ignored.append(rel)

    return DiscoveryResult(
        files=tuple(files), ignored=tuple(ignored), unparseable=tuple(unparseable)
    )
