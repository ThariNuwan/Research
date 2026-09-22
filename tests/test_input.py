"""Discovery decides which scanners are applicable, so misclassifying a file is not cosmetic.

The corpus makes both edges real: Chart.yaml and values.yaml parse cleanly but are
not manifests, and the metadata-db Helm templates are manifests that do not parse.
Neither may be silently ignored.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacrisk.input import DiscoveryResult, discover, is_manifest_document

REPO_ROOT = Path(__file__).resolve().parent.parent
TF_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
K8S_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def test_terraform_files_are_discovered_and_classified() -> None:
    result = discover(TF_ROOT)

    assert result.files, "no terraform files discovered"
    assert all(f.platform == "terraform" for f in result.files)
    assert all(f.relative_path.endswith(".tf") for f in result.files)


def test_relative_paths_are_scan_root_relative_and_posix() -> None:
    """The join key is the scan root, and separators are normalized (spec 5.1)."""
    result = discover(K8S_ROOT)

    for f in result.files:
        assert not f.relative_path.startswith("/")
        assert "\\" not in f.relative_path
        assert not Path(f.relative_path).is_absolute()


def test_a_yaml_without_apiversion_and_kind_is_not_a_manifest() -> None:
    """Chart.yaml parses cleanly and is not a manifest; this is what excludes it."""
    assert not is_manifest_document({"apiVersion": "v1", "description": "a chart"})
    assert not is_manifest_document({"kind": "Deployment"})
    assert not is_manifest_document(["not", "a", "mapping"])
    assert not is_manifest_document(None)
    assert is_manifest_document({"apiVersion": "apps/v1", "kind": "Deployment"})


def test_the_helm_templates_are_recorded_as_unparseable_not_ignored() -> None:
    """Four of the corpus's 22 manifests do not parse. Silence would hide them.

    They are the reason S1's <unresolved> identity path is exercised rather than
    theoretical, so discovery has to surface them as a distinct outcome from
    'this file was not YAML we care about'.
    """
    result = discover(K8S_ROOT)

    assert result.unparseable, "no unparseable files recorded"
    assert all("metadata-db" in p for p in result.unparseable), (
        f"unexpected unparseable files: {result.unparseable}"
    )


def test_kubernetes_manifests_are_discovered() -> None:
    result = discover(K8S_ROOT)

    manifests = [f for f in result.files if f.platform == "kubernetes"]
    assert manifests, "no kubernetes manifests discovered"
    names = {Path(f.relative_path).name for f in manifests}
    assert "Chart.yaml" not in names, "Chart.yaml is not a manifest"
    assert "values.yaml" not in names, "values.yaml is not a manifest"


def test_every_file_under_the_root_is_accounted_for() -> None:
    """in = discovered + ignored + unparseable. A file that vanishes is a coverage lie."""
    result = discover(K8S_ROOT)
    on_disk = {p.relative_to(K8S_ROOT).as_posix() for p in K8S_ROOT.rglob("*") if p.is_file()}
    accounted = (
        {f.relative_path for f in result.files} | set(result.ignored) | set(result.unparseable)
    )

    assert accounted == on_disk, f"unaccounted: {on_disk - accounted}"


def test_a_missing_scan_root_raises_rather_than_returning_empty() -> None:
    """An empty result for a bad path would read as 'a clean scan'."""
    with pytest.raises(FileNotFoundError):
        discover(REPO_ROOT / "no" / "such" / "root")


def test_discovery_result_is_frozen() -> None:
    result = discover(TF_ROOT)
    assert isinstance(result, DiscoveryResult)
    assert isinstance(result.files, tuple)
