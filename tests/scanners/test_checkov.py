"""Checkov: the scanner whose `resource` field is polymorphic (design spec §5, §2.1).

Across corpus v0's 489 failed checks, `resource` carries five different shapes -
a Terraform address, a Dockerfile path, a provider block, a 40-hex secret hash,
and a Kubernetes `Kind.namespace.name[.extra]` triple or quadruple - and none of
that shape is announced by a field name; it has to be read off the string.
`classify_resource` is that reading, and its order is load-bearing (task brief):
a secret hash must be caught before anything else looks at the string, a
Dockerfile path before the terraform/kubernetes address patterns, and terraform
before the fallback, or a value gets a wrong-but-plausible kind instead of the
right one.

The corrected reading of the four-component Kubernetes form gets the most
coverage here on purpose. An earlier draft of the spec and this task's brief
called `Kind.namespace.name.container` a container address; Task 3's implementer
measured it against the manifests and found the fourth component is the pod
template's label rendered `key-value`, in 10 of 10 cases, and that checkov's own
`Kind` for the form is always the synthesized `Pod` rather than the workload's
real kind. Both mistakes would silently produce a wrong resource identity, so
the tests below check the *resolved* identity against the real corpus manifests,
not just that a container component is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iacrisk import identity, taxonomy
from iacrisk.input import discover
from iacrisk.resources import ResourceIndex, build_index
from iacrisk.scanners.base import AdapterResult
from iacrisk.scanners.checkov import CheckovAdapter, classify_resource, fingerprint_from

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "harvest" / "fixtures"
TERRAFORM_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "terragoat" / "terraform" / "aws"
KUBERNETES_SCAN_ROOT = REPO_ROOT / "corpus" / "vendor" / "kubernetes-goat" / "scenarios"


def _load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _raw_failed_checks(name: str) -> list[dict[str, Any]]:
    """Every `failed_checks` entry across every block of one fixture.

    Read independently of `CheckovAdapter`, by walking the same JSON shape the
    adapter walks rather than by asking the adapter what it saw - so the `in`
    side of `in == out + dropped` is not the adapter grading its own homework.
    """
    checks: list[dict[str, Any]] = []
    for document in _load_fixture(name):
        results = document.get("results") or {}
        checks.extend(results.get("failed_checks") or [])
    return checks


def _kubernetes_index() -> ResourceIndex:
    return build_index(discover(KUBERNETES_SCAN_ROOT))


def _terraform_result() -> AdapterResult:
    return CheckovAdapter().parse(
        _load_fixture("checkov-terraform.json"), TERRAFORM_SCAN_ROOT, None
    )


def _kubernetes_result() -> AdapterResult:
    return CheckovAdapter().parse(
        _load_fixture("checkov-kubernetes.json"), KUBERNETES_SCAN_ROOT, _kubernetes_index()
    )


# --- classify_resource: the string-shape classifier, order and all -----------------


def test_a_terraform_address_is_context_eligible() -> None:
    """`aws_db_instance.default` is a real corpus v0 value (§1); a resource this
    concrete is exactly what S3b's context join needs a target for."""
    resource_identity, identity_kind, context_eligible = classify_resource(
        "aws_db_instance.default", "CKV_AWS_16", "terraform"
    )
    assert identity_kind == "terraform"
    assert context_eligible is True
    assert resource_identity == "aws_db_instance.default"


def test_a_40_hex_value_is_a_secret_and_not_context_eligible() -> None:
    """One of corpus v0's four terraform `CKV_SECRET_2` hashes (§2.1)."""
    _, identity_kind, context_eligible = classify_resource(
        "25910f981e85ca04baf359199dd0bd4a3ae738b6", "CKV_SECRET_2", "terraform"
    )
    assert identity_kind == "secret"
    assert context_eligible is False


def test_a_dockerfile_resource_is_a_file_and_not_context_eligible() -> None:
    """One of corpus v0's two terraform `CKV_DOCKER_*` findings (§2.1)."""
    _, identity_kind, context_eligible = classify_resource(
        "/resources\\Dockerfile.", "CKV_DOCKER_2", "terraform"
    )
    assert identity_kind == "file"
    assert context_eligible is False


def test_a_provider_block_is_not_misread_as_a_terraform_address() -> None:
    """`aws.plain_text_access_keys_provider` is corpus v0's one provider block
    (§1 measured fact 3), and it is exactly `<lower>.<lower>` the way a real
    terraform address is - the only structural difference is that no real
    terraform resource *type* is a bare provider name with no underscore in it;
    every one of the 42 real addresses in corpus v0 is `<provider>_<resource>`.
    Without that check this value reads as a resource with nothing to tell it
    apart from `aws_db_instance.default`.
    """
    _, identity_kind, context_eligible = classify_resource(
        "aws.plain_text_access_keys_provider", "CKV_AWS_41", "terraform"
    )
    assert identity_kind == "provider"
    assert context_eligible is False


def test_a_kubernetes_triple_is_context_eligible() -> None:
    """The plain three-component form, unaffected by the four-component erratum."""
    _, identity_kind, context_eligible = classify_resource(
        "Deployment.default.build-code-deployment", "CKV_K8S_43", "kubernetes"
    )
    assert identity_kind == "kubernetes"
    assert context_eligible is True


# --- fingerprint_from: discard the meta-key, preserve case, sort, join -------------


@pytest.mark.parametrize(
    ("evaluated_keys", "expected"),
    [
        ([], None),
        (["resource_type"], None),
        (["storage_encrypted"], "storage_encrypted"),
        (["kms_key_id", "storage_encrypted"], "kms_key_id,storage_encrypted"),
        (["storage_encrypted", "kms_key_id"], "kms_key_id,storage_encrypted"),
        (["resource_type", "storage_encrypted"], "storage_encrypted"),
    ],
    ids=[
        "empty",
        "only-meta-key",
        "one-key",
        "two-keys-sorted",
        "two-keys-unsorted",
        "meta-plus-one",
    ],
)
def test_fingerprint_from_discards_the_meta_key_and_sorts(
    evaluated_keys: list[str], expected: str | None
) -> None:
    assert fingerprint_from(evaluated_keys) == expected


def test_fingerprint_from_a_real_checkov_record() -> None:
    """`CKV_AWS_16` on `aws_db_instance.default` carries exactly `["storage_encrypted"]`
    in corpus v0 - the single-key case grounded in an actual fixture row rather
    than only the parametrized examples above.
    """
    raw_checks = _raw_failed_checks("checkov-terraform.json")
    check = next(c for c in raw_checks if c["check_id"] == "CKV_AWS_16")
    assert check["check_result"]["evaluated_keys"] == ["storage_encrypted"]
    assert fingerprint_from(check["check_result"]["evaluated_keys"]) == "storage_encrypted"


# --- retention: every input finding becomes exactly one finding or one drop --------


def test_every_terraform_finding_is_retained_or_dropped() -> None:
    raw_checks = _raw_failed_checks("checkov-terraform.json")
    result = _terraform_result()
    assert len(raw_checks) == len(result.findings) + len(result.dropped)


def test_every_kubernetes_finding_is_retained_or_dropped() -> None:
    raw_checks = _raw_failed_checks("checkov-kubernetes.json")
    result = _kubernetes_result()
    assert len(raw_checks) == len(result.findings) + len(result.dropped)


def test_nothing_is_dropped_in_corpus_v0() -> None:
    """§1: `resource` is present on 221/221 and 268/268. Both fixtures carry
    `check_id` on every failed check too, so `dropped` should be empty on both -
    asserted directly rather than assumed from the identity-present column, since
    that column is about `resource`, not `check_id`.
    """
    assert _terraform_result().dropped == ()
    assert _kubernetes_result().dropped == ()


# --- severity: absent on every checkov finding, carried as the explicit unknown ----


def test_native_severity_is_none_and_severity_level_is_unknown() -> None:
    """Driven from the fixtures' own absent `severity` field, not from the 46.4%
    corpus-wide rate CLAUDE.md quotes - that rate is checkov's contribution to a
    cross-scanner corpus statistic, not a claim this adapter's tests should restate.
    """
    raw_checks = _raw_failed_checks("checkov-terraform.json") + _raw_failed_checks(
        "checkov-kubernetes.json"
    )
    assert raw_checks
    assert all(check.get("severity") is None for check in raw_checks)

    for result in (_terraform_result(), _kubernetes_result()):
        assert result.findings
        for finding in result.findings:
            assert finding.native_severity is None
            assert finding.severity_level == "unknown"


# --- issue class: the taxonomy join, unmodified -------------------------------------


def test_issue_class_comes_from_the_taxonomy_for_a_known_rule() -> None:
    result = _terraform_result()
    known = next(f for f in result.findings if f.rule_id == "CKV_AWS_16")
    assert known.issue_class == taxonomy.class_for("checkov", "CKV_AWS_16")
    assert not known.is_unmapped


def test_an_unrecognized_rule_id_takes_the_unmapped_fallback() -> None:
    """A minimal, hand-built document - corpus v0 maps all 128 `CKV_*`/`CKV2_*`
    ids it contains (§1), so this rule id has to be invented rather than found.
    """
    raw = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_INVENTED_999999",
                        "check_name": "not a real checkov rule",
                        "check_result": {"result": "FAILED", "evaluated_keys": []},
                        "file_path": "/made-up.tf",
                        "file_line_range": [1, 2],
                        "resource": "aws_made_up_thing.example",
                        "severity": None,
                        "guideline": None,
                    }
                ]
            },
        }
    ]
    result = CheckovAdapter().parse(raw, TERRAFORM_SCAN_ROOT, None)
    (finding,) = result.findings
    assert finding.is_unmapped
    assert finding.issue_class == "unmapped:checkov:CKV_INVENTED_999999"


# --- the label erratum: the four-component form resolves to the workload ----------


def test_build_code_deployment_resolves_to_the_workload_with_no_container() -> None:
    """The exact example the erratum names (§4): `Pod.default.build-code-deployment.
    app-build-code`'s real manifest kind is `Deployment`, and `app-build-code` is
    the pod template's label `app: build-code`, not its one container (also named
    `build-code`, which is itself further evidence the fourth component is not a
    container name - a real container address would have said so).
    """
    result = _kubernetes_result()
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "CKV2_K8S_6" and f.resource_identity.endswith("/build-code-deployment")
    )
    assert "[container=" not in finding.resource_identity
    assert finding.identity_kind == "kubernetes"
    assert finding.resource_identity != identity.UNRESOLVED


def test_internal_proxy_deployment_resolves_to_the_workload_with_no_container() -> None:
    """The erratum's own settling example (§4): `internal-proxy-deployment`'s two
    real containers are `info-app` and `internal-api`; the checkov value's fourth
    component, `app-internal-proxy`, is neither - so a container address is not
    just unproven here, it is contradicted by the manifest.
    """
    result = _kubernetes_result()
    finding = next(
        f
        for f in result.findings
        if f.rule_id == "CKV2_K8S_6" and f.resource_identity.endswith("/internal-proxy-deployment")
    )
    assert "[container=" not in finding.resource_identity


def test_every_ckv2_k8s_6_finding_resolves_without_a_container_component() -> None:
    """CKV2_K8S_6 is pod-level (§4), so none of its findings should carry a
    `[container=...]` component - whether or not checkov's own `resource` string
    happened to carry the fourth (label) component for that particular workload.
    Two of corpus v0's twelve `CKV2_K8S_6` findings have no fourth component at
    all (their pod templates carry no matching label), and those two still need
    the by-line fallback because checkov's synthesized `Kind` is `Pod` either way,
    never the workload's real kind.
    """
    raw_checks = _raw_failed_checks("checkov-kubernetes.json")
    pod_level = [c for c in raw_checks if c["check_id"] == "CKV2_K8S_6"]
    assert pod_level  # corpus v0 exercises this; an empty list would vacuously pass the rest

    result = _kubernetes_result()
    resolved = [f for f in result.findings if f.rule_id == "CKV2_K8S_6"]
    assert len(resolved) == len(pod_level)
    for finding in resolved:
        assert "[container=" not in finding.resource_identity
        assert finding.resource_identity != identity.UNRESOLVED


# --- unresolved kubernetes identity: context_eligible follows the downgraded kind --


def test_an_unresolvable_kubernetes_identity_is_context_ineligible() -> None:
    """Corpus v0 does not exercise this branch: every checkov kubernetes finding
    in the fixtures resolves by address or by line, and none of the 4
    unparseable `metadata-db/templates/` files produces a checkov finding at
    all. So this case - a kubernetes-shaped `resource` that fails both
    `by_address` and `by_line` - is constructed directly against an empty
    index rather than found in the corpus.

    A finding like this must not be `context_eligible`: nothing was actually
    resolved, and marking it eligible would let S3b default every context
    factor and float it to a "High" that reflects nothing but the washout
    (spec §2.1).
    """
    raw = [
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_43",
                        "check_name": "made up for this test",
                        "check_result": {"result": "FAILED", "evaluated_keys": []},
                        "file_path": "/made-up.yaml",
                        "file_line_range": [1, 2],
                        "resource": "Deployment.default.nowhere",
                        "severity": None,
                        "guideline": None,
                    }
                ]
            },
        }
    ]
    empty_index = ResourceIndex(entries=(), unparseable=())
    result = CheckovAdapter().parse(raw, KUBERNETES_SCAN_ROOT, empty_index)
    (finding,) = result.findings
    assert finding.resource_identity == identity.UNRESOLVED
    assert finding.identity_kind == "unresolved"
    assert finding.context_eligible is False


# --- path handling: checkov's own leading-separator spelling is rebased -----------


def test_file_path_is_rebased_scan_root_relative() -> None:
    """checkov emits `\\db-app.tf` for this file (measured in corpus v0's fixture);
    a leading separator surviving into the record would make it a different join
    key from trivy's and tfsec's spelling of the same file (spec §5.1).
    """
    result = _terraform_result()
    assert any(f.file_path == "db-app.tf" for f in result.findings)
    assert not any(f.file_path.startswith(("/", "\\")) for f in result.findings)


# --- file identity: cross-scanner agreement with trivy on the same Dockerfile -----


def test_dockerfile_identity_has_no_trailing_dot_and_matches_trivys() -> None:
    """checkov's raw `resource` for both `CKV_DOCKER_*` findings is
    `/resources\\Dockerfile.` - trailing dot and all - but `resource_identity`
    here is built from the rebased `file_path` instead, which has no such
    decoration. That is what lets it meet trivy's identity for the same file
    (`DS-0002`/`DS-0026` resolve to `resources/Dockerfile` too): a bare
    normalization of the raw `resource` string would leave the trailing dot in
    place and put the two adapters' identities for one Dockerfile one
    character apart, silently defeating Task 8's cross-scanner join. A future
    reader should not "tidy" this back to the raw value.
    """
    result = _terraform_result()
    dockerfile_findings = [f for f in result.findings if f.identity_kind == "file"]
    assert len(dockerfile_findings) == 2  # CKV_DOCKER_2 and CKV_DOCKER_3, corpus v0's only two
    for finding in dockerfile_findings:
        assert finding.resource_identity == "resources/Dockerfile"
        assert not finding.resource_identity.endswith(".")
