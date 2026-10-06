"""`iacrisk.context.inferred`: the registered conventions, applied to constructed resources.

Every resource here is hand-built. These tests were committed with the conventions, before
the mode had been run over the real corpus, so that what the conventions do could be pinned
without anyone having seen what they produce there.
"""

from __future__ import annotations

from typing import Any

import pytest

from iacrisk import rubric
from iacrisk.context import inferred
from iacrisk.context.declared import join
from iacrisk.context.extract import contextualize
from iacrisk.context.inferred import ORIGIN, Inference, conventions, infer, join_inferred
from iacrisk.context.terraform import TerraformResource
from iacrisk.context.value import FactorState
from iacrisk.finding import NormalizedFinding


def _tf(name: str = "data", rtype: str = "aws_s3_bucket", **body: Any) -> TerraformResource:
    return TerraformResource(
        identity=f"{rtype}.{name}", type=rtype, name=name, body=body, file_path="main.tf"
    )


def _index(*resources: TerraformResource) -> dict[str, TerraformResource]:
    return {resource.identity: resource for resource in resources}


def _one(resource: TerraformResource) -> dict[str, Any]:
    return dict(infer(_index(resource)).values.get(resource.identity, {}))


def _k8s(name: str = "web", namespace: str | None = None, **labels: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    if labels:
        metadata["labels"] = labels
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata, "spec": {}}


# --- the registered data --------------------------------------------------------------


def test_the_conventions_obey_the_rules_they_state() -> None:
    """The three safety rules hold by the shape of the data, so no code path can break
    them: criticality stops at 4, no classification value reaches 5, and every name word
    sits above the sensitivity default - which is what makes a hint raise-only."""
    rules = conventions()
    default = int(rubric.factors()["sensitivity"].unresolved_default)

    assert max(int(level) for level in rules["criticality"]["values"]) == 4
    assert max(int(level) for level in rules["sensitivity"]["values"]) == 4
    assert min(int(level) for level in rules["sensitivity"]["name_words"]) > default
    assert "name_words" not in rules["criticality"], "criticality takes no name hint"


def test_no_convention_value_is_listed_under_two_levels() -> None:
    rules = conventions()
    for table in (
        rules["criticality"]["values"],
        rules["sensitivity"]["values"],
        rules["sensitivity"]["name_words"],
    ):
        flat = [inferred._normalize(v) for values in table.values() for v in values]
        assert len(flat) == len(set(flat))
        inferred._level_table(table)


def test_a_value_under_two_levels_is_a_defect_in_the_data_not_a_choice() -> None:
    with pytest.raises(ValueError, match="listed under levels"):
        inferred._level_table({"1": ["dev"], "4": ["Dev"]})


def test_every_level_the_conventions_can_produce_is_in_the_rubrics_range() -> None:
    rules = conventions()
    for factor in ("criticality", "sensitivity"):
        bounds = rubric.factors()[factor]
        tables = [rules[factor]["values"], rules[factor].get("name_words", {})]
        for table in tables:
            for level in table:
                assert bounds.minimum <= int(level) <= bounds.maximum


# --- criticality ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "level"),
    [("prod", 4), ("Production", 4), ("staging", 3), ("qa", 2), ("dev", 1), ("sandbox", 0)],
)
def test_an_environment_tag_gives_the_rubric_level_for_its_value(value: str, level: int) -> None:
    result = _one(_tf(tags={"Environment": f'"{value}"'}))
    assert result["criticality"].level == level
    assert result["criticality"].source == "tag"
    assert "Environment" in result["criticality"].evidence


def test_tag_keys_and_values_are_read_with_or_without_hcl_quotes_and_in_any_case() -> None:
    for tags in ({'"ENV"': '"PROD"'}, {"env": "prod"}, [{"Stage": '"prod"'}]):
        assert _one(_tf(tags=tags))["criticality"].level == 4


@pytest.mark.parametrize("value", ["Pre-Prod", "pre_prod", "preprod", "pre prod"])
def test_pre_prod_is_staging_and_can_never_match_prod(value: str) -> None:
    """Values are matched whole after separators are removed - never as substrings."""
    assert _one(_tf(tags={"Environment": f'"{value}"'}))["criticality"].level == 3


def test_an_interpolated_tag_value_is_not_read() -> None:
    assert _one(_tf(tags={"Environment": '"${var.env}"'})) == {}
    assert _one(_tf(tags={"Environment": "${local.resource_prefix.value}"})) == {}


def test_tags_built_by_an_expression_are_not_a_map_and_yield_nothing() -> None:
    """The shape the vendored Terraform corpus uses: `tags = merge({...}, {...})`."""
    assert _one(_tf(tags='${merge({Environment = "prod"}, {Owner = "x"})}')) == {}


def test_an_unrecognised_value_or_key_infers_nothing() -> None:
    assert _one(_tf(tags={"Environment": '"blue"'})) == {}
    assert _one(_tf(tags={"Owner": '"prod"', "Name": '"prod"'})) == {}


def test_two_environment_signals_that_disagree_resolve_nothing() -> None:
    assert _one(_tf(tags={"Environment": '"prod"', "Stage": '"dev"'})) == {}
    assert _one(_tf(tags={"Environment": '"prod"', "Stage": '"live"'}))["criticality"].level == 4


def test_criticality_takes_no_hint_from_a_name() -> None:
    assert "criticality" not in _one(_tf(name="prod_customer_db"))


# --- sensitivity ----------------------------------------------------------------------


def test_a_classification_tag_is_used_as_written_even_below_the_default() -> None:
    """An explicit tag is the owner's statement, so unlike a name it may lower the value."""
    result = _one(_tf(tags={"DataClassification": '"public"'}))
    assert result["sensitivity"].level == 0
    assert _one(_tf(tags={"Confidentiality": '"restricted"'}))["sensitivity"].level == 4


def test_a_word_in_the_name_raises_sensitivity_when_no_tag_resolved() -> None:
    result = _one(_tf(name="app_secrets"))
    assert result["sensitivity"].level == 5
    assert result["sensitivity"].source == "name"
    assert "'secrets'" in result["sensitivity"].evidence
    assert _one(_tf(name="pii-export"))["sensitivity"].level == 4


def test_a_name_word_is_matched_whole_never_inside_another_word() -> None:
    assert _one(_tf(name="tokenizer")) == {}
    assert _one(_tf(name="secretary_files")) == {}


def test_an_explicit_tag_outranks_a_name_hint() -> None:
    result = _one(_tf(name="pii_store", tags={"DataClassification": '"internal"'}))
    assert result["sensitivity"].level == 2
    assert result["sensitivity"].source == "tag"


def test_name_words_at_two_levels_resolve_nothing() -> None:
    assert _one(_tf(name="pii_secrets")) == {}


def test_a_name_hint_at_or_below_the_default_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    """No registered word sits at or below the default, so the guard is exercised by giving
    it one. A hint that could lower a value is the false reassurance the rule forbids."""
    rules = json_copy(conventions())
    rules["sensitivity"]["name_words"] = {"1": ["scratch"], "3": ["customer"], "5": ["secrets"]}
    monkeypatch.setattr(inferred, "conventions", lambda: rules)

    assert _one(_tf(name="scratch_bucket")) == {}
    assert _one(_tf(name="customer_bucket")) == {}
    assert _one(_tf(name="secrets_bucket"))["sensitivity"].level == 5


def json_copy(value: Any) -> Any:
    import json

    return json.loads(json.dumps(dict(value)))


# --- Kubernetes -----------------------------------------------------------------------


def _one_k8s(body: dict[str, Any]) -> dict[str, Any]:
    return dict(
        infer({}, {"apps/v1/Deployment/x/web": body}).values.get("apps/v1/Deployment/x/web", {})
    )


def test_a_namespace_or_a_label_gives_kubernetes_criticality() -> None:
    assert _one_k8s(_k8s(namespace="production"))["criticality"].source == "namespace"
    assert _one_k8s(_k8s(namespace="production"))["criticality"].level == 4
    assert _one_k8s(_k8s(environment="dev"))["criticality"].level == 1
    assert _one_k8s(_k8s(environment="dev"))["criticality"].source == "label"


def test_the_default_namespace_says_nothing_about_the_environment() -> None:
    assert _one_k8s(_k8s(namespace="default")) == {}
    assert _one_k8s(_k8s(namespace="kube-system")) == {}


def test_a_label_and_a_namespace_that_disagree_resolve_nothing() -> None:
    assert _one_k8s(_k8s(namespace="production", environment="dev")) == {}
    assert _one_k8s(_k8s(namespace="prod", environment="production"))["criticality"].level == 4


def test_a_kubernetes_name_can_raise_sensitivity() -> None:
    assert _one_k8s(_k8s(name="api-token-store"))["sensitivity"].level == 5


# --- the join -------------------------------------------------------------------------


def test_an_inferred_value_is_resolved_and_its_evidence_names_what_it_was_read_from() -> None:
    index = _index(_tf(tags={"Environment": '"prod"'}))
    sensitivity, criticality = join_inferred("aws_s3_bucket.data", infer(index), index)

    assert criticality.state is FactorState.RESOLVED and criticality.level == 4
    assert criticality.evidence.startswith(f"{ORIGIN} for aws_s3_bucket.data: tag Environment")
    assert sensitivity.state is FactorState.DEFAULTED
    assert sensitivity.evidence == f"sensitivity absent in {ORIGIN} for aws_s3_bucket.data"


def test_a_resource_no_convention_matches_is_defaulted_on_both_factors() -> None:
    index = _index(_tf())
    sensitivity, criticality = join_inferred("aws_s3_bucket.data", infer(index), index)

    assert sensitivity.state is criticality.state is FactorState.DEFAULTED
    assert sensitivity.evidence == f"no {ORIGIN} for aws_s3_bucket.data"


def test_a_container_scoped_identity_reads_its_workloads_inferred_values() -> None:
    inference = infer({}, {"apps/v1/Deployment/prod/web": _k8s(namespace="prod")})
    _, criticality = join_inferred("apps/v1/Deployment/prod/web [container=app]", inference, {})
    assert criticality.level == 4


def test_an_attachment_inherits_its_governed_resources_inferred_values() -> None:
    """The IAM-governed inheritance rule, unchanged: the policy has no tags of its own."""
    bucket = _tf(name="b", tags={"DataClassification": '"confidential"'})
    policy = _tf(name="p", rtype="aws_s3_bucket_policy", bucket="${aws_s3_bucket.b.id}")
    index = _index(bucket, policy)
    sensitivity, _ = join_inferred("aws_s3_bucket_policy.p", infer(index), index)

    assert sensitivity.level == 4
    assert "aws_s3_bucket.b" in sensitivity.evidence


def test_the_primary_paths_evidence_strings_are_unchanged() -> None:
    """`join` gained two keyword arguments for this mode. Their defaults must leave every
    existing record's evidence exactly as it was."""
    declared = {"aws_s3_bucket.data": {"sensitivity": 5, "criticality": 2}}
    sensitivity, _ = join("aws_s3_bucket.data", declared, {})
    missing, _ = join("aws_s3_bucket.other", declared, {})

    assert sensitivity.evidence == "declared context for aws_s3_bucket.data"
    assert missing.evidence == "no declared-context match for aws_s3_bucket.other"


def test_in_inference_mode_the_declared_context_is_not_consulted_at_all() -> None:
    """One mode or the other, never merged: a declared 5 must not reach an inferred run."""
    finding = NormalizedFinding(
        scanner="trivy",
        rule_id="AVD-X",
        canonical_rule_id="X",
        issue_class="storage-encryption-at-rest",
        title="t",
        remediation=None,
        native_severity="HIGH",
        severity_level=4,
        platform="terraform",
        resource_identity="aws_s3_bucket.data",
        identity_kind="terraform",
        file_path="main.tf",
        line_range=(1, 2),
        fingerprint=None,
        context_eligible=True,
    )
    index = _index(_tf())
    declared = {"aws_s3_bucket.data": {"sensitivity": 5, "criticality": 5}}

    (declared_run,) = contextualize([finding], declared, index)
    (inferred_run,) = contextualize([finding], declared, index, inference=Inference(values={}))

    assert declared_run.sensitivity is not None and declared_run.sensitivity.level == 5
    assert inferred_run.sensitivity is not None
    assert inferred_run.sensitivity.state is FactorState.DEFAULTED
    assert inferred_run.criticality is not None
    assert inferred_run.criticality.state is FactorState.DEFAULTED
