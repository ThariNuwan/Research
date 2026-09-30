"""Encryption risk, read from the flagged resource's own attributes.

Two constraints from spec section 6 dominate this module.

**A non-literal read can never reach 3.** Level 3 requires positively-established mandate
evidence - a standard-mandated hardening control, or a regulated/customer-managed-key
requirement - which a non-literal read cannot supply. It is bounded at 2.

**The fencing constraint bites hardest here.** The level comes from the resource's
encryption attributes, never from the fact that a rule named `storage-encryption-at-rest`
fired. Where the attribute is absent, the answer is the platform's documented default if
that is literal and knowable from source, and `unresolved` otherwise - never
2-because-the-scanner-complained.

That last case is live in this corpus, not hypothetical. `aws_ebs_volume.web_host_storage`
declares no `encrypted` attribute at all (measured: its body carries only
`availability_zone`, `size` and `tags`), and AWS's effective default depends on an
account-level encryption-by-default setting that is invisible in the code. So it resolves
`unresolved`, which scores 2 - the same number a confirmed-unencrypted volume scores, and
a different state. The coverage report keeps them apart; the score does not need to.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from iacrisk.context.kubernetes import lookup as k8s_lookup
from iacrisk.context.terraform import TerraformResource, attribute, is_literal, unquote
from iacrisk.context.value import FactorValue
from iacrisk.finding import NormalizedFinding

__all__ = ["extract"]

# Data-bearing resource types and the attribute carrying their at-rest encryption state.
# A type absent from this table has no data-at-rest dimension and resolves to 0 - which
# is a statement about the resource, not about whether a scanner complained.
_AT_REST: dict[str, tuple[str, ...]] = {
    "aws_ebs_volume": ("encrypted", "kms_key_id"),
    "aws_ebs_snapshot": ("encrypted", "kms_key_id"),
    "aws_db_instance": ("storage_encrypted", "kms_key_id"),
    "aws_rds_cluster": ("storage_encrypted", "kms_key_id"),
    "aws_neptune_cluster": ("storage_encrypted", "kms_key_id"),
    "aws_docdb_cluster": ("storage_encrypted", "kms_key_id"),
    "aws_s3_bucket": ("server_side_encryption_configuration",),
    "aws_sqs_queue": ("kms_master_key_id", "sqs_managed_sse_enabled"),
    "aws_sns_topic": ("kms_master_key_id",),
    "aws_dynamodb_table": ("server_side_encryption",),
    "aws_efs_file_system": ("encrypted", "kms_key_id"),
    "aws_elasticache_replication_group": ("at_rest_encryption_enabled",),
    "aws_redshift_cluster": ("encrypted", "kms_key_id"),
    "aws_elasticsearch_domain": ("encrypt_at_rest", "node_to_node_encryption"),
    "aws_opensearch_domain": ("encrypt_at_rest", "node_to_node_encryption"),
    "aws_neptune_cluster_snapshot": ("storage_encrypted", "kms_key_id"),
    "aws_rds_cluster_snapshot": ("storage_encrypted", "kms_key_id"),
    "aws_db_snapshot": ("encrypted", "kms_key_id"),
    "aws_ecr_repository": ("encryption_configuration",),
    "aws_eks_cluster": ("encryption_config",),
    "aws_lambda_function": ("kms_key_arn",),
    "aws_kms_key": ("enable_key_rotation",),
    "aws_s3_bucket_object": ("kms_key_id", "server_side_encryption"),
    "aws_instance": ("root_block_device", "ebs_block_device"),
    "aws_cloudwatch_log_group": ("kms_key_id",),
    "aws_neptune_cluster_instance": ("storage_encrypted",),
}

# Types affirmatively established to hold no data at rest within this framework's scope.
# Explicit rather than implied: a type in NEITHER table resolves `unresolved`, because a
# hand-written table's silence is not evidence that a resource holds no data.
#
# Measured before this list existed: 159 findings resolved encryption=0 purely because
# their type was absent from `_AT_REST`, 29 of them carrying an encryption class of their
# own - including `aws_elasticsearch_domain`, which is plainly data-bearing. Resolving 0
# there is the false-reassurance failure mode PLAN Q9 forbids, and spec section 6.2
# requires `unresolved` where the state is not established.
_NO_DATA_AT_REST = frozenset(
    {
        # Network topology and access control carry no stored data.
        "aws_security_group",
        "aws_security_group_rule",
        "aws_subnet",
        "aws_vpc",
        "aws_route",
        "aws_route_table",
        "aws_route_table_association",
        "aws_internet_gateway",
        "aws_network_interface",
        "aws_db_subnet_group",
        "aws_flow_log",
        # Identity objects hold permissions, not data at rest.
        "aws_iam_role",
        "aws_iam_role_policy",
        "aws_iam_role_policy_attachment",
        "aws_iam_user",
        "aws_iam_user_policy",
        "aws_iam_policy",
        "aws_iam_group_policy",
        "aws_iam_instance_profile",
        "aws_iam_access_key",
        "aws_elasticsearch_domain_policy",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_acl",
        "aws_s3_bucket_public_access_block",
        # Configuration containers and attachments.
        "aws_db_option_group",
        "aws_db_parameter_group",
        "aws_volume_attachment",
        "aws_kms_alias",
        "null_resource",
        # Transport-layer resources: their encryption dimension is in transit, which this
        # factor's at-rest reads do not cover, and which no level of the factor asks for
        # separately.
        "aws_elb",
        "aws_lb",
        "aws_alb",
    }
)

# Kubernetes kinds the rubric's level 3 names directly (etcd Secret encryption at rest).
_KUBERNETES_SECRET_KINDS = frozenset({"Secret"})


def _truthy(raw: object) -> bool | None:
    """A literal boolean, or None when the value is not a readable literal."""
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        text = unquote(raw).strip().lower()
        if text in {"true", "1"}:
            return True
        if text in {"false", "0"}:
            return False
    return None


def _kubernetes(identity: str, body: Mapping[str, Any]) -> FactorValue:
    kind = str(body.get("kind", ""))
    if kind not in _KUBERNETES_SECRET_KINDS:
        return FactorValue.resolved(
            "encryption", 0, f"{identity} kind {kind!r} carries no data-at-rest requirement"
        )
    # etcd encryption-at-rest is a cluster-level EncryptionConfiguration, not a property
    # of the Secret manifest. A manifest read cannot establish it either way, and the
    # rubric reserves level 3 for a positively-established requirement - so unresolved
    # rather than 3, which would assert mandate evidence this read does not have.
    return FactorValue.unresolved(
        "encryption",
        f"{identity} is a Secret; etcd encryption-at-rest is a cluster-level "
        f"EncryptionConfiguration and is not readable from this manifest",
    )


def extract(
    finding: NormalizedFinding,
    tf_index: Mapping[str, TerraformResource],
    k8s_index: Mapping[str, Mapping[str, Any]] | None = None,
) -> FactorValue:
    """Resolve the encryption factor for one finding, or mark it unresolved."""
    identity = finding.resource_identity
    if k8s_index is not None:
        body = k8s_lookup(k8s_index, identity)
        if body is not None:
            return _kubernetes(identity, body)

    resource = tf_index.get(identity)
    if resource is None:
        return FactorValue.unresolved("encryption", f"no resource body indexed for {identity}")

    attrs = _AT_REST.get(resource.type)
    if attrs is None:
        if resource.type in _NO_DATA_AT_REST:
            return FactorValue.resolved(
                "encryption",
                0,
                f"{resource.type} holds no data at rest within this framework's scope",
            )
        # Neither table lists this type, so nothing has been established about it. Spec
        # section 6.2: resolving 0 here would let a hand-written table's silence read as
        # evidence of safety.
        return FactorValue.unresolved(
            "encryption",
            f"{resource.type} is in neither the data-bearing nor the no-data table, so its "
            f"encryption dimension is unclassified rather than absent",
        )

    seen_any = False
    for attr in attrs:
        raw = attribute(resource, attr)
        if raw is None:
            continue
        seen_any = True
        if not is_literal(raw):
            return FactorValue.unresolved(
                "encryption", f"{identity}.{attr} is interpolated, not a readable literal"
            )
        flag = _truthy(raw)
        if flag is True:
            return FactorValue.resolved("encryption", 0, f"{identity}.{attr}=true")
        if flag is False:
            return FactorValue.resolved(
                "encryption",
                2,
                f"{identity}.{attr}=false: encryption missing on a data-bearing resource "
                f"with no confirmable compensating control",
            )
        # A non-boolean literal present at all - a KMS key ARN, an SSE block - means the
        # control is configured. Bounded at 0; level 3 needs mandate evidence a literal
        # read cannot supply.
        return FactorValue.resolved(
            "encryption", 0, f"{identity}.{attr} is configured with a literal value"
        )

    if seen_any:  # pragma: no cover - defensive; every branch above returns
        return FactorValue.unresolved("encryption", f"{identity} encryption state indeterminate")

    return FactorValue.unresolved(
        "encryption",
        f"{identity} declares none of {list(attrs)}; the platform default depends on "
        f"account-level settings that are not visible in this source, so the encryption "
        f"state is unknown rather than absent",
    )
