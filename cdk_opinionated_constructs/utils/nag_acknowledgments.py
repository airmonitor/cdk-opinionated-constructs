"""Acknowledge cdk-nag v3 findings whose ids depend on the synthesized template.

cdk-nag v2 suppressed every finding of a rule with a bare id such as ``AwsSolutions-IAM5``. In v3 rules with
granular findings (``AwsSolutions-IAM4``, ``AwsSolutions-IAM5``) need one acknowledgment per finding, e.g.
``AwsSolutions-IAM5[Resource::<BucketArn>/*]``, and those ids contain logical ids, accounts and regions known only at
synthesis. The helpers below compute the finding ids the same way the cdk-nag rules do and acknowledge them during
synthesis, restoring the v2 "suppress this rule for this construct tree" behavior for explicitly chosen scopes.
"""

import json

from collections.abc import Callable, Iterator, Mapping
from typing import Any

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import jsii

from aws_cdk import Acknowledgment, Aspects, Validations, pipelines
from constructs import IConstruct

IAM_MANAGED_POLICIES_RULE = "AwsSolutions-IAM4"
IAM_WILDCARD_PERMISSIONS_RULE = "AwsSolutions-IAM5"
IAM_PRINCIPAL_TYPES = (iam.CfnRole, iam.CfnUser, iam.CfnGroup)
IAM_POLICY_TYPES = (iam.CfnPolicy, iam.CfnManagedPolicy)


def flatten_cfn_reference(reference: Any) -> str:
    """Flatten a CloudFormation value into the string cdk-nag uses in finding ids.

    Port of cdk-nag ``flattenCfnReference``: ``Fn::Join`` is joined, ``Fn::GetAtt`` becomes ``<Resource.Attribute>``,
    ``Ref`` becomes ``<Name>``, ``Fn::Sub`` placeholders ``${X}`` become ``<X>``; anything else is compact JSON.
    """
    if reference is None:
        return ""
    if isinstance(reference, str):
        return reference.replace("${", "<").replace("}", ">")
    if isinstance(reference, Mapping):
        # Same precedence as cdk-nag, which checks the intrinsic functions in this order.
        for function_name, flatten in _INTRINSIC_FLATTENERS:
            if reference.get(function_name):
                return flatten(reference[function_name])
    return json.dumps(reference, separators=(",", ":"))


def _flatten_join(value: list) -> str:
    delimiter, items = value
    return delimiter.join(flatten_cfn_reference(item) for item in items)


def _flatten_get_att(value: list) -> str:
    resource, attribute = value
    return f"<{flatten_cfn_reference(resource)}.{flatten_cfn_reference(attribute)}>"


_INTRINSIC_FLATTENERS: tuple[tuple[str, Callable[[Any], str]], ...] = (
    ("Fn::Join", _flatten_join),
    ("Fn::Sub", flatten_cfn_reference),
    ("Fn::GetAtt", _flatten_get_att),
    ("Fn::ImportValue", flatten_cfn_reference),
    ("Ref", lambda value: f"<{flatten_cfn_reference(value)}>"),
)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def wildcard_permission_findings(policy_document: Mapping[str, Any] | None) -> list[str]:
    """Return the ``AwsSolutions-IAM5`` findings of a resolved policy document, in cdk-nag order."""
    findings: dict[str, None] = {}
    for statement in (policy_document or {}).get("Statement") or []:
        if statement.get("Effect") != "Allow":
            continue
        for action in _as_list(statement.get("Action")):
            if isinstance(action, str) and "*" in action:
                findings[f"Action::{action}"] = None
        for resource in _as_list(statement.get("Resource")):
            flattened = flatten_cfn_reference(resource)
            if "*" in flattened:
                findings[f"Resource::{flattened}"] = None
    return list(findings)


def _iam_findings(node: IConstruct) -> Iterator[tuple[str, str]]:
    """Yield ``(rule id, finding)`` pairs for the IAM rules with granular findings."""
    stack = cdk.Stack.of(node)
    if isinstance(node, IAM_PRINCIPAL_TYPES):
        for policy_arn in stack.resolve(node.managed_policy_arns) or []:
            flattened = flatten_cfn_reference(stack.resolve(policy_arn))
            if ":iam::aws:" in flattened:
                yield IAM_MANAGED_POLICIES_RULE, f"Policy::{flattened}"
        for policy in stack.resolve(node.policies) or []:
            for finding in wildcard_permission_findings(stack.resolve(policy).get("policyDocument")):
                yield IAM_WILDCARD_PERMISSIONS_RULE, finding
    elif isinstance(node, IAM_POLICY_TYPES):
        for finding in wildcard_permission_findings(stack.resolve(node.policy_document)):
            yield IAM_WILDCARD_PERMISSIONS_RULE, finding


@jsii.implements(cdk.IAspect)
class _AcknowledgeIamFindings:
    """Aspect acknowledging every IAM4/IAM5 finding of the visited IAM resources."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def visit(self, node: IConstruct) -> None:
        """Acknowledge the findings of ``node`` if it is an IAM principal or policy."""
        acknowledgments = [
            Acknowledgment(id=f"{rule}[{finding}]", reason=self._reason) for rule, finding in _iam_findings(node)
        ]
        if acknowledgments:
            Validations.of(node).acknowledge(*acknowledgments)


def acknowledge_iam_findings(scope: IConstruct, *, reason: str) -> None:
    """Acknowledge all ``AwsSolutions-IAM4`` and ``AwsSolutions-IAM5`` findings under ``scope``.

    The findings are computed at synthesis, so policies added after this call are covered too. Use it only on
    construct trees whose IAM policies were reviewed, as the v3 equivalent of a v2 rule-wide suppression.

    Parameters
    ----------
    scope : IConstruct
        Root of the construct tree whose IAM findings are acknowledged.
    reason : str
        Why the managed policies and wildcard permissions are acceptable.

    """
    Aspects.of(scope).add(_AcknowledgeIamFindings(reason))


def acknowledge_cdk_pipelines_findings(pipeline: pipelines.CodePipeline) -> None:
    """Acknowledge the AwsSolutions findings of resources generated by CDK Pipelines.

    Must be called after ``pipeline.build_pipeline()``. Covers the IAM policies CDK Pipelines generates for CodePipeline
    and CodeBuild, CodeBuild projects without a customer managed KMS key (CB4) and the cross-region replication
    buckets without access logs (S1).

    Parameters
    ----------
    pipeline : pipelines.CodePipeline
        The built CDK Pipelines pipeline.

    """
    acknowledge_iam_findings(
        pipeline,
        reason="IAM policies are generated by CDK Pipelines and scoped to the pipeline's own resources",
    )
    Validations.of(pipeline).acknowledge(
        Acknowledgment(id="AwsSolutions-CB4", reason="CDK Pipelines CodeBuild projects use AWS managed encryption"),
    )
    for support in pipeline.pipeline.cross_region_support.values():
        Validations.of(support.replication_bucket).acknowledge(
            Acknowledgment(id="AwsSolutions-S1", reason="CDK Pipelines cross-region replication bucket"),
        )
