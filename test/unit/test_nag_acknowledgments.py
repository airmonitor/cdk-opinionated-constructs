"""Unit tests for cdk-nag v3 acknowledgment helpers."""

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import pytest

from aws_cdk import Validations
from aws_cdk.assertions import Template
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.utils.nag_acknowledgments import (
    acknowledge_iam_findings,
    flatten_cfn_reference,
    wildcard_permission_findings,
)


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/*"),
        ({"Fn::GetAtt": ["Bucket83908E77", "Arn"]}, "<Bucket83908E77.Arn>"),
        ({"Fn::Join": ["", [{"Fn::GetAtt": ["Bucket", "Arn"]}, "/*"]]}, "<Bucket.Arn>/*"),
        ({"Fn::Join": [":", ["arn", {"Ref": "AWS::Partition"}, "logs"]]}, "arn:<AWS::Partition>:logs"),
        ({"Fn::Sub": "arn:${AWS::Partition}:sqs:*"}, "arn:<AWS::Partition>:sqs:*"),
        ({"Fn::ImportValue": "Export"}, "Export"),
        ({"Other": 1}, '{"Other":1}'),
    ],
)
def test_flatten_cfn_reference_matches_cdk_nag_format(reference, expected):
    """CloudFormation values are flattened the way cdk-nag prints them in finding ids."""
    assert flatten_cfn_reference(reference) == expected  # nosec B101


def test_wildcard_permission_findings_report_allow_statements_only():
    """Wildcard actions and resources of Allow statements are reported once, Deny statements are ignored."""
    policy_document = {
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:PutObject"], "Resource": ["*", "arn:aws:s3:::b"]},
            {"Effect": "Allow", "Action": "s3:Get*", "Resource": {"Fn::Join": ["", ["<x>", "/*"]]}},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ]
    }

    assert wildcard_permission_findings(policy_document) == [  # nosec B101
        "Action::s3:Get*",
        "Resource::*",
        "Resource::<x>/*",
    ]


def _stack_with_wildcard_roles() -> tuple[cdk.Stack, iam.Role, iam.Role]:
    app = cdk.App()
    stack = cdk.Stack(app, "stack")
    roles = []
    for role_id in ("reviewed", "other"):
        role = iam.Role(
            stack,
            role_id,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess")],
        )
        role.add_to_policy(iam.PolicyStatement(actions=["s3:Get*"], resources=[f"arn:{cdk.Aws.PARTITION}:s3:::b/*"]))
        roles.append(role)
    Validations.of(stack).add_plugins(AwsSolutionsChecks(stack))
    return stack, roles[0], roles[1]


def test_acknowledge_iam_findings_covers_managed_and_wildcard_findings():
    """IAM4 and IAM5 findings under the acknowledged scope no longer fail synthesis."""
    stack, reviewed, other = _stack_with_wildcard_roles()
    acknowledge_iam_findings(reviewed, reason="reviewed")
    acknowledge_iam_findings(other, reason="reviewed")

    Template.from_stack(stack)


def test_acknowledge_iam_findings_is_limited_to_its_scope():
    """Findings outside the acknowledged scope still fail synthesis."""
    stack, reviewed, _ = _stack_with_wildcard_roles()
    acknowledge_iam_findings(reviewed, reason="reviewed")

    with pytest.raises(RuntimeError, match="ValidationFailed"):
        Template.from_stack(stack)
