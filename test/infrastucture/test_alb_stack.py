"""Test CDK template."""

import os

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

from test.stacks.alb_stack import TestALBStack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestALBStack, and returns a template
    generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestALBStack.
    """

    app = cdk.App()
    stack = TestALBStack(app, "TestALBStack", env=CDK_ENV)
    return Template.from_stack(stack)


def test_application_load_balancer_existence(stack_template):
    """test_application_load_balancer_existence tests that the stack template
    contains one Application Load Balancer resource.

    It asserts that the template contains exactly one
    "AWS::ElasticLoadBalancingV2::LoadBalancer" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::ElasticLoadBalancingV2::LoadBalancer", 1)


def test_access_logs_bucket_encryption(stack_template):
    """test_access_logs_bucket_encryption tests that the access logs bucket is
    encrypted with S3 managed keys.

    ALB access logs support only SSE-S3, so the stack must not create a KMS
    key and the bucket must use the "AES256" algorithm.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::KMS::Key", 0)
    stack_template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        },
    )


def test_access_logs_bucket_existence(stack_template):
    """test_access_logs_bucket_existence tests that the stack template contains
    one S3 Bucket resource for access logs.

    It asserts that the template contains exactly one
    "AWS::S3::Bucket" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::S3::Bucket", 1)
