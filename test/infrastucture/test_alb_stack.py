"""Test CDK template."""

import os

from test.stacks.alb_stack import TestALBStack

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

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


def test_kms_key_existence(stack_template):
    """test_kms_key_existence tests that the stack template contains one KMS
    Key resource.

    It asserts that the template contains exactly one
    "AWS::KMS::Key" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::KMS::Key", 1)


def test_access_logs_bucket_existence(stack_template):
    """test_access_logs_bucket_existence tests that the stack template contains
    one S3 Bucket resource for access logs.

    It asserts that the template contains exactly one
    "AWS::S3::Bucket" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::S3::Bucket", 1)
