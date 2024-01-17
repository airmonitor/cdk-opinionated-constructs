"""Test CDK template."""

import os

from test.stacks.sns_stack import TestSNSStack

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestSNSStack, and returns a template
    generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestSNSStack.
    """

    app = cdk.App()
    stack = TestSNSStack(app, "TestSNSStack", env=CDK_ENV)
    return Template.from_stack(stack)


def test_sns_topic_existence(stack_template):
    """test_sns_topic_existence tests that the stack template contains one SNS
    Topic resource.

    It asserts that the template contains exactly one
    "AWS::SNS::Topic" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::SNS::Topic", 1)
