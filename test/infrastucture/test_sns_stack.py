"""Test CDK template."""

import os

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template
from cdk_nag import HIPAASecurityChecks, NIST80053R5Checks, PCIDSS321Checks

from test.stacks.sns_stack import TestSNSStack

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
    # cdk-nag v3 plugins are app-wide; compliance packs are applied here so they cover only this stack
    cdk.Validations.of(app).add_plugins(NIST80053R5Checks(app), PCIDSS321Checks(app), HIPAASecurityChecks(app))
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
