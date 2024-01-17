"""Test CDK template."""

import os

from test.stacks.ecr_stack import TestECRStack

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestECRStack, and returns a template
    generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestECRStack.
    """

    app = cdk.App()
    stack = TestECRStack(app, "TestECRStack", env=CDK_ENV)
    return Template.from_stack(stack)


def test_ecr_repository_existence(stack_template):
    """test_ecr_repository_existence tests that the stack template contains one
    ECR Repository resource.

    It asserts that the template contains exactly one
    "AWS::ECR::Repository" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::ECR::Repository", 1)
