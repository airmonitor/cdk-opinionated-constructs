"""Test CDK template."""

import os

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

from test.stacks.lmb_stack import TestAWSPythonLambdaFunctionStack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestAWSPythonLambdaFunctionStack,
    and returns a template generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestAWSPythonLambdaFunctionStack.
    """

    app = cdk.App()
    stack = TestAWSPythonLambdaFunctionStack(
        app,
        "TestAWSLambdaFunctionStack",
        env=CDK_ENV,
        props={"stage": "dev", "project": "test_project", "service_name": "example_lambda_function"},
    )
    return Template.from_stack(stack)


def test_aws_lambda_function_existence(stack_template):
    """test_aws_lambda_function_existence tests that the stack template
    contains one AWS Lambda Function resource.

    It asserts that the template contains exactly one
    "AWS::Lambda::Function" resource. The function uses an explicit log
    group, so CDK does not add a LogRetention custom resource function.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::Lambda::Function", 1)


def test_aws_lambda_function_log_group(stack_template):
    """test_aws_lambda_function_log_group tests that the function has its own
    log group with a one-week retention.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.has_resource_properties(
        "AWS::Logs::LogGroup",
        {"LogGroupName": "/service/lambda/example_lambda_function", "RetentionInDays": 7},
    )


def test_signer_profile_existence(stack_template):
    """test_signer_profile_existence tests that the stack template contains one
    AWS Signer SigningProfile resource.

    It asserts that the template contains exactly one
    "AWS::Signer::SigningProfile" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::Signer::SigningProfile", 1)
