# -*- coding: utf-8 -*-
"""Test CDK template."""
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template
import pytest

from test.stacks.lmb_stack import TestAWSPythonLambdaFunctionStack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """Returns CDK template."""
    app = cdk.App()
    stack = TestAWSPythonLambdaFunctionStack(
        app,
        "TestAWSLambdaFunctionStack",
        env=CDK_ENV,
        props={"stage": "dev", "project": "test_project", "service_name": "example_lambda_function"},
    )
    return Template.from_stack(stack)


# pylint: disable=redefined-outer-name
def test_aws_lambda_function(stack_template):
    """Test if AWS Lambda function is created."""
    stack_template.resource_count_is("AWS::Lambda::Function", 2)


# pylint: disable=redefined-outer-name
def test_signer_profile(stack_template):
    """Test if AWS signer profile is created."""
    stack_template.resource_count_is("AWS::Signer::SigningProfile", 1)
