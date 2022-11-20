# -*- coding: utf-8 -*-
"""Test CDK template."""
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template
import pytest

from test.stacks.sns_stack import TestSNSStack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """Returns CDK template."""
    app = cdk.App()
    stack = TestSNSStack(app, "TestSNSStack", env=CDK_ENV)
    return Template.from_stack(stack)


# pylint: disable=redefined-outer-name
def test_sns_topic(stack_template):
    """Test if SNS topic is created."""
    stack_template.resource_count_is("AWS::SNS::Topic", 1)
