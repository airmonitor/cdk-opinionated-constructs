# -*- coding: utf-8 -*-
"""Test CDK template."""
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template
import pytest

from test.stacks.ecr_stack import TestECRStack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """Returns CDK template."""
    app = cdk.App()
    stack = TestECRStack(app, "TestECRStack", env=CDK_ENV)
    return Template.from_stack(stack)


# pylint: disable=redefined-outer-name
def test_registry(stack_template):
    """Test if CodeCommit repository created."""
    stack_template.resource_count_is("AWS::ECR::Repository", 1)


#
#
# # pylint: disable=redefined-outer-name
# def test_kms_key(stack_template):
#     """Test if KMS key created."""
#     stack_template.resource_count_is("AWS::KMS::Key", 1)
#
#
# # pylint: disable=redefined-outer-name
# def test_access_logs_bucket(stack_template):
#     """Test if SNS topic created."""
#     stack_template.resource_count_is("AWS::S3::Bucket", 1)
