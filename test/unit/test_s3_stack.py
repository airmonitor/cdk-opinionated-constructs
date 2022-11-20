# -*- coding: utf-8 -*-
"""Test CDK template."""
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template
import pytest

from test.stacks.s3_stack import TestS3Stack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """Returns CDK template."""
    app = cdk.App()
    stack = TestS3Stack(app, "TestS3Stack", env=CDK_ENV)
    return Template.from_stack(stack)


# pylint: disable=redefined-outer-name
def test_s3_bucket(stack_template):
    """Test creation of S3 Buckets."""
    stack_template.resource_count_is("AWS::S3::Bucket", 2)


# pylint: disable=redefined-outer-name
def test_kms_key(stack_template):
    """Test if KMS key is created."""
    stack_template.resource_count_is("AWS::KMS::Key", 1)
