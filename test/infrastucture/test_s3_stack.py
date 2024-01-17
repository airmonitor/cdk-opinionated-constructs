"""Test CDK template."""

import os

from test.stacks.s3_stack import TestS3Stack

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestS3Stack, and returns a template
    generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestS3Stack.
    """

    app = cdk.App()
    stack = TestS3Stack(app, "TestS3Stack", env=CDK_ENV)
    return Template.from_stack(stack)


def test_s3_bucket_existence(stack_template):
    """test_s3_bucket_existence tests that the stack template contains two S3
    Bucket resources.

    It asserts that the template contains exactly two
    "AWS::S3::Bucket" resources.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::S3::Bucket", 2)


def test_kms_key_existence(stack_template):
    """test_kms_key_existence tests that the stack template contains one KMS
    Key resource.

    It asserts that the template contains exactly one
    "AWS::KMS::Key" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::KMS::Key", 1)
