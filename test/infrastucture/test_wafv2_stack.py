"""Test CDK template."""

import os

from test.stacks.wafv2_stack import TestWAFv2Stack

import aws_cdk as cdk
import pytest

from aws_cdk.assertions import Template

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """The stack_template fixture generates a CDK stack template for testing.

    It creates a CDK app, instantiates the TestWAFv2Stack, and returns a template
    generated from the stack.

    Parameters:

    - None

    Returns:

    - Template: The CDK stack template generated from TestWAFv2Stack.
    """

    app = cdk.App()
    stack = TestWAFv2Stack(app, "TestWAFv2Stack", env=CDK_ENV)
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


def test_web_acl_association_existence(stack_template):
    """test_web_acl_association_existence tests that the stack template
    contains one WebACLAssociation resource.

    It asserts that the template contains exactly one
    "AWS::WAFv2::WebACLAssociation" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::WAFv2::WebACLAssociation", 1)


def test_web_acl_existence(stack_template):
    """test_web_acl_existence tests that the stack template contains one WAFv2
    WebACL resource.

    It asserts that the template contains exactly one
    "AWS::WAFv2::WebACL" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::WAFv2::WebACL", 1)


def test_log_group_existence(stack_template):
    """test_log_group_existence tests that the stack template contains one
    CloudWatch Log Group resource.

    It asserts that the template contains exactly one
    "AWS::Logs::LogGroup" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::Logs::LogGroup", 1)


def test_wav_logging_configuration_existence(stack_template):
    """test_wav_logging_configuration_existence tests that the stack template
    contains one WAFv2 LoggingConfiguration resource.

    It asserts that the template contains exactly one
    "AWS::WAFv2::LoggingConfiguration" resource.

    Parameters:

    - stack_template: The CDK stack template to test against.
    """

    stack_template.resource_count_is("AWS::WAFv2::LoggingConfiguration", 1)
