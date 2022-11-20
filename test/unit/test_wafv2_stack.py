# -*- coding: utf-8 -*-
"""Test CDK template."""
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template
import pytest

from test.stacks.wafv2_stack import TestWAFv2Stack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])


@pytest.fixture(autouse=True)
def stack_template() -> Template:
    """Returns CDK template."""
    app = cdk.App()
    stack = TestWAFv2Stack(app, "TestWAFv2Stack", env=CDK_ENV)
    return Template.from_stack(stack)


# pylint: disable=redefined-outer-name
def test_application_load_balancer(stack_template):
    """Test if EC2 Application Load Balancer is created."""
    stack_template.resource_count_is("AWS::ElasticLoadBalancingV2::LoadBalancer", 1)


# pylint: disable=redefined-outer-name
def test_kms_key(stack_template):
    """Test if KMS key is created."""
    stack_template.resource_count_is("AWS::KMS::Key", 1)


# pylint: disable=redefined-outer-name
def test_access_logs_bucket(stack_template):
    """Test if S3 bucket is created."""
    stack_template.resource_count_is("AWS::S3::Bucket", 1)


# pylint: disable=redefined-outer-name
def test_web_acl_association(stack_template):
    """Test if WAFV2 web association is created."""
    stack_template.resource_count_is("AWS::WAFv2::WebACLAssociation", 1)


# pylint: disable=redefined-outer-name
def test_web_acl(stack_template):
    """Test if WAFV2 web ACL is created."""
    stack_template.resource_count_is("AWS::WAFv2::WebACL", 1)


# pylint: disable=redefined-outer-name
def test_log_group(stack_template):
    """Test if CloudWatch log group is created."""
    stack_template.resource_count_is("AWS::Logs::LogGroup", 1)


# pylint: disable=redefined-outer-name
def test_wav_logging_configuration(stack_template):
    """Test if WAFV2 logging configuration is created."""
    stack_template.resource_count_is("AWS::WAFv2::LoggingConfiguration", 1)
