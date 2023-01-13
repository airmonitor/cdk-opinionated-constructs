# -*- coding: utf-8 -*-
"""Test AWS WAFv2 construct against cdk-nag."""
from aws_cdk import Stack
from constructs import Construct
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from cdk_opinionated_constructs.alb import ApplicationLoadBalancer
from cdk_opinionated_constructs.wafv2 import WAFv2

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestWAFv2Stack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")

        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                {
                    "id": "AwsSolutions-VPC7",
                    "reason": "Test VPC, flow logs logs aren't required here.",
                },
            ],
        )

        alb_construct = ApplicationLoadBalancer(self, construct_id="alb_construct")

        alb_name = "alb"
        alb = albv2.ApplicationLoadBalancer(
            self,
            id=f"{alb_name}_load_balancer",
            internet_facing=True,
            load_balancer_name=alb_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(bucket_name="bucket-name", expiration_days=7)

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        wafv2_construct = WAFv2(self, construct_id="wafv2_construct")

        wafv2_acl = wafv2_construct.web_acl(
            name="wafv2",
            rate_value=500,
            aws_common_rule=True,
            aws_common_rule_ignore_list=[
                "SizeRestrictions_BODY",
            ],
            aws_sqli_rule=True,
            aws_anony_list=True,
            aws_bad_inputs_rule=True,
            aws_account_takeover_prevention={
                "login_path": "/portal/login",
                "payload_type": "FORM_ENCODED",
                "password_field": "data[AuthUser][password]",
                "username_field": "data[AuthUser][userId]",
            },
        )

        wafv2_construct.web_acl_log(log_group_name="aws-waf-logs-wafv2", web_acl_arn=wafv2_acl.attr_arn)

        wafv2_construct.web_acl_association(resource_arn=alb.load_balancer_arn, web_acl_arn=wafv2_acl.attr_arn)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
