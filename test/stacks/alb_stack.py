# -*- coding: utf-8 -*-
"""Example code for Application Load Balancer cdk stack."""
from aws_cdk import Stack
from constructs import Construct

from aws_cdk import aws_kms as kms
import aws_cdk.aws_ec2 as ec2
from cdk_opinionated_constructs.alb import ApplicationLoadBalancer

from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


class TestALBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

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

        alb = alb_construct.create_alb(
            load_balancer_name="alb",
            internet_facing=True,
            vpc=vpc,
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", kms_key=shared_kms_key, expiration_days=7
        )

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
