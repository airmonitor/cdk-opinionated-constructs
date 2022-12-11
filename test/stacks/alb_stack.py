# -*- coding: utf-8 -*-
"""Example code for Application Load Balancer cdk stack."""
from aws_cdk import Stack, Duration
from constructs import Construct

from aws_cdk import aws_kms as kms
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from cdk_opinionated_constructs.alb import ApplicationLoadBalancer

from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


class TestALBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        shared_kms_key = kms.Key(self, "shared_kms_key", enable_key_rotation=True)
        certificate = certificate_manager.Certificate(self, "certificate", domain_name="example.com")

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

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", kms_key=shared_kms_key, expiration_days=7
        )

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        alb_construct.add_connections(
            alb=alb,
            certificates=[certificate],
            ports=[
                {
                    "back_end_port": 8088,
                    "front_end_port": 443,
                    "back_end_protocol": albv2.ApplicationProtocol.HTTP,
                    "targets": [],
                    "healthy_http_codes": "200,302",
                    "deregistration_delay": Duration.minutes(1),
                }
            ],
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
