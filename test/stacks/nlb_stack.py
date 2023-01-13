# -*- coding: utf-8 -*-
"""Example code for Network Load Balancer cdk stack."""
from aws_cdk import Stack
from constructs import Construct

import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from cdk_opinionated_constructs.nlb import NetworkLoadBalancer

from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


class TestNLBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

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

        nlb_construct = NetworkLoadBalancer(self, construct_id="nlb_construct")
        nlb_name = "nlb"
        nlb = albv2.NetworkLoadBalancer(
            self,
            id=f"{nlb_name}_load_balancer",
            cross_zone_enabled=False,
            internet_facing=True,
            load_balancer_name=nlb_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        nlb_access_logs_bucket = nlb_construct.create_access_logs_bucket(bucket_name="bucket-name", expiration_days=7)
        nlb.log_access_logs(bucket=nlb_access_logs_bucket)

        network_load_balancer_construct = NetworkLoadBalancer(self, construct_id="network_load_balancer_construct")

        network_load_balancer_construct.add_connections(
            nlb=nlb,
            certificates=[],
            ports=[
                {
                    "front_end_port": 6001,
                    "front_end_protocol": albv2.Protocol.UDP,
                    "targets": [],
                    "back_end_port": 6001,
                    "back_end_protocol": albv2.Protocol.UDP,
                },
            ],
        )
        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
