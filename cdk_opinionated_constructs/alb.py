# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create Application load balancer with dedicated
S3 bucket for storing access logs.

Security parameters are set by default
"""
from cdk_nag import NagSuppressions
from cdk_opinionated_constructs.s3 import S3Bucket
from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_elasticloadbalancingv2 as albv2
import aws_cdk.aws_certificatemanager as certificate_manager


class ApplicationLoadBalancer(Construct):
    """Create Application LB."""

    # pylint: disable=W0235
    def __init__(self, scope: Construct, construct_id: str):
        """

        :param scope:
        :param construct_id:
        """
        super().__init__(scope, construct_id)

    def create_access_logs_bucket(self, bucket_name: str, expiration_days: int) -> s3.Bucket:
        """Create dedicated access logs bucket using opinionated cdk construct
        from cdk-opinionated-constructs.

        :param expiration_days: The number of days after which logs will be deleted
        :param bucket_name: The name of S3 bucket
        :return: CDK S3 IBucket object
        """

        alb_access_logs_bucket_construct = S3Bucket(self, id=f"alb_access_logs_{bucket_name}_construct")
        alb_access_logs_bucket = alb_access_logs_bucket_construct.create_bucket(
            bucket_name=bucket_name, encryption=s3.BucketEncryption.S3_MANAGED
        )

        alb_access_logs_bucket.add_to_resource_policy(
            permission=iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:PutObject"],
                principals=[iam.ServicePrincipal(service="delivery.logs.amazonaws.com")],
                resources=[f"{alb_access_logs_bucket.bucket_arn}/*"],
                conditions={"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            )
        )

        alb_access_logs_bucket.add_to_resource_policy(
            permission=iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetBucketAcl"],
                principals=[iam.ServicePrincipal(service="delivery.logs.amazonaws.com")],
                resources=[alb_access_logs_bucket.bucket_arn],
            )
        )
        alb_access_logs_bucket.add_lifecycle_rule(expiration=cdk.Duration.days(expiration_days))

        # Supress few false positive alerts from the cfn-nag
        NagSuppressions.add_resource_suppressions(
            alb_access_logs_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "ALB access logs location, doesn't contain sensitive data"
                    "it doesn't require another resource for storing access logs from it",
                },
            ],
        )

        return alb_access_logs_bucket

    @staticmethod
    def add_connections(
        alb: albv2.ApplicationLoadBalancer, certificates: list[certificate_manager.ICertificate], ports: list
    ):
        """Create ALB listener and target.

        :param alb: The CDK construct for Application Load Balancer
        :param certificates: List of certificates from AWS Certificate Manager
        :param ports: List of dictionaries that contain connection details

        Example usage:
        add_connections(
            alb=alb,
            certificates=[imported_acm_certificate],
            ports=[
                {
                    "back_end_port": 8088,
                    "front_end_port": 443,
                    "back_end_protocol": albv2.ApplicationProtocol.HTTPS,
                    "targets": [service],
                    "healthy_http_codes": "200,302",
                    "deregistration_delay": cdk.Duration.minutes(1)
                }
            ]
        )
        """
        for port_definition in ports:
            front_end_port_number = port_definition["front_end_port"]

            listener = alb.add_listener(
                certificates=certificates,
                id=f"https_{front_end_port_number}_listener",
                port=front_end_port_number,
                protocol=albv2.ApplicationProtocol.HTTPS,
                ssl_policy=albv2.SslPolicy.FORWARD_SECRECY_TLS12_RES_GCM,
                open=False,
            )

            back_end_port = port_definition["back_end_port"]
            listener.add_targets(
                id=f"{back_end_port}_target",
                deregistration_delay=port_definition.get("deregistration_delay"),
                health_check=albv2.HealthCheck(
                    enabled=True,
                    healthy_http_codes=port_definition.get("healthy_http_codes"),
                ),
                port=back_end_port,
                protocol=port_definition["back_end_protocol"],
                targets=port_definition["targets"],
            )
