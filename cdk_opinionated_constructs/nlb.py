# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create Network load balancer.

Security parameters are set by default
"""
import aws_cdk as cdk
from constructs import Construct
import aws_cdk.aws_elasticloadbalancingv2 as albv2
import aws_cdk.aws_events_targets as albv2_targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_kms as kms
import aws_cdk.aws_certificatemanager as certificate_manager
from cdk_opinionated_constructs.s3 import S3Bucket

from cdk_nag import NagSuppressions


class NetworkLoadBalancer(Construct):
    """Create Network LB."""

    # pylint: disable=W0235
    def __init__(self, scope: Construct, construct_id: str):
        """

        :param scope:
        :param construct_id:
        """
        super().__init__(scope, construct_id)

    def create_access_logs_bucket(self, bucket_name: str, kms_key: kms.IKey, expiration_days: int) -> s3.Bucket:
        """Create dedicated access logs bucket using opinionated cdk construct
        from cdk-opinionated-constructs.

        :param expiration_days: The number of days after which logs will be deleted
        :param bucket_name: The name of S3 bucket
        :param kms_key: The kms key
        :return: CDK S3 IBucket object
        """

        alb_access_logs_bucket_construct = S3Bucket(self, id=f"alb_access_logs_{bucket_name}_construct")
        alb_access_logs_bucket = alb_access_logs_bucket_construct.create_bucket(
            bucket_name=bucket_name,
            kms_key=kms_key,
        )

        # The ALB access logging function don't work with KMS CMK which is used in the S3 bucket.
        # To overcome this issue a supported bucket encryption was used - AES256
        cfn_alb_access_logs_bucket = alb_access_logs_bucket.node.default_child
        cfn_alb_access_logs_bucket.add_property_override(
            "BucketEncryption.ServerSideEncryptionConfiguration.0.ServerSideEncryptionByDefault.SSEAlgorithm", "AES256"
        )
        cfn_alb_access_logs_bucket.add_property_deletion_override(
            "BucketEncryption.ServerSideEncryptionConfiguration.0.ServerSideEncryptionByDefault.KMSMasterKeyID"
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
        nlb: albv2.NetworkLoadBalancer, certificates: list[certificate_manager.ICertificate], ports: list
    ):
        """Create NLB listener and target.

        :param nlb: The CDK construct for Network Load Balancer
        :param certificates: List of certificates from AWS Certificate Manager
        :param ports: List of dictionaries that contain connection details

        Example usage:
        add_connections(
            nlb=imported_network_load_balancer,
            certificates=[],
            ports=[
                {
                    "front_end_port": 6001,
                    "front_end_protocol": albv2.Protocol.UDP,
                    "targets": [service],
                    "back_end_port": 6001,
                    "back_end_protocol": albv2.Protocol.UDP,
                },
            ]
        )
        """
        for port_definition in ports:
            front_end_protocol: albv2.Protocol = port_definition["front_end_protocol"]
            front_end_port: int = port_definition["front_end_port"]

            if certificates:
                listener = nlb.add_listener(
                    id=f"{front_end_protocol}-{front_end_port}",
                    port=front_end_port,
                    protocol=front_end_protocol,
                    certificates=certificates,
                    ssl_policy=port_definition.get("ssl_policy"),
                )

            else:
                listener = nlb.add_listener(
                    id=f"{front_end_protocol}-{front_end_port}", port=front_end_port, protocol=front_end_protocol
                )

            back_end_protocol: albv2.Protocol = port_definition["back_end_protocol"]
            back_end_port: int = port_definition["back_end_port"]
            targets: list[albv2_targets] = port_definition["targets"]
            if port_definition.get("target_type") == "alb":
                target = listener.add_targets(
                    id=f"{back_end_protocol}-{back_end_port}",
                    targets=targets,
                    port=back_end_port,
                    preserve_client_ip=True,
                    health_check=albv2.HealthCheck(
                        enabled=True,
                        protocol=albv2.Protocol.HTTPS,
                        port=str(back_end_port),
                        path=port_definition.get("health_check_path", "/"),
                    ),
                )
            else:
                target = listener.add_targets(
                    id=f"{back_end_protocol}-{back_end_port}",
                    targets=targets,
                    port=back_end_port,
                    preserve_client_ip=True,
                )
                target.set_attribute("deregistration_delay.connection_termination.enabled", "true")

            if port_definition.get("stickiness"):
                target.set_attribute("stickiness.enabled", "true")
