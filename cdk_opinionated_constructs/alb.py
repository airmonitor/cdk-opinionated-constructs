"""Opinionated CDK construct to create Application load balancer with dedicated
S3 bucket for storing access logs.

Security parameters are set by default
"""

import aws_cdk as cdk
import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_elasticloadbalancingv2 as albv2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3

from cdk_nag import NagPackSuppression, NagSuppressions
from cdk_opinionated_constructs.s3 import S3Bucket
from constructs import Construct


class ApplicationLoadBalancer(Construct):
    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)

    def create_access_logs_bucket(self, bucket_name: str, expiration_days: int) -> s3.Bucket | s3.IBucket:
        """Creates an S3 bucket for ALB access logs and configures access
        policies.

        Parameters:

        - bucket_name: Name of the S3 bucket to create.
        - expiration_days: Number of days before objects in the bucket expire.

        Returns:
            The created S3 bucket object.

        It creates the bucket with S3 managed encryption enabled.

        It adds a bucket policy to allow the ALB service to write access logs.

        It adds a lifecycle rule to expire objects after the given number of days.

        It suppresses some false positive alerts related to not having separate
        access logs bucket.
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

        # Supress a few false positive alerts from the cfn-nag
        NagSuppressions.add_resource_suppressions(
            alb_access_logs_bucket,
            [
                NagPackSuppression(
                    id="AwsSolutions-S1",
                    reason="ALB access logs location, doesn't contain sensitive data it doesn't require "
                    "another resource for storing access logs from it",
                ),
            ],
        )

        return alb_access_logs_bucket

    @staticmethod
    def add_connections(
        alb: albv2.ApplicationLoadBalancer, certificates: list[certificate_manager.ICertificate], ports: list
    ):
        """Adds listeners and target groups to an ALB based on a list of port
        definitions.

        Parameters:

        - alb: The ApplicationLoadBalancer to add listeners and targets to.
        - certificates: List of ACM certificates to attach to the listeners.
        - ports: List of port definitions, each containing:
          - front_end_port: Frontend port number for listener
          - back_end_port: Backend port number for target group
          - back_end_protocol: Backend protocol (HTTP/HTTPS)
          - targets: List of targets for target group
          - deregistration_delay: Optional deregistration delay
          - healthy_http_codes: Optional healthy HTTP codes for health checks
          - health_check_path: Optional path for health checks

        For each port definition, it will:

        - Create an HTTPS listener on the frontend port, attaching the certificates
        - Add a target group on the backend port, using provided targets
        - Configure deregistration delay and health check codes if provided

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
                    "deregistration_delay": cdk.Duration.minutes(1),
                    "health_check_path": "/health",
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
                enable_anomaly_mitigation=True,
                load_balancing_algorithm_type=albv2.TargetGroupLoadBalancingAlgorithmType.WEIGHTED_RANDOM,
                deregistration_delay=port_definition.get("deregistration_delay"),
                health_check=albv2.HealthCheck(
                    enabled=True,
                    healthy_http_codes=port_definition.get("healthy_http_codes"),
                    path=port_definition.get("health_check_path"),
                ),
                port=back_end_port,
                protocol=port_definition["back_end_protocol"],
                targets=port_definition["targets"],
            )
