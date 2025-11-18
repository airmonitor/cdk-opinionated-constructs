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
        """
        Parameters:
            scope: The CDK construct scope in which this resource is defined
            construct_id (str): The unique identifier for this construct

        Functionality:
            Initializes an ApplicationLoadBalancer construct
        """
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
        """
        Parameters:
            alb (albv2.ApplicationLoadBalancer): The Application Load Balancer instance to configure
            certificates (list[certificate_manager.ICertificate]): List of ACM certificates to attach to HTTPS listeners
            ports (list): List of port configuration dictionaries

        Functionality:
            Configures listeners and target groups for an Application Load Balancer based on provided port definitions.
            For each port definition, creates:
            - HTTPS listener with specified certificates
            - Target group with specified backend protocol and targets
            - Health check configuration with optional custom settings
            - Optional stickiness configuration with cookie duration
            - Optional deregistration delay settings

            Automatically applies security best practices:
            - Uses TLS 1.2 with forward secrecy
            - Configures health checks with customizable parameters
            - Implements load balancing algorithms based on stickiness requirements
            - Sets appropriate anomaly mitigation based on configuration

        Arguments:
            alb: The Application Load Balancer to configure
            certificates: ACM certificates for HTTPS listeners
            ports: List of port configuration dictionaries containing:
                - front_end_port: Frontend listener port number
                - back_end_port: Backend target group port number
                - back_end_protocol: Backend protocol (HTTP/HTTPS)
                - targets: List of targets for the target group
                - deregistration_delay: Optional deregistration delay duration
                - healthy_http_codes: Optional HTTP codes for health checks
                - health_check_path: Optional health check path
                - stickiness_cookie_duration: Optional stickiness cookie duration
                - healthy_threshold_count: Optional healthy threshold count

        Returns:
            None
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
                enable_anomaly_mitigation=not port_definition.get("stickiness_cookie_duration"),
                load_balancing_algorithm_type=albv2.TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN
                if port_definition.get("stickiness_cookie_duration")
                else albv2.TargetGroupLoadBalancingAlgorithmType.WEIGHTED_RANDOM,
                deregistration_delay=port_definition.get("deregistration_delay"),
                health_check=albv2.HealthCheck(
                    enabled=True,
                    healthy_http_codes=port_definition.get("healthy_http_codes"),
                    path=port_definition.get("health_check_path"),
                    healthy_threshold_count=port_definition.get("healthy_threshold_count"),
                ),
                port=back_end_port,
                protocol=port_definition["back_end_protocol"],
                targets=port_definition["targets"],
                stickiness_cookie_duration=port_definition.get("stickiness_cookie_duration"),
            )
