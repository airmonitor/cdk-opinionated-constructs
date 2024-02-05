"""Opinionated CDK construct to create Network load balancer.

Security parameters are set by default
"""

import aws_cdk as cdk
import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_elasticloadbalancingv2 as albv2
import aws_cdk.aws_events_targets as albv2_targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3

from cdk_nag import NagPackSuppression, NagSuppressions
from cdk_opinionated_constructs.s3 import S3Bucket
from constructs import Construct


class NetworkLoadBalancer(Construct):
    """Create Network LB."""

    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)

    def create_access_logs_bucket(self, bucket_name: str, expiration_days: int) -> s3.Bucket | s3.IBucket:
        """Creates an S3 bucket for ALB access logs with required permissions.

        Parameters:

        - bucket_name: Name of the S3 bucket.
        - expiration_days: Number of days before objects expire.

        Returns:
            The S3 Bucket object.

        It creates the bucket with S3 managed encryption enabled.

        It adds a bucket policy to allow delivery.logs.amazonaws.com service principal to write logs.

        It allows the service principal to get bucket ACL.

        It adds a lifecycle rule to expire objects after the given days.

        It suppresses some false positive alerts from cfn-nag for this valid use case.
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
        nlb: albv2.NetworkLoadBalancer, certificates: list[certificate_manager.ICertificate], ports: list
    ):
        """Adds listeners and target groups to a Network Load Balancer.

        Parameters:

        - nlb: The NLB object to add listeners and targets to.

        - certificates: List of ACM certificates to add to listeners.

        - ports: List of port definitions, each containing:

          - front_end_protocol: Protocol for listener (TCP, TLS etc.)
          - front_end_port: Listener port number
          - back_end_protocol: Protocol for targets (TCP, HTTP etc.)
          - back_end_port: Target group port
          - targets: List of target IP addresses or ALBs
          - target_type: 'instance' or 'alb'
          - health_check_path: Path for health checks (default '/')
          - stickiness: Whether to enable stickiness (true/false)

        It creates a listener with provided certificates if given.

        It adds a target group for each port definition.

        It enables connection draining and custom health checks.

        It enables stickiness if configured.

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
            ])
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
