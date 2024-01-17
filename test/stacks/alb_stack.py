"""Example code for Application Load Balancer cdk stack."""

import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2

from aws_cdk import Aspects, Duration, Stack
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.alb import ApplicationLoadBalancer


class TestALBStack(Stack):
    """TestALBStack defines a CDK stack that creates an Application Load
    Balancer.

    It creates a VPC, ACM certificate, and ApplicationLoadBalancer construct.
    It configures an internet-facing ALB with access logging enabled.

    The ApplicationLoadBalancer construct is used to create an S3 bucket for
    access logs and add listeners/targets to the ALB.

    Parameters:

    - scope: The CDK scope constructing this stack.
    - construct_id: ID for the stack construct.
    - **kwargs: Additional stack options.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """The __init__ method constructs the TestALBStack.

        It creates the following resources:

        - VPC
        - ACM Certificate
        - ApplicationLoadBalancer construct
        - Internet-facing ALB with access logging enabled
        - S3 bucket for ALB access logs
        - ALB listener and target group

        It configures ALB connections and access logging via the ApplicationLoadBalancer
        construct.

        It validates the stack against the AWS Solutions checklist.

        Parameters:

        - scope: The CDK scope constructing this stack.
        - construct_id: ID for the stack construct.
        - **kwargs: Additional stack options.
        """

        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        certificate = certificate_manager.Certificate(self, "certificate", domain_name="example.com")

        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                NagPackSuppression(id="AwsSolutions-VPC7", reason="Test VPC, flow logs logs aren't required here."),
            ],
        )

        alb_construct = ApplicationLoadBalancer(self, construct_id="alb_construct")

        alb_name = "alb"
        alb = albv2.ApplicationLoadBalancer(
            self,
            id=f"{alb_name}_load_balancer",
            internet_facing=True,
            load_balancer_name=alb_name,
            vpc=vpc,  # type: ignore
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(bucket_name="bucket-name", expiration_days=7)

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        alb_construct.add_connections(
            alb=alb,
            certificates=[certificate],  # type: ignore
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
