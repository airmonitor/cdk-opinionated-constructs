# -*- coding: utf-8 -*-
"""Test AWS Lambda docker function construct."""
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.lmb import AWSDockerLambdaFunction
import aws_cdk.aws_lambda as lmb
import aws_cdk.aws_ecr as ecr
import aws_cdk.aws_ec2 as ec2
import aws_cdk as cdk

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestAWSLambdaDockerFunctionStack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
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

        ecr_repository = ecr.Repository(
            self,
            id="ecr_repository",
            auto_delete_images=True,
            encryption=ecr.RepositoryEncryption.AES_256,
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.IMMUTABLE,
            repository_name="test_ecr_repository",
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        lmb_construct = AWSDockerLambdaFunction(self, id="lmb_construct")
        lmb_function = lmb_construct.create_lambda_function(
            code=lmb.DockerImageCode.from_ecr(
                repository=ecr_repository,
                tag_or_digest="0",
            ),
            env=env,
            ephemeral_storage_size=cdk.Size.gibibytes(amount=10),
            function_name=props["service_name"],
            timeout=60,
            memory_size=512,
            env_variables={
                "POWERTOOLS_SERVICE_NAME": props["service_name"],
                "LOG_LEVEL": "DEBUG",
            },
            reserved_concurrent_executions=1,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        self.output_props = props.copy()
        self.output_props["lmb_function"] = lmb_function

        # Validate stack against AWS Solutions checklist
        nag_suppression_rule_list = self.nag_suppression()
        NagSuppressions.add_stack_suppressions(self, nag_suppression_rule_list)
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            {
                "id": "AwsSolutions-IAM4",
                "reason": "Using managed policies is allowed",
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "There isn't a way to tailor IAM policy using more restrictive permissions for "
                "used API calls logs:CreateLogGroup, xray:PutTelemetryRecords, xray:PutTraceSegments",
            },
        ]

    @property
    def outputs(self):
        """Update props dictionary.

        :return: Updated props dict
        """
        return self.output_props
