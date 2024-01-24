"""Test AWS Lambda docker function construct."""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_lambda as lmb

from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.ecr import ECR
from cdk_opinionated_constructs.lmb import AWSDockerLambdaFunction


class TestAWSLambdaDockerFunctionStack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        """Creates an ECR repository, VPC, and lambda function with docker
        image from ECR.

        Parameters:
        - scope: The construct scope.
        - construct_id: The construct ID.
        - env: The CDK environment.
        - props: A props dictionary with service_name key.
        - vpc_id: The VPC ID to use.
        - ecr_repository_name: The ECR repository name.
        - ecr_removal_policy: The removal policy for the ECR repository.
        - ecr_max_image_count: Max number of images to retain in ECR repository.
        - function_name: The name for the lambda function.
        - function_timeout: The timeout for the lambda function.
        - function_memory_size: The memory allocated for the lambda function.
        - function_env_variables: Environment variables for the lambda function.
        - function_reserved_concurrency: Reserved concurrency limit.
        - function_vpc_subnets: Subnets to place the lambda function.

        Returns:
        - lmb_function: The created lambda function with docker image from ECR.

        The ECR repository will be created with the provided name and configuration.
        The VPC will be suppressed from some AWS solutions checks.
        The lambda function will use the docker image from the ECR repository and
        will be configured with the provided parameters.
        """

        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(self, id="vpc")
        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                NagPackSuppression(id="AwsSolutions-VPC7", reason="Test VPC, flow logs logs aren't required here.")
            ],
        )

        ecr_construct = ECR(
            self,
            id="ecr_construct",
        )
        ecr_repository = ecr_construct.repository(
            repository_name="test_ecr_repository", removal_policy="destroy", max_image_count=5
        )

        lmb_construct = AWSDockerLambdaFunction(self, id="lmb_construct")
        lmb_function = lmb_construct.create_lambda_function(
            code=lmb.DockerImageCode.from_ecr(
                repository=ecr_repository,  # type: ignore
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
            NagPackSuppression(id="AwsSolutions-IAM4", reason="Using managed policies is allowed"),
            NagPackSuppression(
                id="AwsSolutions-IAM5",
                reason="There isn't a way to tailor IAM policy using more restrictive "
                "permissions for used API calls logs:CreateLogGroup, "
                "xray:PutTelemetryRecords, xray:PutTraceSegments",
            ),
        ]

    @property
    def outputs(self):
        """Update props dictionary.

        :return: Updated props dict
        """
        return self.output_props
