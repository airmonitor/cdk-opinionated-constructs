# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create AWS Lambda function.

Security parameters are set by default
"""
from typing import Union

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as lmb
from aws_cdk import aws_logs as logs
from aws_cdk import aws_signer as signer
from constructs import Construct


class AWSPythonLambdaFunction(Construct):
    """Create Lambda function and supported objects like lambda layer, signing
    profile, IAM role and policies."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, id: str):
        """

        :param scope:
        :param id:
        """
        super().__init__(scope, id)

    def signing_config(self, signing_profile_name: str) -> lmb.ICodeSigningConfig:
        """Create code signing config and profile to sign lambda code with help
        from AWS Signer.

        :param signing_profile_name: The name of signing profile
        :return: AWS Lambda code signing config
        """
        profile = signer.SigningProfile(
            self,
            "signing-profile",
            platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA,  # type: ignore
            signing_profile_name=signing_profile_name,
        )

        return lmb.CodeSigningConfig(self, "conde-signing-config", signing_profiles=[profile])

    def create_lambda_layer(self, code_path: str, construct_id: str = "supporting_libraries") -> lmb.LayerVersion:
        """Create lambda layer.

        :param code_path: path which contains lambda layer directory
        :param construct_id: construct id
        :return: Lambda layer
        """
        return lmb.LayerVersion(
            self,
            id=construct_id,
            code=lmb.Code.from_asset(code_path),
            compatible_runtimes=[lmb.Runtime.PYTHON_3_11],  # type: ignore
        )

    # pylint: disable=R0913
    def create_lambda_function(
        self,
        code_path: str,
        env: cdk.Environment,
        env_variables: dict,
        function_name: str,
        layers: list[lmb.ILayerVersion],
        reserved_concurrent_executions: Union[None, int],
        timeout: int,
        architecture: lmb.Architecture = lmb.Architecture.ARM_64,
        memory_size: int = 256,
        handler: str = "handler.handler",
        signing_config: Union[lmb.ICodeSigningConfig, None] = None,
        tracing: bool = True,
        **kwargs,
    ) -> lmb.Function:
        """Create lambda function.

        :param tracing: Enable tracing using AWS XRay
        :param architecture: Lambda CPU architecture, default ARM_64
        :param code_path: path which contains lambda function directory
        :param env: The CDK Environment object which consist region and aws account id
        :param env_variables: Dictionary which contain additional lambda env variables
        :param function_name: The name of lambda function
        :param handler: Lambda handler, default handler.handler
        :param layers: Contains list of lambda layer objects
        :param memory_size: Lambda memory size, default 256MB
        :param reserved_concurrent_executions: The number of max concurrent lambda executions
        :param signing_config: Contains signing config for lambda, default None
        :param timeout: Lambda timeout in seconds,
        :param kwargs:
            * Security_groups - list of ec2.SecurityGroup, the vpc security groups to be assigned to lambda function
            * vpc - the ec2.IVpc object, lambda will be assigned to this VPC
            * vpc_subnets - ec2.SubnetSelection, in which subnet lambda will operate
        :return: Lambda function
        """
        lambda_environment_default_variables = {
            "CLOUDWATCH_SAMPLING_RATE": "1",
            "REGION_NAME": env.region,
        }

        return lmb.Function(
            self,
            architecture=architecture,
            code=lmb.Code.from_asset(code_path),
            code_signing_config=signing_config,
            environment=lambda_environment_default_variables | env_variables,
            function_name=function_name,
            filesystem=kwargs.get("filesystem"),
            handler=handler,
            id=function_name,
            initial_policy=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:CreateLogGroup"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                    resources=["arn:aws:logs:*:*:log-group:/aws/lambda-insights:*"],
                ),
            ],
            layers=layers,
            log_retention=logs.RetentionDays.ONE_WEEK,
            memory_size=memory_size,
            on_success=kwargs.get("on_success"),
            on_failure=kwargs.get("on_failure"),
            profiling=True,
            reserved_concurrent_executions=reserved_concurrent_executions,
            runtime=lmb.Runtime.PYTHON_3_11,  # type: ignore
            security_groups=kwargs.get("security_groups"),
            timeout=cdk.Duration.seconds(timeout),
            tracing=lmb.Tracing.ACTIVE if tracing else lmb.Tracing.DISABLED,
            vpc=kwargs.get("vpc"),
            vpc_subnets=kwargs.get("vpc_subnets"),
        )


class AWSDockerLambdaFunction(Construct):
    """Create Lambda function based on docker image with support of signing
    profile, IAM role and policies."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, id: str):
        """

        :param scope:
        :param id:
        """
        super().__init__(scope, id)

    # pylint: disable=R0913
    def create_lambda_function(
        self,
        code: lmb.DockerImageCode,
        env: cdk.Environment,
        env_variables: dict,
        function_name: str,
        reserved_concurrent_executions: Union[None, int],
        timeout: int,
        architecture: lmb.Architecture = lmb.Architecture.X86_64,
        memory_size: int = 256,
        **kwargs,
    ) -> lmb.Function:
        """Create lambda function.

        :param architecture: Lambda CPU architecture, default ARM_64
        :param code: The AWS CDK lmb.Code object
        :param env: The CDK Environment object which consists of region and aws account id
        :param env_variables: Dictionary which contain additional lambda env variables
        :param function_name: The name of lambda function
        :param memory_size: Lambda memory size, default 256MB
        :param reserved_concurrent_executions: The number of max concurrent lambda executions
        :param timeout: Lambda timeout in seconds
        :param kwargs:
            * Security_groups - list of ec2.SecurityGroup, the vpc security groups to be assigned to lambda function
            * vpc - the ec2.IVpc object, lambda will be assigned to this VPC
            * vpc_subnets - ec2.SubnetSelection, in which subnet lambda will operate
            * ephemeral_storage_size - The size of the function’s /tmp directory in MiB. Default: 512 MiB
        :return: Lambda function
        """
        lambda_environment_default_variables = {
            "CLOUDWATCH_SAMPLING_RATE": "1",
            "REGION_NAME": env.region,
        }
        return lmb.DockerImageFunction(
            self,
            id=function_name,
            allow_public_subnet=True,
            architecture=architecture,
            code=code,
            environment=lambda_environment_default_variables | env_variables,
            ephemeral_storage_size=kwargs.get("ephemeral_storage_size"),
            filesystem=kwargs.get("filesystem"),
            function_name=function_name,
            initial_policy=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:CreateLogGroup"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                    resources=["arn:aws:logs:*:*:log-group:/aws/lambda-insights:*"],
                ),
            ],
            log_retention=logs.RetentionDays.ONE_WEEK,
            memory_size=memory_size,
            on_failure=kwargs.get("on_failure"),
            on_success=kwargs.get("on_success"),
            profiling=False,  # CodeGuru profiling is not supported by runtime FROM_IMAGE
            reserved_concurrent_executions=reserved_concurrent_executions,
            security_groups=kwargs.get("security_groups"),
            timeout=cdk.Duration.seconds(timeout),
            tracing=lmb.Tracing.ACTIVE,
            vpc=kwargs.get("vpc"),
            vpc_subnets=kwargs.get("vpc_subnets"),
        )
