"""Opinionated CDK construct to create AWS Lambda function.

Security parameters are set by default
"""

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as lmb

from aws_cdk import aws_logs as logs, aws_signer as signer
from constructs import Construct


class AWSPythonLambdaFunction(Construct):
    """Create Lambda function and supported objects like lambda layer, signing
    profile, IAM role and policies."""

    def __init__(self, scope: Construct, id: str):  # noqa: A002
        super().__init__(scope, id)

    def create_log_group(self, log_group_name: str):
        """Creates a log group for the Lambda function.

        Returns:
            The LogGroup object.

        It creates a log group with the given name.
        """

        return logs.LogGroup(
            self,
            "log-group",
            log_group_name=f"/service/lambda/{log_group_name}",
            log_group_class=logs.LogGroupClass.STANDARD,
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def signing_config(self, signing_profile_name: str) -> lmb.ICodeSigningConfig:
        """Creates a code signing configuration for Lambda functions.

        Parameters:

        - signing_profile_name: The name for the signing profile.

        Returns:
            The CodeSigningConfig object.

        It creates a signing profile for AWS Lambda with SHA384 ECDSA.

        This is then used to create a CodeSigningConfig with the profile.

        The CodeSigningConfig can be passed to Lambda functions to enable
        code signing.
        """

        profile = signer.SigningProfile(
            self,
            "signing-profile",
            platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA,  # type: ignore
            signing_profile_name=signing_profile_name,
        )

        return lmb.CodeSigningConfig(self, "conde-signing-config", signing_profiles=[profile])

    def create_lambda_layer(
        self, code_path: str, construct_id: str = "supporting_libraries"
    ) -> lmb.LayerVersion | lmb.ILayerVersion:
        """Creates a Lambda layer from a directory of assets.

        Parameters:

        - code_path: Path to the directory containing the layer assets.
        - construct_id: Optional ID for the layer construct.

        Returns:
            The Lambda LayerVersion object.

        It creates a LayerVersion from the given asset directory.

        The layer will be compatible with Python 3.11 runtimes.
        """

        return lmb.LayerVersion(
            self,
            id=construct_id,
            code=lmb.Code.from_asset(code_path),
            compatible_runtimes=[lmb.Runtime.PYTHON_3_11],  # type: ignore
        )

    def create_lambda_function(
        self,
        code_path: str,
        env: cdk.Environment,
        function_name: str,
        layers: list[lmb.ILayerVersion] | list[lmb.LayerVersion],
        reserved_concurrent_executions: None | int,
        timeout: int,
        architecture: lmb.Architecture = lmb.Architecture.ARM_64,
        memory_size: int = 256,
        handler: str = "handler.handler",
        signing_config: lmb.ICodeSigningConfig | None = None,
        tracing: bool = True,  # noqa: FBT001, FBT002
        insights_version: lmb.LambdaInsightsVersion | None = lmb.LambdaInsightsVersion.VERSION_1_0_229_0,
        env_variables: None | dict = None,
        **kwargs,
    ) -> lmb.Function | lmb.IFunction:
        """Creates a Lambda function from a local asset directory.

        Parameters:

        - code_path: Path to the directory containing the function code.
        - env: The CDK environment.
        - function_name: Name of the function.
        - layers: List of layers to attach to the function.
        - reserved_concurrent_executions: Max concurrent executions.
        - timeout: Function timeout in seconds.
        - architecture: CPU architecture - default ARM64.
        - memory_size: Memory size in MB - default 256.
        - handler: Handler name - default 'handler.handler'.
        - signing_config: Optional code signing configuration.
        - tracing: Enable Active Tracing - default True.
        - insights_version: Lambda Insights version to enable.
        - env_variables: Additional environment variables.
        - kwargs: Additional options like VPC, filesystem, callbacks.

        Returns:
            The Lambda Function object.

        It sets up Lambda best practices like:

        - Initial policies for CloudWatch logging
        - Environment variables for CloudWatch sampling & AWS region
        - Enabling profiling & insights
        - Retention of logs
        """

        if env_variables is None:
            env_variables = {}
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
            insights_version=insights_version,
            layers=layers,
            log_group=self.create_log_group(function_name),  # type: ignore
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

    def __init__(self, scope: Construct, id: str):  # noqa: A002
        super().__init__(scope, id)

    def create_log_group(self, log_group_name: str):
        """Creates a log group for the Lambda function.

        Returns:
            The LogGroup object.

        It creates a log group with the given name.
        """

        return logs.LogGroup(
            self,
            "log-group",
            log_group_name=f"/service/lambda/{log_group_name}",
            log_group_class=logs.LogGroupClass.STANDARD,
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

    def create_lambda_function(
        self,
        code: lmb.DockerImageCode,
        env: cdk.Environment,
        function_name: str,
        reserved_concurrent_executions: None | int,
        timeout: int,
        architecture: lmb.Architecture = lmb.Architecture.X86_64,
        memory_size: int = 256,
        env_variables: None | dict = None,
        **kwargs,
    ) -> lmb.Function | lmb.IFunction:
        """Creates a Lambda function from a Docker image.

        Parameters:

        - code: DockerImageCode object for the image.
        - env: The CDK environment.
        - function_name: Name of the function.
        - reserved_concurrent_executions: Max concurrent executions.
        - timeout: Function timeout in seconds.
        - architecture: CPU architecture - default X86_64.
        - memory_size: Memory size in MB - default 256.
        - env_variables: Additional environment variables.
        - kwargs: Additional options like filesystem, callbacks.

        Returns:
            The Lambda DockerImageFunction object.

        It sets up Lambda best practices like:

        - Initial policies for CloudWatch logging
        - Environment variables for CloudWatch sampling & AWS region
        - Retention of logs

        CodeGuru profiling is disabled due to incompatibility with FROM_IMAGE.
        """

        if env_variables is None:
            env_variables = {}
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
            log_group=self.create_log_group(function_name),  # type: ignore
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
