from typing import Literal

import aws_cdk.aws_codebuild as codebuild

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    default_install_commands,
    get_build_image_for_architecture,
    runtime_versions,
)


def create_lambda_build_project(
    *,
    scope,
    env: Environment,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
    pipeline_vars: PipelineVars,
    stage_name: str,
    function_name: str,
) -> codebuild.PipelineProject:
    """
    Parameters:
        scope: The CDK construct scope in which this resource will be created
        env (Environment): AWS environment containing region and account information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for which to create the build project
        compute_type (codebuild.ComputeType): AWS CodeBuild compute type to use for the build project
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        stage_name (str): Name of the stage being deployed
        function_name (str): Name of the AWS Lambda function

    Functionality:
        Creates an AWS CodeBuild pipeline project for building AWS Lambda functions.
        The project:
        1. Sets up a build environment with the appropriate architecture-specific build image
        2. Configures a build specification with installation commands
        3. Includes commands to deploy the Lambda function and its monitoring stack using CDK
        4. Applies default IAM permissions for CDK operations
        5. Supports optional CodeBuild fleet configuration

    Arguments:
        scope: The CDK construct scope
        env: AWS environment object
        cpu_architecture: Target CPU architecture for the build
        compute_type: AWS CodeBuild compute type
        pipeline_vars: Pipeline configuration variables
        stage_name: Deployment stage name
        function_name: Name of the Lambda function

    Returns:
        codebuild.PipelineProject: The configured AWS CodeBuild pipeline project for Lambda builds
    """
    project_name = "lambda_project"
    build_image = get_build_image_for_architecture(
        scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
        cpu_architecture=cpu_architecture,
    )
    fleet = None
    if pipeline_vars.codebuild_fleet_arn:
        fleet = codebuild.Fleet.from_fleet_arn(
            scope, id=f"{stage_name}_{project_name}_imported_fleet", fleet_arn=pipeline_vars.codebuild_fleet_arn
        )

    lambda_project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{function_name}_{project_name}",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
            fleet=fleet,
        ),
        auto_retry_limit=3,
        build_spec=codebuild.BuildSpec.from_object({
            "version": "0.2",
            "phases": {
                "install": {
                    "runtime-versions": runtime_versions,
                    "commands": [
                        "pip install uv",
                        "make venv",
                        ". .venv/bin/activate",
                        *default_install_commands,
                        f"cdk deploy --require-approval never {pipeline_vars.project}-pipeline/"
                        f"{stage_name}-{pipeline_vars.project}-{cpu_architecture}-lambda-stage/"
                        f"{function_name.replace('_', '-')}-lambda-stack",
                        f"cdk deploy --require-approval never {pipeline_vars.project}-pipeline/"
                        f"{stage_name}-{pipeline_vars.project}-{cpu_architecture}-lambda-stage/"
                        f"{function_name.replace('_', '-')}-monitoring-stack",
                    ],
                },
            },
        }),
    )

    apply_default_permissions(lambda_project, env)

    return lambda_project
