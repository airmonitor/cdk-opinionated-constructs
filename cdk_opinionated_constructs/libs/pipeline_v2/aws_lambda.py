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
        scope: The CDK construct scope in which this resource is defined
        env (Environment): AWS environment configuration
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the Lambda function
        compute_type (codebuild.ComputeType): Compute resources for the build environment
        pipeline_vars (PipelineVars): Pipeline configuration variables
        stage_name (str): Name of the deployment stage
        function_name (str): Name of the Lambda function

    Functionality:
        Creates a CodeBuild project that deploys a Lambda function and its monitoring stack.
        The project uses an architecture-specific build image and applies default permissions.
        The build process executes CDK deploy commands for both the Lambda stack and its
        corresponding monitoring stack.

    Returns:
        codebuild.PipelineProject: The configured CodeBuild project for Lambda deployment
    """
    build_image = get_build_image_for_architecture(cpu_architecture)
    lambda_project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{function_name}_lambda_project",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
        ),
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
