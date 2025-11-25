from typing import Literal

import aws_cdk.aws_codebuild as codebuild

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    attach_role,
    default_install_commands,
    get_build_image_for_architecture,
    revert_to_original_role_command,
    runtime_versions,
)


def _create_docker_build_commands(
    env: Environment, pipeline_vars: PipelineVars, stage_name: str, docker_project_name: str
) -> list[str]:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        stage_name (str): Name of the deployment stage (e.g., dev, prod)
        docker_project_name (str): Name of the Docker project/service to build

    Functionality:
        Generates a list of shell commands that:
        1. Assumes an IAM role in the target AWS account
        2. Retrieves ECR repository URIs from SSM Parameter Store
        3. Downloads artifacts from S3 bucket
        4. Builds a Docker image with appropriate build arguments
        5. Tags the Docker image with the current commit hash
        6. Pushes the tagged image to Amazon ECR
        7. Stores the image tag and URI in SSM Parameter Store for later use

    Returns:
        list[str]: A list of shell commands to be executed in a CodeBuild environment
    """

    ssm_path_base = f"/{pipeline_vars.project}/{stage_name}"
    ecr_uri_param = f"{ssm_path_base}/ecr/repository/uri"
    image_tag_param = f"{ssm_path_base}/ecr/image/tag"
    image_uri_param = f"{ssm_path_base}/ecr/image/uri"

    return [
        'echo "Assuming role into target account..."',
        f"ASSUME_OUTPUT=$(aws sts assume-role "
        f"--role-arn arn:aws:iam::{env.account}:role/{pipeline_vars.project}-{stage_name}-docker-role "
        f"--role-session-name docker-session "
        f"--output text "
        f"--query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]')",
        'read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< "$ASSUME_OUTPUT"',
        "export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
        f'ECR_REPOSITORY_URI=$(aws ssm get-parameter --name "{ecr_uri_param}" '
        f'--region {env.region} --query "Parameter.Value" --output text)',
        "echo $ECR_REPOSITORY_URI",
        f'IMAGE_URI=$(aws ssm get-parameter --name "{image_uri_param}" '
        f'--region {env.region} --query "Parameter.Value" --output text)',
        "echo $IMAGE_URI",
        'echo "Logging into Amazon ECR..."',
        f"aws ecr get-login-password --region {env.region} | "
        f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
        'echo "Building Docker Image..."',
        f"docker build --cache-from $IMAGE_URI "
        f"-t '{pipeline_vars.project}-{stage_name}' services/{docker_project_name}",
        'echo "Current Commit Hash: $CODEBUILD_RESOLVED_SOURCE_VERSION"',
        'DATE=$(date -u +"%Y-%m-%dT%H-%M-%SZ")',
        'echo "Current time: $DATE"',
        'IMAGE_TAG="${CODEBUILD_RESOLVED_SOURCE_VERSION}_${DATE}"',
        'echo "Image tag: $IMAGE_TAG"',
        f'docker tag "{pipeline_vars.project}-{stage_name}:latest" "$ECR_REPOSITORY_URI:$IMAGE_TAG"',
        'docker push "$ECR_REPOSITORY_URI:$IMAGE_TAG"',
        f'aws ssm put-parameter --name "{image_tag_param}" '
        f'--region {env.region} --value "$IMAGE_TAG" '
        f"--type String --overwrite",
        f'aws ssm put-parameter --name "{image_uri_param}" '
        f'--region {env.region} --value "$ECR_REPOSITORY_URI:$IMAGE_TAG" '
        f"--type String --overwrite",
        revert_to_original_role_command,
        f'aws ssm put-parameter --name "{image_tag_param}" '
        f'--region {env.region} --value "$IMAGE_TAG" '
        f"--type String --overwrite",
    ]


def _attach_docker_iam_policies(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
):
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild project to attach IAM policies to
        env (cdk.Environment): AWS environment containing account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed

    Functionality:
        Attaches necessary IAM policies to the Docker build project
    """
    attach_role(project=project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="docker")


def create_docker_build_project(
    scope,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    docker_project_name: str,
    compute_type: codebuild.ComputeType,
):
    """
    Parameters:
        env (Environment): AWS environment configuration containing account and region information
        stage_name (str): Name of the deployment stage
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        docker_project_name (str): Name of the Docker project/service to build
        compute_type (codebuild.ComputeType): Compute type for the CodeBuild environment

    Functionality:
        Creates and configures a CodeBuild pipeline project for Docker image building with the following capabilities:
        - Selects appropriate build image based on specified CPU architecture (ARM64 or AMD64)
        - Configures privileged Docker build environment with containerd socket access
        - Optionally uses a CodeBuild fleet if fleet ARN is provided in pipeline variables
        - Generates Docker build commands that authenticate with ECR, build the image, and push to repository
        - Sets up environment variables for containerd socket location
        - Applies default IAM permissions for CDK asset management, parameter store access,
        and CloudFormation operations
        - Attaches Docker-specific IAM policies for ECR operations and role assumption

    Returns:
        codebuild.PipelineProject: Configured CodeBuild project ready for Docker image building in the pipeline
    """

    build_image = get_build_image_for_architecture(cpu_architecture)
    project_name = "docker_project"

    docker_commands = _create_docker_build_commands(env, pipeline_vars, stage_name, docker_project_name)

    fleet = None
    if pipeline_vars.codebuild_fleet_arn:
        fleet = codebuild.Fleet.from_fleet_arn(
            scope, id=f"{stage_name}_{project_name}_imported_fleet", fleet_arn=pipeline_vars.codebuild_fleet_arn
        )

    docker_project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{docker_project_name}_{project_name}",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
            fleet=fleet,
        ),
        environment_variables={
            "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                value="/var/run/docker/containerd/containerd.sock",
                type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
            ),
        },
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
                        *docker_commands,
                    ],
                },
            },
        }),
    )

    apply_default_permissions(docker_project, env)
    _attach_docker_iam_policies(project=docker_project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name)

    return docker_project
