"""Docker build CodeBuild project configuration.

This module provides functions to create and configure CodeBuild projects
for building and pushing Docker images to Amazon ECR.
"""

from itertools import chain
from typing import Any, Literal, TypedDict

import aws_cdk.aws_codebuild as codebuild

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.libs.pipeline_v2 import (
    install_docker_default,
    install_pre_backed,
    use_fleet,
)
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    attach_role,
    get_build_image_for_architecture,
    revert_to_original_role_command,
)

# =============================================================================
# Type Definitions - Better Type Safety and Documentation
# =============================================================================


class DockerCommands(TypedDict):
    """Type definition for Docker command structure."""

    install_commands: dict[str, Any]
    commands: list[str]


class DockerBuildContext(TypedDict):
    """Context for Docker build command generation."""

    region: str
    account: str
    project: str
    stage_name: str
    docker_project_name: str


class SSMPaths(TypedDict):
    """SSM Parameter Store paths for Docker build."""

    base: str
    ecr_uri: str
    image_tag: str
    image_uri: str


# =============================================================================
# Pure Helper Functions - High Cohesion, Single Responsibility
# =============================================================================


def _create_ssm_paths(project: str, stage_name: str) -> SSMPaths:
    """Generate SSM Parameter Store paths for Docker build configuration.

    Args:
        project: Project name
        stage_name: Name of the deployment stage

    Returns:
        Dictionary containing all SSM paths
    """
    base = f"/{project}/{stage_name}"
    return SSMPaths(
        base=base,
        ecr_uri=f"{base}/ecr/repository/uri",
        image_tag=f"{base}/ecr/image/tag",
        image_uri=f"{base}/ecr/image/uri",
    )


def _create_assume_role_commands(ctx: DockerBuildContext) -> tuple[str, ...]:
    """Generate IAM role assumption commands for cross-account access.

    Args:
        ctx: Docker build context containing AWS environment details

    Returns:
        Tuple of role assumption commands
    """
    return (
        'echo "Assuming role into target account..."',
        f"ASSUME_OUTPUT=$(aws sts assume-role "
        f"--role-arn arn:aws:iam::{ctx['account']}:role/{ctx['project']}-{ctx['stage_name']}-docker-role "
        f"--role-session-name docker-session "
        f"--output text "
        f"--query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]')",
        'read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< "$ASSUME_OUTPUT"',
        "export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
    )


def _create_ecr_login_commands(ctx: DockerBuildContext, ssm_paths: SSMPaths) -> tuple[str, ...]:
    """Generate ECR login and repository URI retrieval commands.

    Args:
        ctx: Docker build context containing AWS environment details
        ssm_paths: SSM Parameter Store paths

    Returns:
        Tuple of ECR login commands
    """
    return (
        f'ECR_REPOSITORY_URI=$(aws ssm get-parameter --name "{ssm_paths["ecr_uri"]}" '
        f'--region {ctx["region"]} --query "Parameter.Value" --output text)',
        "echo $ECR_REPOSITORY_URI",
        f'IMAGE_URI=$(aws ssm get-parameter --name "{ssm_paths["image_uri"]}" '
        f'--region {ctx["region"]} --query "Parameter.Value" --output text)',
        "echo $IMAGE_URI",
        'echo "Logging into Amazon ECR..."',
        f"aws ecr get-login-password --region {ctx['region']} | "
        f"docker login --username AWS --password-stdin {ctx['account']}.dkr.ecr.{ctx['region']}.amazonaws.com",
    )


def _create_docker_build_commands(ctx: DockerBuildContext) -> tuple[str, ...]:
    """Generate Docker image build commands.

    Args:
        ctx: Docker build context containing project details

    Returns:
        Tuple of Docker build commands
    """
    return (
        'echo "Building Docker Image..."',
        f"docker build --cache-from $IMAGE_URI "
        f"-t '{ctx['project']}-{ctx['stage_name']}' services/{ctx['docker_project_name']}",
    )


def _create_image_tagging_commands() -> tuple[str, ...]:
    """Generate image tagging commands with commit hash and timestamp.

    Returns:
        Tuple of image tagging commands
    """
    return (
        'echo "Current Commit Hash: $CODEBUILD_RESOLVED_SOURCE_VERSION"',
        'DATE=$(date -u +"%Y-%m-%dT%H-%M-%SZ")',
        'echo "Current time: $DATE"',
        'IMAGE_TAG="${CODEBUILD_RESOLVED_SOURCE_VERSION}_${DATE}"',
        'echo "Image tag: $IMAGE_TAG"',
    )


def _create_docker_tag_command(ctx: DockerBuildContext) -> str:
    """Generate Docker tag command.

    Args:
        ctx: Docker build context containing project details

    Returns:
        Docker tag command string
    """
    return f'docker tag "{ctx["project"]}-{ctx["stage_name"]}:latest" "$ECR_REPOSITORY_URI:$IMAGE_TAG"'


def _create_docker_push_commands() -> tuple[str, ...]:
    """Generate Docker push commands.

    Returns:
        Tuple of Docker push commands
    """
    return ('docker push "$ECR_REPOSITORY_URI:$IMAGE_TAG"',)


def _create_ssm_update_commands(ctx: DockerBuildContext, ssm_paths: SSMPaths) -> tuple[str, ...]:
    """Generate SSM Parameter Store update commands for image metadata.

    Args:
        ctx: Docker build context containing AWS environment details
        ssm_paths: SSM Parameter Store paths

    Returns:
        Tuple of SSM update commands
    """
    return (
        f'aws ssm put-parameter --name "{ssm_paths["image_tag"]}" '
        f'--region {ctx["region"]} --value "$IMAGE_TAG" '
        f"--type String --overwrite",
        f'aws ssm put-parameter --name "{ssm_paths["image_uri"]}" '
        f'--region {ctx["region"]} --value "$ECR_REPOSITORY_URI:$IMAGE_TAG" '
        f"--type String --overwrite",
    )


def _create_revert_role_commands(ctx: DockerBuildContext, ssm_paths: SSMPaths) -> tuple[str, ...]:
    """Generate commands to revert to original role and update SSM.

    Args:
        ctx: Docker build context containing AWS environment details
        ssm_paths: SSM Parameter Store paths

    Returns:
        Tuple of role revert and SSM update commands
    """
    return (
        revert_to_original_role_command,
        f'aws ssm put-parameter --name "{ssm_paths["image_tag"]}" '
        f'--region {ctx["region"]} --value "$IMAGE_TAG" '
        f"--type String --overwrite",
    )


# =============================================================================
# Function Composition - Building Complex Commands from Simple Ones
# =============================================================================


def _create_build_context(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    docker_project_name: str,
) -> DockerBuildContext:
    """Create an immutable build context from environment parameters.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        docker_project_name: Name of the Docker project

    Returns:
        Immutable context dictionary for Docker build operations
    """
    return DockerBuildContext(
        region=str(env.region),
        account=str(env.account),
        project=pipeline_vars.project,
        stage_name=stage_name,
        docker_project_name=docker_project_name,
    )


def _compose_docker_build_commands(
    ctx: DockerBuildContext,
    ssm_paths: SSMPaths,
) -> list[str]:
    """Compose all Docker build commands using function composition.

    This function chains together multiple command generators to create
    the complete Docker build command sequence.

    Args:
        ctx: Docker build context containing AWS environment details
        ssm_paths: SSM Parameter Store paths

    Returns:
        List of all Docker build commands in execution order
    """
    return list(
        chain(
            _create_assume_role_commands(ctx),
            _create_ecr_login_commands(ctx, ssm_paths),
            _create_docker_build_commands(ctx),
            _create_image_tagging_commands(),
            (_create_docker_tag_command(ctx),),
            _create_docker_push_commands(),
            _create_ssm_update_commands(ctx, ssm_paths),
            _create_revert_role_commands(ctx, ssm_paths),
        )
    )


# =============================================================================
# Public API Functions
# =============================================================================


def create_docker_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    docker_project_name: str,
) -> DockerCommands:
    """Create Docker build and push commands.

    This function generates all necessary commands for building Docker images
    and pushing them to Amazon ECR.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        docker_project_name: Name of the Docker project to build

    Returns:
        Dictionary containing:
            - "install_commands": Install phase configuration
            - "commands": List of commands to execute the Docker build process
    """
    ctx = _create_build_context(env, pipeline_vars, stage_name, docker_project_name)
    ssm_paths = _create_ssm_paths(pipeline_vars.project, stage_name)

    install_phase = install_pre_backed() if pipeline_vars.codebuild_docker_ecr_repo_arn else install_docker_default()

    return DockerCommands(
        install_commands=install_phase,
        commands=_compose_docker_build_commands(ctx, ssm_paths),
    )


def attach_docker_iam_role(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """Attach the Docker IAM role to a CodeBuild project.

    This role provides the necessary permissions for Docker to build images,
    access ECR repositories, and update SSM Parameter Store.

    Args:
        project: The CodeBuild pipeline project to attach the IAM role to
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
    """
    attach_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="docker",
    )


def create_build_environment(
    scope: Any,
    pipeline_vars: PipelineVars,
    stage_name: str,
    project_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
) -> codebuild.BuildEnvironment:
    """Create the build environment configuration for the Docker project.

    Args:
        scope: CDK construct scope
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        project_name: Name of the project
        cpu_architecture: CPU architecture for the build environment
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured BuildEnvironment for the CodeBuild project
    """
    build_image = get_build_image_for_architecture(
        self=scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
        cpu_architecture=cpu_architecture,
    )

    fleet = use_fleet(
        self=scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
    )

    return codebuild.BuildEnvironment(
        build_image=build_image,  # type: ignore
        privileged=True,
        compute_type=compute_type,
        fleet=fleet,
    )


def create_build_spec(commands: DockerCommands) -> codebuild.BuildSpec:
    """Create the build specification for the Docker CodeBuild project.

    Args:
        commands: Docker installation and execution commands

    Returns:
        BuildSpec object for the CodeBuild project
    """
    return codebuild.BuildSpec.from_object({
        "version": "0.2",
        "phases": {
            "install": commands["install_commands"],
            "build": {
                "commands": [
                    ". /.venv/bin/activate",
                    *commands["commands"],
                ],
            },
        },
    })


def create_environment_variables() -> dict[str, codebuild.BuildEnvironmentVariable]:
    """Create environment variables for the Docker CodeBuild project.

    Returns:
        Dictionary of environment variables
    """
    return {
        "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
            value="/var/run/docker/containerd/containerd.sock",
            type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
        ),
    }


def create_docker_build_project(
    *,
    scope: Any,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    docker_project_name: str,
    compute_type: codebuild.ComputeType,
) -> codebuild.PipelineProject:
    """Create a CodeBuild pipeline project for Docker image building.

    This function creates a fully configured CodeBuild project for building
    Docker images. The project:
    1. Selects the appropriate build image based on CPU architecture
    2. Generates Docker build and push commands
    3. Configures the build environment with Docker privileges
    4. Applies default permissions and attaches the Docker IAM role
    5. Builds, tags, and pushes images to ECR
    6. Stores image references in SSM Parameter Store

    Args:
        scope: CDK construct scope
        env: AWS environment containing region and account information
        stage_name: Name of the stage being deployed
        pipeline_vars: Pipeline variables containing project information
        cpu_architecture: CPU architecture for the build environment
        docker_project_name: Name of the Docker project/service to build
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured CodeBuild pipeline project for Docker image building
    """
    project_name = "docker_project"

    # Create Docker commands using functional composition
    commands = create_docker_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        docker_project_name=docker_project_name,
    )

    # Create the CodeBuild project
    docker_project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{docker_project_name}_{project_name}",
        environment=create_build_environment(
            scope=scope,
            pipeline_vars=pipeline_vars,
            stage_name=stage_name,
            project_name=project_name,
            cpu_architecture=cpu_architecture,
            compute_type=compute_type,
        ),
        environment_variables=create_environment_variables(),
        build_spec=create_build_spec(commands),
    )

    # Apply permissions and attach IAM role
    apply_default_permissions(docker_project, env)
    attach_docker_iam_role(
        project=docker_project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return docker_project
