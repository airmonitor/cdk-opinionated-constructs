"""SOCI (Seekable OCI) index CodeBuild project configuration.

This module provides functions to create and configure CodeBuild projects
for generating SOCI indexes for container images, enabling lazy loading
and faster container startup times.
"""

from itertools import chain
from typing import Any, Literal, TypedDict

import aws_cdk.aws_codebuild as codebuild

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.libs.pipeline_v2 import (
    install_default,
    install_pre_backed,
    use_fleet,
)
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    assume_role_commands,
    attach_role,
    get_build_image_for_architecture,
)


# Type definitions for better type safety and documentation
class SociCommands(TypedDict):
    """Type definition for SOCI command structure."""

    install_commands: list[str]
    commands: list[str]


class SociContext(TypedDict):
    """Context for SOCI index command generation."""

    region: str
    account: str
    project: str
    stage_name: str


# =============================================================================
# Pure Helper Functions - High Cohesion, Single Responsibility
# =============================================================================


def _get_soci_download_url(cpu_architecture: Literal["arm64", "amd64"], version: str) -> str:
    """Generate the SOCI snapshotter download URL for the specified architecture.

    Args:
        cpu_architecture: Target CPU architecture
        version: SOCI snapshotter version to install

    Returns:
        Complete URL for the SOCI snapshotter tarball
    """
    return (
        f"https://github.com/awslabs/soci-snapshotter/releases/download/"
        f"v{version}/soci-snapshotter-{version}-linux-{cpu_architecture}.tar.gz"
    )


def _create_ecr_credentials_commands(ctx: SociContext) -> tuple[str, ...]:
    """Generate ECR credentials retrieval commands.

    Args:
        ctx: SOCI context containing AWS environment details

    Returns:
        Tuple of ECR credentials commands
    """
    return (
        f"export PASSWORD=$(aws ecr get-login-password --region {ctx['region']})",
        f'IMAGE_URI=$(aws ssm get-parameter --name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/image/uri" '
        f'--region {ctx["region"]} --query "Parameter.Value" --output text)',
        "echo $IMAGE_URI",
    )


def _create_soci_download_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    soci_version: str,
) -> tuple[str, ...]:
    """Generate SOCI snapshotter download and installation commands.

    Args:
        cpu_architecture: Target CPU architecture
        soci_version: Version of SOCI snapshotter to install

    Returns:
        Tuple of SOCI download and installation commands
    """
    download_url = _get_soci_download_url(cpu_architecture, soci_version)
    tarball_name = f"soci-snapshotter-{soci_version}-linux-{cpu_architecture}.tar.gz"

    return (
        "echo Download the SOCI Binaries",
        f"wget --quiet {download_url}",
        f"tar xvzf {tarball_name} soci",
        "mv soci /usr/local/bin/soci",
    )


def _create_ecr_login_commands(ctx: SociContext) -> tuple[str, ...]:
    """Generate ECR login commands.

    Args:
        ctx: SOCI context containing AWS environment details

    Returns:
        Tuple of ECR login commands
    """
    return (
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {ctx['region']} | "
        f"docker login --username AWS --password-stdin {ctx['account']}.dkr.ecr.{ctx['region']}.amazonaws.com",
    )


def _create_image_pull_commands() -> tuple[str, ...]:
    """Generate containerd image pull commands.

    Returns:
        Tuple of containerd image pull commands
    """
    return ("ctr image pull -user AWS:$PASSWORD $IMAGE_URI",)


def _create_soci_index_commands() -> tuple[str, ...]:
    """Generate SOCI index creation and push commands.

    Returns:
        Tuple of SOCI index commands
    """
    return (
        "echo Generating SOCI index ",
        "soci create $IMAGE_URI ",
        "echo Push the SOCI index to ECR ",
        "soci push --user AWS:$PASSWORD $IMAGE_URI ",
    )


# =============================================================================
# Function Composition - Building Complex Commands from Simple Ones
# =============================================================================


def _compose_install_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    soci_version: str,
) -> list[str]:
    """Compose all installation commands using function composition.

    Args:
        cpu_architecture: Target CPU architecture
        soci_version: Version of SOCI snapshotter to install

    Returns:
        List of all installation commands
    """
    return list(_create_soci_download_commands(cpu_architecture, soci_version))


def _compose_build_commands(
    ctx: SociContext,
    assume_commands: list[str],
) -> list[str]:
    """Compose all build commands using function composition.

    This function chains together multiple command generators to create
    the complete build command sequence.

    Args:
        ctx: SOCI context containing AWS environment details
        assume_commands: Commands to assume the required IAM role

    Returns:
        List of all build commands in execution order
    """
    return list(
        chain(
            assume_commands,
            _create_ecr_credentials_commands(ctx),
            _create_ecr_login_commands(ctx),
            _create_image_pull_commands(),
            _create_soci_index_commands(),
        )
    )


def _create_soci_context(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> SociContext:
    """Create an immutable SOCI context from environment parameters.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed

    Returns:
        Immutable context dictionary for SOCI operations
    """
    return SociContext(
        region=str(env.region),
        account=str(env.account),
        project=pipeline_vars.project,
        stage_name=stage_name,
    )


# =============================================================================
# Public API Functions
# =============================================================================


def create_soci_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    soci_version: str = "0.12.0",
) -> SociCommands:
    """Create SOCI installation and execution commands.

    This function generates all necessary commands for installing SOCI
    and generating indexes for container images.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        cpu_architecture: CPU architecture for installing the appropriate SOCI version
        assume_commands: Commands to assume the required IAM role
        soci_version: Version of SOCI snapshotter to install, defaults to "0.12.0"

    Returns:
        Dictionary containing:
            - "install_commands": List of commands to install SOCI binaries
            - "commands": List of commands to execute the SOCI index generation
    """
    ctx = _create_soci_context(env, pipeline_vars, stage_name)

    return SociCommands(
        install_commands=_compose_install_commands(cpu_architecture, soci_version),
        commands=_compose_build_commands(ctx, assume_commands),
    )


def attach_soci_iam_role(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """Attach the SOCI IAM role to a CodeBuild project.

    This role provides the necessary permissions for SOCI to pull container images,
    generate indexes, and push them back to ECR.

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
    compute_type: codebuild.ComputeType,
) -> codebuild.BuildEnvironment:
    """Create the build environment configuration for the SOCI project.

    Args:
        scope: CDK construct scope
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        project_name: Name of the project
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured BuildEnvironment for the CodeBuild project
    """
    build_image = get_build_image_for_architecture(
        self=scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
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


def create_build_spec(
    commands: SociCommands,
    pipeline_vars: PipelineVars,
) -> codebuild.BuildSpec:
    """Create the build specification for the SOCI CodeBuild project.

    Args:
        commands: SOCI installation and execution commands
        pipeline_vars: Pipeline variables containing project information

    Returns:
        BuildSpec object for the CodeBuild project
    """
    install_phase = (
        install_pre_backed() if pipeline_vars.codebuild_docker_ecr_repo_arn else install_default(dict(commands))
    )

    return codebuild.BuildSpec.from_object({
        "version": "0.2",
        "phases": {
            "install": install_phase,
            "build": {
                "commands": commands["commands"],
            },
        },
    })


def create_environment_variables() -> dict[str, codebuild.BuildEnvironmentVariable]:
    """Create environment variables for the SOCI CodeBuild project.

    Returns:
        Dictionary of environment variables
    """
    return {
        "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
            value="/var/run/docker/containerd/containerd.sock",
            type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
        ),
    }


def create_soci_index_project(
    *,
    scope: Any,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
) -> codebuild.PipelineProject:
    """Create a CodeBuild pipeline project for SOCI index generation.

    This function creates a fully configured CodeBuild project for generating
    SOCI indexes for container images. The project:
    1. Selects the appropriate build image based on CPU architecture
    2. Generates SOCI installation and execution commands
    3. Configures the build environment with Docker privileges
    4. Applies default permissions and attaches the Docker IAM role

    SOCI indexes enable container images to start before being fully downloaded,
    significantly improving container startup times for large images.

    Args:
        scope: CDK construct scope
        env: AWS environment containing region and account information
        stage_name: Name of the stage being deployed
        pipeline_vars: Pipeline variables containing project information
        cpu_architecture: CPU architecture for the build environment
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured CodeBuild pipeline project for SOCI index generation
    """
    project_name = "soci_index_project"

    # Generate assume role commands
    assume_commands = assume_role_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="docker",
    )

    # Create SOCI commands using functional composition
    commands = create_soci_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
        assume_commands=assume_commands,
    )

    # Create the CodeBuild project
    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{project_name}",
        environment=create_build_environment(
            scope=scope,
            pipeline_vars=pipeline_vars,
            stage_name=stage_name,
            project_name=project_name,
            compute_type=compute_type,
        ),
        auto_retry_limit=3,
        environment_variables=create_environment_variables(),
        build_spec=create_build_spec(commands, pipeline_vars),
    )

    # Apply permissions and attach IAM role
    apply_default_permissions(project, env)
    attach_soci_iam_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return project
