"""Trivy security scanner CodeBuild project configuration.

This module provides functions to create and configure CodeBuild projects
for running Trivy security scans on Docker images and SBOMs.
"""

from functools import partial
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
class TrivyCommands(TypedDict):
    """Type definition for Trivy command structure."""

    install_commands: list[str]
    commands: list[str]


class ScanContext(TypedDict):
    """Context for scan command generation."""

    region: str
    account: str
    project: str
    stage_name: str


# =============================================================================
# Pure Helper Functions - High Cohesion, Single Responsibility
# =============================================================================


def _get_trivy_rpm_url(cpu_architecture: Literal["arm64", "amd64"], version: str) -> str:
    """Generate the Trivy RPM download URL for the specified architecture.

    Args:
        cpu_architecture: Target CPU architecture
        version: Trivy version to install

    Returns:
        Complete URL for the Trivy RPM package
    """
    arch_suffix = "64bit" if cpu_architecture == "amd64" else "ARM64"
    return f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-{arch_suffix}.rpm"


def _create_base_install_commands() -> tuple[str, ...]:
    """Generate base installation commands required for all architectures.

    Returns:
        Tuple of base installation commands
    """
    return (
        "n 22",
        "pip install uv",
        "make venv",
        "source .venv/bin/activate",
        "pip install boto3 click cdk-opinionated-constructs",
        "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
    )


def _create_trivy_install_command(
    cpu_architecture: Literal["arm64", "amd64"],
    trivy_version: str,
) -> str:
    """Generate Trivy installation command for the specified architecture.

    Args:
        cpu_architecture: Target CPU architecture
        trivy_version: Version of Trivy to install

    Returns:
        RPM installation command for Trivy
    """
    rpm_url = _get_trivy_rpm_url(cpu_architecture, trivy_version)
    return f"rpm -ivh {rpm_url}"


def _create_ecr_login_commands(ctx: ScanContext) -> tuple[str, ...]:
    """Generate ECR login and image retrieval commands.

    Args:
        ctx: Scan context containing AWS environment details

    Returns:
        Tuple of ECR login commands
    """
    return (
        f"export PASSWORD=$(aws ecr get-login-password --region {ctx['region']})",
        f'IMAGE_URI=$(aws ssm get-parameter --name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/image/uri" '
        f'--region {ctx["region"]} --query "Parameter.Value" --output text)',
        "echo $IMAGE_URI",
        f'IMAGE_TAG=$(aws ssm get-parameter --name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/image/tag" '
        f'--region {ctx["region"]} --query "Parameter.Value" --output text)',
        "echo $IMAGE_TAG",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {ctx['region']} | "
        f"docker login --username AWS --password-stdin {ctx['account']}.dkr.ecr.{ctx['region']}.amazonaws.com",
        "docker pull $IMAGE_URI",
    )


def _create_image_scan_commands() -> tuple[str, ...]:
    """Generate Docker image scanning commands.

    Returns:
        Tuple of image scanning commands
    """
    return (
        "echo Scanning image vulnerabilities...",
        "echo #################################################",
        "trivy image"
        " --timeout 60m"
        " --no-progress"
        " --scanners vuln,misconfig,secret"
        " -f json"
        " -o trivy_image_scan_result.json"
        " --severity HIGH,CRITICAL $IMAGE_URI",
        "echo #################################################",
    )


def _create_security_hub_parser_command(
    ctx: ScanContext,
    results_file: str,
) -> str:
    """Generate Security Hub parser command.

    Args:
        ctx: Scan context containing AWS environment details
        results_file: Path to the Trivy results JSON file

    Returns:
        Python command to run the Security Hub parser
    """
    return (
        f"python3 trivy_docker_image_security_hub_parser.py "
        f"--aws-account {ctx['account']} "
        f"--aws-region {ctx['region']} "
        f"--project-name {ctx['project']} "
        f"--container-name {ctx['project']}-{ctx['stage_name']} "
        f"--container-tag $IMAGE_TAG "
        f"--results-file {results_file}"
    )


def _create_image_security_hub_commands(ctx: ScanContext) -> tuple[str, ...]:
    """Generate commands to send Docker image scan results to Security Hub.

    Args:
        ctx: Scan context containing AWS environment details

    Returns:
        Tuple of Security Hub upload commands for image scan
    """
    return (
        "echo sending trivy Docker image results to Security Hub...",
        "wget https://raw.githubusercontent.com/airmonitor/cdk-opinionated-constructs/refs/heads/main/cdk_opinionated_constructs/utils/trivy_docker_image_security_hub_parser.py",
        _create_security_hub_parser_command(ctx, "trivy_image_scan_result.json"),
        "echo #################################################",
        "trivy image --scanners vuln,misconfig,secret $IMAGE_URI --timeout 60m --severity CRITICAL,HIGH --exit-code 1",
        "echo #################################################",
    )


def _create_sbom_scan_commands() -> tuple[str, ...]:
    """Generate SBOM generation and scanning commands.

    Returns:
        Tuple of SBOM scanning commands
    """
    return (
        "echo Scanning SBOM vulnerabilities...",
        "syft $IMAGE_URI -o spdx-json > /tmp/sbom.spdx.json",
        "trivy sbom"
        " --timeout 60m"
        " --no-progress"
        " --scanners vuln"
        " -f json"
        " -o sbom_trivy_results.json"
        " --severity HIGH,CRITICAL"
        " /tmp/sbom.spdx.json",
        "echo #################################################",
    )


def _create_sbom_security_hub_commands(ctx: ScanContext) -> tuple[str, ...]:
    """Generate commands to send SBOM scan results to Security Hub.

    Args:
        ctx: Scan context containing AWS environment details

    Returns:
        Tuple of Security Hub upload commands for SBOM scan
    """
    return (
        "echo sending trivy SBOM results to Security Hub...",
        _create_security_hub_parser_command(ctx, "sbom_trivy_results.json"),
        "echo #################################################",
        "trivy sbom --scanners vuln --timeout 60m --severity CRITICAL,HIGH --exit-code 1 /tmp/sbom.spdx.json",
    )


# =============================================================================
# Function Composition - Building Complex Commands from Simple Ones
# =============================================================================


def _compose_install_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    trivy_version: str,
) -> list[str]:
    """Compose all installation commands using function composition.

    Args:
        cpu_architecture: Target CPU architecture
        trivy_version: Version of Trivy to install

    Returns:
        List of all installation commands
    """
    return list(
        chain(
            _create_base_install_commands(),
            (_create_trivy_install_command(cpu_architecture, trivy_version),),
        )
    )


def _compose_scan_commands(
    ctx: ScanContext,
    assume_commands: list[str],
) -> list[str]:
    """Compose all scanning commands using function composition.

    This function chains together multiple command generators to create
    the complete scan command sequence.

    Args:
        ctx: Scan context containing AWS environment details
        assume_commands: Commands to assume the required IAM role

    Returns:
        List of all scanning commands in execution order
    """
    # Create partial applications for context-dependent functions
    image_security_hub = partial(_create_image_security_hub_commands, ctx)
    sbom_security_hub = partial(_create_sbom_security_hub_commands, ctx)
    ecr_login = partial(_create_ecr_login_commands, ctx)

    # Compose all command sequences
    return list(
        chain(
            assume_commands,
            ecr_login(),
            _create_image_scan_commands(),
            image_security_hub(),
            _create_sbom_scan_commands(),
            sbom_security_hub(),
        )
    )


def _create_scan_context(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> ScanContext:
    """Create an immutable scan context from environment parameters.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed

    Returns:
        Immutable context dictionary for scan operations
    """
    return ScanContext(
        region=str(env.region),
        account=str(env.account),
        project=pipeline_vars.project,
        stage_name=stage_name,
    )


# =============================================================================
# Public API Functions
# =============================================================================


def create_trivy_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    trivy_version: str = "0.68.1",
) -> TrivyCommands:
    """Create Trivy installation and execution commands.

    This function generates all necessary commands for installing Trivy
    and running security scans on Docker images and SBOMs.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        cpu_architecture: CPU architecture for installing the appropriate Trivy version
        assume_commands: Commands to assume the required IAM role
        trivy_version: Version of Trivy to install, defaults to "0.68.1"

    Returns:
        Dictionary containing:
            - "install_commands": List of commands to install Trivy and dependencies
            - "commands": List of commands to execute the security scanning process
    """
    ctx = _create_scan_context(env, pipeline_vars, stage_name)

    return TrivyCommands(
        install_commands=_compose_install_commands(cpu_architecture, trivy_version),
        commands=_compose_scan_commands(ctx, assume_commands),
    )


def attach_trivy_iam_role(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """Attach the Trivy IAM role to a CodeBuild project.

    This role provides the necessary permissions for Trivy to scan Docker images,
    access ECR repositories, and publish findings to AWS Security Hub.

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
        role_name="trivy",
    )


def create_build_environment(
    scope: Any,
    pipeline_vars: PipelineVars,
    stage_name: str,
    project_name: str,
    compute_type: codebuild.ComputeType,
) -> codebuild.BuildEnvironment:
    """Create the build environment configuration for the Trivy project.

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
    commands: TrivyCommands,
    pipeline_vars: PipelineVars,
) -> codebuild.BuildSpec:
    """Create the build specification for the Trivy CodeBuild project.

    Args:
        commands: Trivy installation and execution commands
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
                "commands": [
                    ". /.venv/bin/activate",
                    *commands["commands"],
                ],
            },
        },
    })


def create_environment_variables() -> dict[str, codebuild.BuildEnvironmentVariable]:
    """Create environment variables for the Trivy CodeBuild project.

    Returns:
        Dictionary of environment variables
    """
    return {
        "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
            value="/var/run/docker/containerd/containerd.sock",
            type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
        ),
    }


def create_trivy_project(
    *,
    scope: Any,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
    docker_project_name: str,
) -> codebuild.PipelineProject:
    """Create a CodeBuild pipeline project for Trivy security scanning.

    This function creates a fully configured CodeBuild project for running
    Trivy security scans on Docker images. The project:
    1. Selects the appropriate build image based on CPU architecture
    2. Generates Trivy installation and execution commands
    3. Configures the build environment with Docker privileges
    4. Applies default permissions and attaches the Trivy IAM role

    Args:
        scope: CDK construct scope
        env: AWS environment containing region and account information
        stage_name: Name of the stage being deployed
        pipeline_vars: Pipeline variables containing project information
        cpu_architecture: CPU architecture for the build environment
        compute_type: Compute type for the CodeBuild project
        docker_project_name: Name of the Docker project

    Returns:
        Configured CodeBuild pipeline project for Trivy security scans
    """
    project_name = "trivy_project"

    # Generate assume role commands
    assume_commands = assume_role_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="trivy",
    )

    # Create Trivy commands using functional composition
    commands = create_trivy_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
        assume_commands=assume_commands,
    )

    # Create the CodeBuild project
    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{docker_project_name}_{project_name}",
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
    attach_trivy_iam_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return project
