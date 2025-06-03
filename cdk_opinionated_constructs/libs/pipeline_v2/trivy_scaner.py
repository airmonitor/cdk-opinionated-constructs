from typing import Any, Literal

import aws_cdk.aws_codebuild as codebuild

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    assume_role_commands,
    attach_role,
    default_install_commands,
    get_build_image_for_architecture,
    runtime_versions,
)


def _create_trivy_install_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    cdk_opinionated_constructs_version: str = "4.2.5",
    trivy_version: str = "0.63.0",
) -> dict[str, list[str] | list[str | Any]]:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for installing the
            appropriate Trivy version
        cdk_opinionated_constructs_version (str): Version of cdk-opinionated-constructs
            to use for the Trivy parser script, defaults to "4.2.5"
        trivy_version (str): Version of Trivy to install, defaults to "0.63.0"

    Functionality:
        Generates installation and execution commands for Trivy security scanner
        that will be used in a CodeBuild project. The function:
        1. Creates commands to install Trivy with the appropriate architecture-specific binary
        2. Creates commands to install supporting Python packages (boto3, click)
        3. Downloads a parser script to export Trivy results to AWS Security Hub
        4. Generates commands to retrieve Docker image information from SSM parameters
        5. Creates commands to pull the Docker image and scan it for vulnerabilities
        6. Creates commands to retrieve and scan the SBOM file from S3
        7. Configures commands to export scan results to AWS Security Hub
        8. Sets up final scan commands that will fail the build if HIGH or CRITICAL
        vulnerabilities are found

    Returns:
        dict[str, list[str] | list[str | Any]]: Dictionary containing two keys:
            - "install_commands": List of commands to install Trivy and dependencies
            - "commands": List of commands to execute the security scanning process
    """

    _install_commands = [
        "pip3 install boto3 click",
        f"wget https://raw.githubusercontent.com/airmonitor/cdk-opinionated-constructs/refs/heads/"
        f"{cdk_opinionated_constructs_version}/cdk_opinionated_constructs/utils/"
        f"trivy_docker_image_security_hub_parser.py",
        "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
    ]

    if cpu_architecture == "amd64":
        _install_commands.extend([
            f"rpm -ivh https://github.com/aquasecurity/trivy/releases/download/"
            f"v{trivy_version}/trivy_{trivy_version}_Linux-64bit.rpm",
        ])
    else:
        _install_commands.extend([
            f"rpm -ivh https://github.com/aquasecurity/trivy/releases/download/"
            f"v{trivy_version}/trivy_{trivy_version}_Linux-ARM64.rpm",
        ])
    commands = [
        *assume_commands,
        f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
        f"IMAGE_URI=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_URI",
        f"IMAGE_TAG=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/tag" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_TAG",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {env.region} | "
        f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
        "docker pull $IMAGE_URI",
        "echo Scanning image vulnerabilities...",
        "echo #################################################",
        "trivy image"
        " --timeout 60m"
        " --no-progress"
        " --scanners vuln,misconfig,secret"
        " -f json "
        " -o trivy_image_scan_result.json"
        " --severity HIGH,CRITICAL $IMAGE_URI",
        "echo #################################################",
        "echo sending trivy Docker image results to Security Hub...",
        f"python3 trivy_docker_image_security_hub_parser.py "
        f"--aws-account {env.account} "
        f"--aws-region {env.region} "
        f"--project-name {pipeline_vars.project} "
        f"--container-name {pipeline_vars.project}-{stage_name} "
        f"--container-tag $IMAGE_TAG "
        f"--results-file trivy_image_scan_result.json",
        "echo #################################################",
        "trivy image --scanners vuln,misconfig,secret $IMAGE_URI --timeout 60m --severity CRITICAL,HIGH --exit-code 1 ",
        "echo #################################################",
        "echo Scanning SBOM vulnerabilities...",
        "syft $IMAGE_URI -o spdx-json > /tmp/sbom.spdx.json",
        "trivy sbom "
        " --timeout 60m"
        " --no-progress"
        " --scanners vuln"
        " -f json "
        " -o sbom_trivy_results.json "
        "--severity HIGH,CRITICAL"
        " /tmp/sbom.spdx.json",
        "echo #################################################",
        "echo sending trivy SBOM results to Security Hub...",
        f"python3 trivy_docker_image_security_hub_parser.py "
        f"--aws-account {env.account} "
        f"--aws-region {env.region} "
        f"--project-name {pipeline_vars.project} "
        f"--container-name {pipeline_vars.project}-{stage_name} "
        f"--container-tag $IMAGE_TAG "
        f"--results-file sbom_trivy_results.json",
        "echo #################################################",
        "trivy sbom --scanners vuln --timeout 60m --severity CRITICAL,HIGH --exit-code 1 /tmp/sbom.spdx.json",
    ]

    return {"install_commands": _install_commands, "commands": commands}


def _attach_trivy_iam_role(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild pipeline project to attach the IAM role to
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed

    Functionality:
        Attaches the Trivy IAM role to the specified CodeBuild project.
        This role provides the necessary permissions for Trivy to scan Docker images,
        access ECR repositories, and publish findings to AWS Security Hub.
        The function delegates to the generic 'attach_role' function with the role name "trivy".
    """
    attach_role(project=project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="trivy")


def create_trivy_project(
    *,
    scope,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
    docker_project_name: str,
) -> codebuild.PipelineProject:
    """
    Parameters:
        scope: The CDK construct scope in which this construct is created
        env (Environment): AWS environment containing region and account information
        stage_name (str): Name of the stage being deployed
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture to determine the appropriate build image
        compute_type (codebuild.ComputeType): The compute resources for the CodeBuild project
        docker_project_name (str): Base name for the Docker project that will be scanned

    Functionality:
        Creates a CodeBuild pipeline project that performs security scanning with Trivy.
        The project:
        1. Determines the appropriate build image based on CPU architecture
        2. Configures Trivy installation commands for the specified architecture
        3. Creates a CodeBuild environment with Docker support (privileged mode)
        4. Sets up environment variables needed for container operations
        5. Configures build phases to install dependencies and run security scans
        6. Scans both Docker images and SBOM files for security vulnerabilities
        7. Reports findings to AWS Security Hub
        8. Fails the build if HIGH or CRITICAL vulnerabilities are found
        9. Applies necessary IAM permissions for ECR, SSM, S3, and Security Hub access

    Returns:
        codebuild.PipelineProject: A configured CodeBuild project for Trivy security scanning
    """
    build_image = get_build_image_for_architecture(cpu_architecture)

    _assume_trivy_role_commands = assume_role_commands(
        env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="trivy"
    )

    commands = _create_trivy_install_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
        assume_commands=_assume_trivy_role_commands,
    )

    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{docker_project_name}_trivy_project",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
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
                        *commands["install_commands"],
                    ],
                },
                "build": {
                    "commands": [*commands["commands"]],
                },
            },
        }),
    )

    apply_default_permissions(project, env)
    _attach_trivy_iam_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return project
