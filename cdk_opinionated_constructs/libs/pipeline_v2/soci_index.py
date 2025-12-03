from typing import Literal

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


def _create_soci_index_install_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    soci_snapshotter_version: str = "0.11.1",
) -> list[str]:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for which to install
            SOCI binaries (arm64 or amd64)
        soci_snapshotter_version (str): Version of SOCI snapshotter to install, defaults to "0.11.1"

    Functionality:
        Generates a list of shell commands that:
        1. Retrieves ECR credentials and Docker image URI from SSM parameters
        2. Downloads the appropriate SOCI (Seekable OCI) snapshotter binaries for the specified architecture
        3. Installs the SOCI tool to the system path
        4. Authenticates with Amazon ECR
        5. Pulls the container image using containerd
        6. Generates a SOCI index for the container image, which enables lazy loading
        7. Pushes the SOCI index back to ECR

        SOCI indexes enable container images to start before being fully downloaded,
        significantly improving container startup times for large images.

    Returns:
        list[str]: A list of shell commands to be executed in a CodeBuild environment
    """

    ecr_ssm_path_base = f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/ecr"

    commands = [
        f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
        f"IMAGE_URI=$(aws ssm get-parameter "
        f'--name "{ecr_ssm_path_base}/image/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_URI",
        "echo Download the SOCI Binaries",
        f"wget --quiet https://github.com/awslabs/soci-snapshotter/releases/download/"
        f"v{soci_snapshotter_version}/soci-snapshotter-{soci_snapshotter_version}-linux-{cpu_architecture}.tar.gz",
        f"tar xvzf soci-snapshotter-{soci_snapshotter_version}-linux-{cpu_architecture}.tar.gz soci",
        "mv soci /usr/local/bin/soci",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {env.region} | "
        f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
        "ctr image pull -user AWS:$PASSWORD $IMAGE_URI",
        "echo Generating SOCI index ",
        "soci create $IMAGE_URI ",
        "echo Push the SOCI index to ECR ",
        "soci push --user AWS:$PASSWORD $IMAGE_URI ",
    ]

    return commands


def _attach_soci_index_iam_policies(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild project to attach IAM policies to
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed

    Functionality:
        Attaches necessary IAM policies to the SOCI index
    """

    attach_role(project=project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="docker")


def create_soci_index_project(
    *,
    scope,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
) -> codebuild.PipelineProject:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        stage_name (str): Name of the stage being deployed
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for which to create the build project
        compute_type (codebuild.ComputeType): AWS CodeBuild compute type to use for the build project

    Functionality:
        Creates an AWS CodeBuild pipeline project for generating SOCI indexes for container images.
        The project:
        1. Sets up a build environment with the appropriate architecture-specific build image
        2. Configures a build specification with installation commands
        3. Includes commands to:
           - Retrieve ECR credentials and Docker image URI
           - Download and install SOCI snapshotter binaries
           - Authenticate with Amazon ECR
           - Pull the container image using containerd
           - Generate a SOCI index for the container image
           - Push the SOCI index back to ECR
        4. Applies default IAM permissions for CDK operations
        5. Attaches necessary IAM policies for Docker operations
        6. Supports optional CodeBuild fleet configuration

    Arguments:
        scope: The CDK construct scope
        env: AWS environment object
        stage_name: Deployment stage name
        pipeline_vars: Pipeline configuration variables
        cpu_architecture: Target CPU architecture for the build
        compute_type: AWS CodeBuild compute type

    Returns:
        codebuild.PipelineProject: The configured AWS CodeBuild pipeline project for SOCI index generation
    """
    project_name = "soci_index_project"
    build_image = get_build_image_for_architecture(
        self=scope, pipeline_vars=pipeline_vars, stage_name=stage_name, stage_type=project_name
    )

    commands = _create_soci_index_install_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
    )

    fleet = None
    if pipeline_vars.codebuild_fleet_arn:
        fleet = codebuild.Fleet.from_fleet_arn(
            scope, id=f"{stage_name}_{project_name}_imported_fleet", fleet_arn=pipeline_vars.codebuild_fleet_arn
        )

    install_default = {
        "runtime-versions": runtime_versions,
        "commands": ["pip install uv", "make venv", ". .venv/bin/activate", *default_install_commands],
    }
    install_pre_backed = {
        "commands": [
            "nohup /usr/local/bin/dockerd "
            "--host=unix:///var/run/docker.sock "
            "--host=tcp://127.0.0.1:2375 "
            "--storage-driver=overlay2 &"
        ]
    }

    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{project_name}",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
            fleet=fleet,
        ),
        auto_retry_limit=3,
        environment_variables={
            "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                value="/var/run/docker/containerd/containerd.sock",
                type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
            ),
        },
        build_spec=codebuild.BuildSpec.from_object({
            "version": "0.2",
            "phases": {
                "install": install_pre_backed if pipeline_vars.codebuild_docker_ecr_repo_arn else install_default,
                "build": {
                    "commands": [
                        *assume_role_commands(
                            env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="docker"
                        ),
                        *commands,
                    ],
                },
            },
        }),
    )

    apply_default_permissions(project, env)
    _attach_soci_index_iam_policies(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return project
