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


def use_fleet(*, self, pipeline_vars: PipelineVars, stage_name: str, stage_type: str) -> codebuild.IFleet | None:
    """
    Parameters:
        self
        pipeline_vars (PipelineVars): PipelineVars object containing pipeline configuration
        stage_name (str): Name of the stage
        stage_type (str): Type of the stage

    Functionality:
        Retrieves or creates a CodeBuild fleet based on the provided pipeline variables
        Returns an imported fleet if a fleet ARN is available in pipeline_vars, otherwise returns None

    Arguments:
        pipeline_vars: PipelineVars object containing pipeline configuration
        stage_name: Name of the stage
        stage_type: Type of the stage

    Returns:
        codebuild.IFleet | None: An IFleet object if fleet_arn exists in pipeline_vars, otherwise None
    """
    if pipeline_vars.codebuild_fleet_arn:
        return codebuild.Fleet.from_fleet_arn(
            self, id=f"{stage_name}_{stage_type}_imported_fleet", fleet_arn=pipeline_vars.codebuild_fleet_arn
        )
    return None


def install_pre_backed() -> dict:
    return {
        "commands": [
            "nohup /usr/local/bin/dockerd "
            "--host=unix:///var/run/docker.sock "
            "--host=tcp://127.0.0.1:2375 "
            "--storage-driver=overlay2 &"
        ]
    }


def install_default() -> dict:
    return {
        "runtime-versions": runtime_versions,
        "commands": [
            "pip install uv",
            "make venv",
            ". .venv/bin/activate",
            *default_install_commands,
        ],
    }


def _create_docker_build_commands(
    *, env: Environment, pipeline_vars: PipelineVars, stage_name: str, docker_project_name: str
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
        scope: The construct scope in which this resource is defined
        env (Environment): AWS environment containing region and account information
        stage_name (str): Name of the stage being deployed
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        docker_project_name (str): Name of the Docker project/service to build
        compute_type (codebuild.ComputeType): AWS CodeBuild compute type for the build environment

    Functionality:
        Creates an AWS CodeBuild pipeline project configured for Docker image building that:
        1. Sets up a build environment based on the specified CPU architecture
        2. Configures the build environment with proper Docker privileges
        3. Creates Docker build commands for the specified project
        4. Sets up a build specification with necessary runtime versions and commands
        5. Applies default permissions and Docker-specific IAM policies
        6. The Docker build process will build, tag, and push images to ECR
        7. Stores image references in SSM Parameter Store for later use

    Returns:
        codebuild.PipelineProject: A fully configured CodeBuild project for Docker image building
    """
    project_name = "docker_project"

    docker_commands = _create_docker_build_commands(
        env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, docker_project_name=docker_project_name
    )

    docker_project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{docker_project_name}_{project_name}",
        environment=codebuild.BuildEnvironment(
            build_image=get_build_image_for_architecture(
                self=scope,
                pipeline_vars=pipeline_vars,
                stage_name=stage_name,
                stage_type=project_name,
                cpu_architecture=cpu_architecture,
            ),
            privileged=True,
            compute_type=compute_type,
            fleet=use_fleet(self=scope, pipeline_vars=pipeline_vars, stage_name=stage_name, stage_type=project_name),
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
                "install": install_pre_backed() if pipeline_vars.codebuild_docker_ecr_repo_arn else install_default(),
                "build": {
                    "commands": [
                        ". /.venv/bin/activate",
                        *docker_commands,
                    ],
                },
            },
        }),
    )

    apply_default_permissions(docker_project, env)
    _attach_docker_iam_policies(project=docker_project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name)

    return docker_project
