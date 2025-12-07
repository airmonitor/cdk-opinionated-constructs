import aws_cdk.aws_codebuild as codebuild

from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.stages.logic import (
    default_install_commands,
    runtime_versions,
)


def use_fleet(*, self, pipeline_vars: PipelineVars, stage_name: str, stage_type: str) -> codebuild.IFleet | None:
    """
    Parameters:
        pipeline_vars (PipelineVars): PipelineVars object containing pipeline configuration
        stage_name (str): Name of the stage
        stage_type (str): Type of the stage

    Functionality:
        Retrieves a CodeBuild Fleet based on pipeline configuration variables
        Supports fleet retrieval from ARN or SSM parameter
        Returns None if no fleet configuration is provided

    Arguments:
        pipeline_vars: PipelineVars object containing pipeline configuration
        stage_name: Name of the stage
        stage_type: Type of the stage

    Returns:
        codebuild.IFleet | None: A CodeBuild Fleet object if configuration is provided, otherwise None
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


def install_default(commands: dict) -> dict:
    return {
        "runtime-versions": runtime_versions,
        "commands": [
            "pip install uv",
            "make venv",
            ". .venv/bin/activate",
            *default_install_commands,
            *commands["install_commands"],
        ],
    }


def install_docker_default() -> dict:
    return {
        "runtime-versions": runtime_versions,
        "commands": [
            "pip install uv",
            "make venv",
            ". .venv/bin/activate",
            *default_install_commands,
        ],
    }
