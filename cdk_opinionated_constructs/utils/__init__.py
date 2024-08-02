"""Helper functions to make your life simple."""

from os import walk
from pathlib import Path

import aws_cdk as cdk
import yaml

from aws_cdk import Stack, Stage


def check_ansible_dir(directory: str) -> bool:
    """Checks if an Ansible directory exists.

    Parameters:
      - directory (str): The directory path to check.

    Returns:
      - bool: True if the directory exists, False otherwise.

    Functionality:
      - Resolves the full path using the __file__ variable.
      - Checks if the path exists and is a directory using pathlib.
      - Returns True if it's a directory, False otherwise.
    """

    this_dir = Path(__file__).parent
    ansible_path = this_dir.joinpath(directory).resolve()
    return ansible_path.is_dir()


def apply_tags(props: dict, resource: cdk.Stack | cdk.Stage) -> Stack | Stage:
    """Applies tags to a CDK Stack or Stage.

    Parameters:
      - props (dict): Dictionary containing tags to apply
      - resource (cdk.Stack | cdk.Stage): Stack or Stage to apply tags to

    Returns:
      - Stack | Stage: The same resource passed in, after tags applied

    Functionality:
      - Loops through tags in props and adds them to the resource with cdk.Tags.of
      - Returns the modified resource object
    """

    for key, value in props["tags"].items():
        cdk.Tags.of(resource).add(key, value)

    return resource


def _load_base_properties(stage: str) -> dict:
    """Loads base properties from the config-ci-cd.yaml file."""
    config_file_path = Path("cdk/config/config-ci-cd.yaml")
    with config_file_path.open(encoding="utf-8") as file:
        props = yaml.safe_load(file)
        props["stage"] = stage
    return props


def _load_stage_properties(stage: str) -> dict:
    """Loads stage-specific properties from files in the stage directory."""
    props_env: dict[str, str] = {}
    for dir_path, _, files in walk(f"cdk/config/{stage}", topdown=False):
        for file_name in files:
            file_path = Path(f"{dir_path}/{file_name}")
            with file_path.open(encoding="utf-8") as f:
                props_env.update(yaml.safe_load(f) or {})
    return props_env


def load_properties(stage: str) -> dict:
    """Loads properties from YAML configuration files.

    Args:
        stage (str): The deployment stage (e.g., 'dev', 'prod').

    Returns:
        dict: A dictionary containing the loaded properties.
    """

    props = _load_base_properties(stage)
    props_env = _load_stage_properties(stage)

    # Merge tags, giving precedence to stage-specific tags
    props_tags = props.get("tags", {})
    conf_tags = props_env.get("tags", {})
    updated_props = {
        **props_env,
        **props,
        "tags": {**props_tags, **conf_tags},
    }

    # Add optional properties if they exist in stage-specific config
    optional_keys = ["slack_channel_id_alarms", "ms_teams_channel_id_alarms"]
    for key in optional_keys:
        value = props_env.get(key)
        if value:
            updated_props[key] = value

    return updated_props
