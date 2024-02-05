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


def load_properties(stage: str) -> dict:
    """Loads configuration properties from YAML files.

    Returns:
        props (dict): Dictionary containing configuration properties loaded from YAML files.

    Functionality:
        1. Load base config properties from cdk/config/config-ci-cd.yaml into prop dict.
        2. Set props['stage'] to value of STAGE environment variable.
        3. Walk the directory tree under cdk/config/<STAGE> and load properties from
           each .yaml file into props_env dict.
        4. Merge props_env into props to produce final props dict containing
           properties from all config files.
        5. Return populated props dict.
    """

    config_file_path = Path("cdk/config/config-ci-cd.yaml")
    with config_file_path.open(encoding="utf-8") as file:
        props = yaml.safe_load(file)
        props["stage"] = stage

    props_env: dict[list, dict] = {}

    for dir_path, dir_names, files in walk(f"cdk/config/{stage}", topdown=False):  # noqa
        for file_name in files:
            file_path = Path(f"{dir_path}/{file_name}")
            with file_path.open(encoding="utf-8") as f:
                props_env |= yaml.safe_load(f)

    props_tags = props["tags"]
    conf_tags = props_env["tags"]  # type: ignore
    updated_props = {
        **props_env,
        **props,
        "tags": {**props_tags, **conf_tags},
        "slack_channel_id_alarms": props_env["slack_channel_id_alarms"],  # type: ignore
    }

    return updated_props
