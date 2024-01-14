"""Helper functions to make your life simple."""

from pathlib import Path

import aws_cdk as cdk

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
