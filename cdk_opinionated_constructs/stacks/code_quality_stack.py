"""The pre-prerequisites stack which create resource which needs to exist
before core stack will be created.

Example is SSM parameter store entry ci/cd configuration values
"""

from os import walk
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.aws_ssm as ssm
import yaml

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from constructs import Construct

from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars


class CodeQualityStack(cdk.Stack):
    """Constructs the CodeQualityStack. As CDK pipeline can't contain empty
    stage to which additional jobs will be added, this stack will create AWS
    SSM parameter store with the content of used configuration file. It is done
    like this as a workaround to the CDK pipelines limitations.

    Parameters:
      - scope: The parent Construct for this Stack.
      - construct_id: The id of this Stack.
      - env: The environment this stack is targeting.
      - props: Base configuration properties.
      - **kwargs: Additional stack options.

    Functionality:
      - Loads configuration files from cdk/config/{stage} into props_env.
      - Merges props_env into props.
      - Creates an SSM StringParameter to hold the config values.
      - Parameter name is /{project}/{stage}/config.
      - Adds the AwsSolutionsChecks aspect to enable CDK Nag rules.
    """

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        props_env: dict[list, dict] = {}
        config_vars = ConfigurationVars(**props)

        for dir_path, dir_names, files in walk(f"cdk/config/{config_vars.stage}", topdown=False):  # noqa
            for file_name in files:
                file_path = Path(f"{dir_path}/{file_name}")
                with file_path.open(encoding="utf-8") as f:
                    props_env |= yaml.safe_load(f)
                    props = {**props_env, **props}

        ssm.StringParameter(
            self,
            id="config_file",
            string_value=str(props_env),
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/config",
        )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
