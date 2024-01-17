from os import walk
from pathlib import Path

import aws_cdk as cdk
import aws_cdk.aws_ssm as ssm
import yaml

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from constructs import Construct

from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars


class PipelinePluginsStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        """Initializes the PipelinePluginsStack construct.

        Parameters:
        - scope (Construct): The parent construct.
        - construct_id (str): The construct ID.
        - env: The CDK environment.
        - props: Stack configuration properties.
        - **kwargs: Additional keyword arguments passed to the Stack constructor.

        The constructor does the following:

        1. Call the parent Stack constructor.

        2. Loads configuration from YAML files in the config directory for the stage.

        3. Merge the loaded configuration with the passed props.

        4. Create ConfigurationVars and PipelineVars objects from the configuration.

        5. Create an SSM StringParameter to store the pipeline plugins configuration
           from PipelineVars, for later retrieval.

        6. Validates the stack against the AWS Solutions checklist using Aspects.
        """

        super().__init__(scope, construct_id, env=env, **kwargs)
        props_env: dict[list, dict] = {}

        for dir_path, dir_names, files in walk(f"cdk/config/{props['stage']}", topdown=False):  # noqa
            for file_name in files:
                file_path = Path(f"{dir_path}/{file_name}")
                with file_path.open(encoding="utf-8") as f:
                    props_env |= yaml.safe_load(f)
                    props = {**props_env, **props}

        config_vars = ConfigurationVars(**props)

        ssm.StringParameter(
            self,
            id="pipeline_plugins",
            string_value=str(config_vars.plugins),
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/pipeline_plugins",
        )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
