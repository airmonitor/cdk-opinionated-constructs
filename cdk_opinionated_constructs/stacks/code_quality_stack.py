"""The pre-prerequisites stack which create resource which needs to exist
before core stack will be created.

Example is SSM parameter store entry ci/cd configuration values
"""

import aws_cdk as cdk
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from cdk_opinionated_constructs.stacks import count_characters_number, reduce_items_number, set_ssm_parameter_tier_type
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


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
        config_vars = ConfigurationVars(**props)

        ssm_parameter_value = reduce_items_number(values=load_properties(stage=config_vars.stage))
        character_number = count_characters_number(ssm_parameter_value)

        ssm.StringParameter(
            self,
            id="config_file",
            string_value=str(ssm_parameter_value),
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/config",
            tier=set_ssm_parameter_tier_type(character_number=character_number),
        )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
