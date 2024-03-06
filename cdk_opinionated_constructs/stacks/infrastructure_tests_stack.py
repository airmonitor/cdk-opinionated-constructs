import aws_cdk as cdk
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from cdk_opinionated_constructs.stacks import reduce_items_number, set_ssm_parameter_tier_type
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


class InfrastructureTestsStack(cdk.Stack):
    """Infrastructure tests stack."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        """Initializes the InfrastructureTestsStack construct.

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

        4. Create a ConfigurationVars object from the merged configuration.

        5. Create an SSM StringParameter to store the ConfigurationVars as a string,
           for later retrieval.

        6. Validates the stack against the AWS Solutions checklist using Aspects.
        """

        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        props_env = load_properties(stage=config_vars.stage)
        ssm_parameter_value = reduce_items_number(values=props_env)

        ssm.StringParameter(
            self,
            id="config_file",
            string_value=str(ssm_parameter_value),
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/infrastructure/tests/config",
            tier=set_ssm_parameter_tier_type(character_number=len(str(ssm_parameter_value))),
        )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
