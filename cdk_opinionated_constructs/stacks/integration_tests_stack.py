import aws_cdk as cdk
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from cdk_opinionated_constructs.stacks import reduce_items_number, set_ssm_parameter_tier_type
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


class IntegrationTestsStack(cdk.Stack):
    """IntegrationTestsStack defines a CDK stack for integration tests
    configuration.

    It loads configuration files from the cdk/config directory into a dict.
    It creates a ConfigurationVars object from the combined props and config.

    It stores the ConfigurationVars as a StringParameter in SSM, with a name built from
    the config values.

    It validates the stack against the AWS Solutions checklist.

    Parameters:

    - scope: The CDK scope constructing this stack.
    - construct_id: ID for the stack construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stack.
    - **kwargs: Additional stack options.
    """

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        props_env = load_properties(stage=config_vars.stage)
        ssm_parameter_value = reduce_items_number(values=props_env)

        ssm.StringParameter(
            self,
            id="config_file",
            string_value=str(ssm_parameter_value),
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/integration/tests/config",
            tier=set_ssm_parameter_tier_type(character_number=len(str(ssm_parameter_value))),
        )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
