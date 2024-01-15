"""The AWS shared resources for core application stage."""

import aws_cdk as cdk

from constructs import Construct

from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from cdk_opinionated_constructs.stacks.pipeline_plugins_stack import PipelinePluginsStack
from cdk_opinionated_constructs.stacks.pipeline_trigger_stack import PipelineTriggerStack


class PluginsStage(cdk.Stage):
    """Create CI/CD stage with shared resources."""

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        """Initialize default parameters from AWS CDK and configuration file.

        :param scope:
        :param construct_id:
        :param env: The AWS CDK Environment class which provides AWS
            Account ID and AWS Region.
        :param props:
        :param kwargs:
        """
        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        PipelinePluginsStack(
            self,
            construct_id="pipeline-plugins-stack",
            env=env,
            props=props,
        )

        if config_vars.plugins.pipeline_trigger:
            PipelineTriggerStack(
                self,
                construct_id="pipeline-trigger-stack",
                env=env,
                props=props,
            )
