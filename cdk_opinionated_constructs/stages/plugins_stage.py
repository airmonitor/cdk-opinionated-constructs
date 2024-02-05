import aws_cdk as cdk

from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from cdk_opinionated_constructs.stacks.pipeline_plugins_stack import PipelinePluginsStack
from cdk_opinionated_constructs.stacks.pipeline_trigger_stack import PipelineTriggerStack
from constructs import Construct


class PluginsStage(cdk.Stage):
    """PluginsStage defines a CDK Stage for CodePipeline plugins.

    It creates a PipelinePluginsStack to add plugins to the pipeline.

    If pipeline_trigger is enabled in the config, it also creates a
    PipelineTriggerStack to setup a trigger for the pipeline.

    Parameters:

    - scope: The CDK scope constructing this stage.
    - construct_id: ID for the stage construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stage.
    - **kwargs: Additional stage options.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
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
