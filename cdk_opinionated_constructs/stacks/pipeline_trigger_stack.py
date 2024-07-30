import aws_cdk as cdk
import aws_cdk.aws_codepipeline as pipeline
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as events_targets
import aws_cdk.aws_iam as iam

from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars
from constructs import Construct


class PipelineTriggerStack(cdk.Stack):
    """Constructs a PipelineTriggerStack that creates a CloudWatch Events rule
    to trigger a CodePipeline pipeline execution when specified SSM parameters
    change.

    Parameters
    ----------
    - scope: The parent CDK construct for this stack.
    - construct_id: The ID to use for this stack.
    - env: The CDK environment.
    - props: A dictionary of configuration variables including:
      - config_vars: ConfigurationVars object containing project and stage names.
      - pipeline_vars: PipelineVars object containing plugin configuration.
    - **kwargs: Additional keyword arguments passed to the Stack constructor.

    The stack does the following:

    1. Filters pipeline_vars.plugins.pipeline_trigger_ssm_parameters to get those matching config_vars.stage.

    2. Define an EventPattern to trigger on Create or Update for those SSM parameters.

    3. Create an IAM role with permissions to start the CodePipeline execution.

    4. Creates a CloudWatch Events Rule targeting the CodePipeline, using the created role.

    The result is a Rule that will detect changes to the specified SSM parameters and trigger
    a new execution of the CodePipeline.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        # Filter all ssm parameters that have the name of the stage
        filtered_ssm_parameters: list[str] = list(
            filter(lambda x: config_vars.stage in x, config_vars.plugins.pipeline_trigger_ssm_parameters)  # type: ignore
        )  # type: ignore

        event_pattern = events.EventPattern(
            source=["aws.ssm"],
            detail_type=["Parameter Store Change"],
            detail={"name": filtered_ssm_parameters, "operation": ["Create", "Update"]},
        )

        if filtered_ssm_parameters:
            events_iam_role_policy = iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=["codepipeline:StartPipelineExecution"],
                        resources=[f"arn:aws:codepipeline:{env.region}:{env.account}:{config_vars.project}"],
                    ),
                ]
            )
            events_iam_role = iam.Role(
                self,
                id="events_iam_role",
                role_name=f"{config_vars.project}-{config_vars.stage}-pipeline-trigger",
                assumed_by=iam.ServicePrincipal(service="events.amazonaws.com"),
                inline_policies={"allow_starting_codepipeline": events_iam_role_policy},
            )
            events.Rule(
                self,
                id="rule_start_codepipeline",
                event_pattern=event_pattern,
                targets=[
                    events_targets.CodePipeline(
                        event_role=events_iam_role,
                        pipeline=pipeline.Pipeline.from_pipeline_arn(
                            self,
                            id="imported_codepipeline",
                            pipeline_arn=f"arn:aws:codepipeline:{env.region}:{env.account}:{config_vars.project}",
                        ),
                    )
                ],
            )
