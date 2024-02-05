"""TBD."""

import aws_cdk.aws_chatbot as chatbot
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as events_targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_sns as sns
import aws_cdk.aws_sns_subscriptions as sns_subscriptions
import aws_cdk.aws_ssm as ssm

from aws_cdk.aws_codestarnotifications import DetailType, NotificationRule
from cdk.schemas.configuration_vars import PipelineVars
from cdk_nag import NagPackSuppression
from cdk_opinionated_constructs.utils import apply_tags


def count_characters_number(values: dict[list, dict] | dict[str, str]) -> int:
    """Counts the number of characters in the values.

    Parameters:
        - values: The environment configuration properties.

    Returns:
      - The number of characters.
    """

    total_value_characters = sum(len(str(v)) for v in values.values())
    total_key_characters = sum(len(str(v)) for v in values)
    return total_key_characters + total_value_characters


def reduce_items_number(
    values: dict[list, dict], standard_character_number: int = 4096
) -> dict[list, dict] | dict[str, str]:
    """Counts the number of characters in the values.

    Parameters:
        - values: The environment configuration properties.
        - standard_character_number: The standard number of characters.

    Returns:
      - A Dict with the reduced number of items.
    """

    char_count = count_characters_number(values)

    if char_count <= standard_character_number:
        return values

    return {"dummy": "value"}


def set_ssm_parameter_tier_type(*, character_number: int) -> ssm.ParameterTier:
    """Sets the tier type of the parameter based on the total characters of the
    key and value.

    Parameters:
        - values: The environment configuration properties.

    Returns:
      - The tier type.
    """

    tier_type = ssm.ParameterTier.STANDARD
    if 4069 <= character_number <= 8192:
        tier_type = ssm.ParameterTier.ADVANCED
    return tier_type


def notifications_topic(self, pipeline_vars: PipelineVars) -> sns.Topic:
    """Creates an SNS topic for pipeline notifications.

    Parameters:

    pipeline_vars (PipelineVars): A model containing pipeline configuration values like notification email.

    Functionality:

    1. create an SNS topic called 'notifications_topic' to be used for notifications.

    2. add a subscription to the topic using the email address from pipeline_vars.

    3. add metadata to suppress cdk_nag warnings about encryption.

    4. return the created SNS topic.
    """
    notifications_sns_topic = sns.Topic(self, "notifications_topic", display_name="CodePipeline notifications")
    notifications_sns_topic.add_subscription(
        topic_subscription=sns_subscriptions.EmailSubscription(email_address=pipeline_vars.ci_cd_notification_email)
    )

    # Warning suppression for cdk_nag
    notifications_sns_topic_cfn = notifications_sns_topic.node.default_child
    notifications_sns_topic_cfn.add_metadata(  # type: ignore
        "cdk_nag",
        {
            "rules_to_suppress": [
                NagPackSuppression(id="AwsSolutions-SNS2", reason="Notifications stack, doesn't require encryption"),
            ]
        },
    )
    return notifications_sns_topic


def pipeline_notifications(self, sns_topic: sns.ITopic) -> None:
    """Configures notifications for pipeline events.

    Parameters:

    sns_topic (sns.ITopic): The SNS topic to send notifications to.

    Functionality:

    1. add resource policy to an SNS topic to allow CodeStar Notifications to publish.

    2. create a NotificationRule to send notifications on pipeline events:
       - Pipeline execution failed
       - Action execution failed
       - Stage execution failed
       - Manual approval failed
       - Manual approval needed

    the notification rule will send messages to the provided SNS topic.
    """
    sns_topic.add_to_resource_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.ServicePrincipal(service="codestar-notifications.amazonaws.com")],
            actions=["SNS:Publish"],
            resources=[sns_topic.topic_arn],
        )
    )

    # The CodePipeline notifications available rules:
    # https://docs.aws.amazon.com/dtconsole/latest/userguide/concepts.html#events-ref-repositories
    NotificationRule(
        self,
        "codepipeline_notifications",
        detail_type=DetailType.FULL,
        events=[
            "codepipeline-pipeline-pipeline-execution-failed",
            "codepipeline-pipeline-action-execution-failed",
            "codepipeline-pipeline-stage-execution-failed",
            "codepipeline-pipeline-manual-approval-failed",
            "codepipeline-pipeline-manual-approval-needed",
        ],
        source=self.codepipeline.pipeline,
        targets=[sns_topic],
    )


def pipeline_email_notifications(sns_topic: sns.Topic) -> None:
    """Configures email notifications for the pipeline SNS topic.

    Parameters:

    sns_topic (sns.Topic): The SNS topic to configure notifications for.

    Functionality:

    - adds a resource policy to the SNS topic to allow CodeStar Notifications
    to publish messages to it.

    - this enables email notifications to be sent on pipeline events.
    """
    sns_topic.add_to_resource_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.ServicePrincipal(service="codestar-notifications.amazonaws.com")],
            actions=["SNS:Publish"],
            resources=[sns_topic.topic_arn],
        )
    )


def pipeline_trigger(self, pipeline_vars: PipelineVars, props: dict, schedule: events.Schedule):
    """Creates a scheduled rule to trigger the pipeline.

    Parameters:

    pipeline_vars (PipelineVars): A model containing pipeline configuration values.

    props (dict): A dictionary of configuration properties.

    schedule (events.Schedule): The scheduled interval to trigger the pipeline.

    Functionality:

    1. create a Rule with the provided schedule, enabled status, name, and description.

    2. add the pipeline as a target for the rule.
    this will trigger the pipeline on the schedule.

    3. apply tags to the rule based on props.
    """

    # Auto triggers the pipeline every day to ensure pipeline validation
    trigger = events.Rule(
        self,
        id="daily_release",
        description="Auto trigger the pipeline every day to ensure pipeline validation",
        enabled=True,
        rule_name=f"{pipeline_vars.project}-scheduled-release",
        schedule=schedule,
    )
    trigger.add_target(events_targets.CodePipeline(self.codepipeline.pipeline))  # type: ignore
    apply_tags(props=props, resource=trigger)  # type: ignore


def create_pipeline_notifications(self, notifications_sns_topic: sns.Topic | sns.ITopic, pipeline_vars: PipelineVars):
    """Creates notifications for the pipeline.

    Parameters:

    notifications_sns_topic (sns.Topic | sns.ITopic): The SNS topic to publish notifications to.

    pipeline_vars (PipelineVars): A Pydantic model containing pipeline configuration values like
    notification email, Slack workspace ID, etc.

    Functionality:

    1. if a notification email address is provided in pipeline_vars, enable email notifications by calling
    pipeline_email_notifications()

    2. enable default pipeline notifications by calling pipeline_notifications()

    3. if Slack workspace ID and channel ID are provided in pipeline_vars, enable Slack notifications by
    creating a SlackChannelConfiguration construct
    """

    # Enable SNS notifications if the recipient email address was provided
    if pipeline_vars.ci_cd_notification_email:
        pipeline_email_notifications(sns_topic=notifications_sns_topic)
    if pipeline_vars.slack_ci_cd_channel_id:
        pipeline_notifications(self, sns_topic=notifications_sns_topic)
    # Enable Slack notifications if recipient workspace and channel slack were provided.
    if pipeline_vars.slack_workspace_id and pipeline_vars.slack_ci_cd_channel_id:
        chatbot.SlackChannelConfiguration(
            self,
            "chatbot",
            slack_channel_configuration_name=pipeline_vars.project,
            notification_topics=[notifications_sns_topic],
            slack_workspace_id=pipeline_vars.slack_workspace_id,
            slack_channel_id=pipeline_vars.slack_ci_cd_channel_id,
        )
