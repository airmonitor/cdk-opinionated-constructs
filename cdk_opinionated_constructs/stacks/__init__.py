from typing import Union

import aws_cdk.aws_chatbot as chatbot
import aws_cdk.aws_events as events
import aws_cdk.aws_events_targets as events_targets
import aws_cdk.aws_iam as iam
import aws_cdk.aws_sns as sns
import aws_cdk.aws_sns_subscriptions as sns_subscriptions
import aws_cdk.aws_ssm as ssm

from aws_cdk.aws_codepipeline import Pipeline
from aws_cdk.aws_codestarnotifications import DetailType, NotificationRule
from aws_cdk.pipelines import CodePipeline
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
    return len(str(values))


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


def pipeline_notifications(self, sns_topic: sns.ITopic, source: Union[Pipeline, CodePipeline.pipeline]) -> None:
    """Configures notifications for pipeline events.

    Parameters:
        sns_topic (sns.ITopic): The SNS topic to send notifications to
        source (Pipeline | CodePipeline.pipeline): The pipeline source to monitor for events

    Functionality:
        1. Adds a resource policy to the SNS topic allowing CodeStar Notifications service to publish messages
        2. Creates a comprehensive NotificationRule that monitors all major pipeline events including:
           - Pipeline execution events (started, succeeded, failed, canceled, resumed, superseded)
           - Action execution events (started, succeeded, failed, canceled)
           - Stage execution events (started, succeeded, failed, canceled, resumed)
           - Manual approval events (needed, succeeded, failed)
        3. Configures the notification rule to send detailed event information to the specified SNS topic

    Returns:
        None
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
            "codepipeline-pipeline-action-execution-canceled",
            "codepipeline-pipeline-action-execution-failed",
            "codepipeline-pipeline-action-execution-started",
            "codepipeline-pipeline-action-execution-succeeded",
            "codepipeline-pipeline-manual-approval-failed",
            "codepipeline-pipeline-manual-approval-needed",
            "codepipeline-pipeline-manual-approval-succeeded",
            "codepipeline-pipeline-pipeline-execution-canceled",
            "codepipeline-pipeline-pipeline-execution-failed",
            "codepipeline-pipeline-pipeline-execution-resumed",
            "codepipeline-pipeline-pipeline-execution-started",
            "codepipeline-pipeline-pipeline-execution-succeeded",
            "codepipeline-pipeline-pipeline-execution-superseded",
            "codepipeline-pipeline-stage-execution-canceled",
            "codepipeline-pipeline-stage-execution-failed",
            "codepipeline-pipeline-stage-execution-resumed",
            "codepipeline-pipeline-stage-execution-started",
            "codepipeline-pipeline-stage-execution-succeeded",
        ],
        source=source,
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
    self:

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


def _configure_pipeline_email_notifications(sns_topic: sns.Topic) -> None:
    """Configures email notifications for the pipeline SNS topic.

    Parameters:
        sns_topic (sns.Topic): The SNS topic to configure email notifications for

    Functionality:
        Adds a resource policy to the SNS topic that allows AWS CodeStar Notifications service
        to publish messages to the topic. This enables the pipeline to send notifications via
        email when pipeline events occur. The policy grants the codestar-notifications service
        principal permission to perform SNS:Publish actions on the specified topic.
        This is an internal helper function designed to avoid code duplication across
        notification configuration workflows.

    Arguments:
        sns_topic: The SNS topic resource that will receive pipeline notifications

    Returns:
        None
    """

    sns_topic.add_to_resource_policy(
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.ServicePrincipal(service="codestar-notifications.amazonaws.com")],
            actions=["SNS:Publish"],
            resources=[sns_topic.topic_arn],
        )
    )


def _configure_pipeline_slack_notifications(
    scope, notifications_sns_topic: sns.Topic | sns.ITopic, pipeline_vars: PipelineVars
) -> None:
    """Configures Slack notifications for the pipeline.

    Parameters:
        scope: The scope for the chatbot construct
        notifications_sns_topic (sns.Topic | sns.ITopic): The SNS topic to send notifications to
        pipeline_vars (PipelineVars): Pipeline variables containing Slack configuration

    Functionality:
        Creates a Slack channel configuration for pipeline notifications using AWS Chatbot.
        Conditionally sets up the Slack integration only if both slack_workspace_id and
        slack_ci_cd_channel_id are provided in the pipeline variables.
        Links the SNS topic to the Slack channel for receiving notification messages.
        Uses the project name from pipeline_vars as the configuration name.

    Arguments:
        scope: The scope for the chatbot construct
        notifications_sns_topic: The SNS topic to send notifications to
        pipeline_vars: Pipeline variables containing Slack configuration

    Returns:
        None
    """

    if pipeline_vars.slack_workspace_id and pipeline_vars.slack_ci_cd_channel_id:
        chatbot.SlackChannelConfiguration(
            scope,
            "chatbot",
            slack_channel_configuration_name=pipeline_vars.project,
            notification_topics=[notifications_sns_topic],
            slack_workspace_id=pipeline_vars.slack_workspace_id,
            slack_channel_id=pipeline_vars.slack_ci_cd_channel_id,
        )


def _create_ms_teams_chatbot_iam_role(scope) -> iam.Role:
    """Creates an IAM role for MS Teams chatbot integration with necessary permissions.

    Parameters:
        scope: The scope for the IAM role construct

    Functionality:
        Creates an IAM role that can be assumed by AWS Chatbot service
        to send CodePipeline notifications to Microsoft Teams channels.
        Applies ReadOnlyAccess managed policy as a baseline for permissions.
        Explicitly denies sensitive IAM, S3, SSM, STS, KMS and other critical service permissions for security.
        Grants specific CloudWatch permissions for monitoring and metrics access.
        Provides CodePipeline permissions for pipeline state and execution information retrieval.
        Includes CloudWatch Logs permissions for log access and querying capabilities.
        Configures the role with appropriate trust policy for chatbot.amazonaws.com service principal.

    Returns:
        iam.Role: The created IAM role configured for MS Teams chatbot integration with restricted permissions
    """

    ms_teams_chatbot_role = iam.Role(
        scope,
        "ms-teams-chatbot-iam-role",
        assumed_by=iam.ServicePrincipal(service="chatbot.amazonaws.com"),
        description="IAM role for AWS Chatbot to send CodePipeline notifications to MS Teams",
        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess")],
    )

    # Deny sensitive permissions for security
    ms_teams_chatbot_role.add_to_policy(
        iam.PolicyStatement(
            actions=[
                "iam:*",
                "s3:GetBucketPolicy",
                "ssm:*",
                "sts:*",
                "kms:*",
                "cognito-idp:GetSigningCertificate",
                "ec2:GetPasswordData",
                "ecr:GetAuthorizationToken",
                "gamelift:RequestUploadCredentials",
                "gamelift:GetInstanceAccess",
                "lightsail:DownloadDefaultKeyPair",
                "lightsail:GetInstanceAccessDetails",
                "lightsail:GetKeyPair",
                "lightsail:GetKeyPairs",
                "redshift:GetClusterCredentials",
                "storagegateway:DescribeChapCredentials",
            ],
            effect=iam.Effect.DENY,
            resources=["*"],
        ),
    )

    # CloudWatch permissions for monitoring and metrics
    ms_teams_chatbot_role.add_to_policy(
        iam.PolicyStatement(
            actions=["cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*"],
            resources=["*"],
        ),
    )

    # CodePipeline permissions for pipeline operations
    ms_teams_chatbot_role.add_to_policy(
        iam.PolicyStatement(
            actions=[
                "codepipeline:GetPipeline",
                "codepipeline:GetPipelineExecution",
                "codepipeline:GetPipelineState",
                "codepipeline:ListActionExecutions",
                "codepipeline:ListPipelineExecutions",
                "codepipeline:RetryStageExecution",
            ],
            resources=["*"],
        ),
    )

    # Logs permissions for CloudWatch Logs access
    ms_teams_chatbot_role.add_to_policy(
        iam.PolicyStatement(
            actions=[
                "logs:Describe*",
                "logs:Get*",
                "logs:List*",
                "logs:StartQuery",
                "logs:StopQuery",
                "logs:TestMetricFilter",
                "logs:FilterLogEvents",
            ],
            resources=["*"],
        ),
    )

    return ms_teams_chatbot_role


def _configure_pipeline_ms_teams_notifications(
    scope, notifications_sns_topic: sns.Topic | sns.ITopic, pipeline_vars: PipelineVars
) -> None:
    """Configures MS Teams notifications for the pipeline.

    Parameters:
        scope: The scope for the chatbot construct
        notifications_sns_topic (sns.Topic | sns.ITopic): The SNS topic to send notifications to
        pipeline_vars (PipelineVars): Pipeline variables containing MS Teams configuration

    Functionality:
        Creates and configures MS Teams chatbot integration for pipeline notifications.
        Validates that required MS Teams configuration parameters are present before proceeding.
        Creates an IAM role with appropriate permissions for the MS Teams chatbot.
        Sets up a CfnMicrosoftTeamsChannelConfiguration to connect the SNS topic to the specified MS Teams channel.
        This is an internal helper function to encapsulate MS Teams-specific notification logic.

    Arguments:
        scope: The scope for the chatbot construct
        notifications_sns_topic: The SNS topic to send notifications to
        pipeline_vars: Pipeline variables containing MS Teams team ID, channel ID, and tenant ID

    Returns:
        None
    """

    if pipeline_vars.ms_teams_team_id and pipeline_vars.ms_teams_ci_cd_channel_id:
        # Create IAM role for MS Teams chatbot
        ms_teams_role = _create_ms_teams_chatbot_iam_role(scope)

        chatbot.CfnMicrosoftTeamsChannelConfiguration(
            scope,
            "ci-cd-ms-teams-chatbot",
            configuration_name=f"{pipeline_vars.project}-ci-cd",
            iam_role_arn=ms_teams_role.role_arn,
            sns_topic_arns=[notifications_sns_topic.topic_arn],
            team_id=pipeline_vars.ms_teams_team_id,
            teams_channel_id=pipeline_vars.ms_teams_ci_cd_channel_id,
            teams_tenant_id=pipeline_vars.ms_teams_tenant_id,
        )


def create_pipeline_notifications(
    scope,
    notifications_sns_topic: sns.Topic | sns.ITopic,
    pipeline_vars: PipelineVars,
    source: Pipeline | CodePipeline,
    use_chatbot: bool = True,  # noqa: FBT001, FBT002
):
    """Configures notifications for the pipeline.

    Parameters:
        notifications_sns_topic (sns.Topic | sns.ITopic): The SNS topic to send notifications to
        pipeline_vars (PipelineVars): Pipeline variables containing notification configurations
        use_chatbot (bool): Flag to enable/disable chatbot integrations, defaults to True
        source (Pipeline | CodePipeline): The pipeline source to monitor for events

    Functionality:
        Orchestrates the configuration of different notification channels for the pipeline.
        Conditionally sets up email notifications if ci_cd_notification_email is configured.
        Configures pipeline notifications for Slack or MS Teams channels if channel IDs are provided.
        Sets up chatbot integrations for Slack and MS Teams when use_chatbot flag is enabled.
        Each notification type is configured through dedicated helper functions.

    Arguments:
        scope: The scope for child constructs
        notifications_sns_topic: The SNS topic to send notifications to
        pipeline_vars: Pipeline variables containing notification configurations
        use_chatbot: Flag to enable/disable chatbot integrations

    Returns:
        None
    """

    if pipeline_vars.ci_cd_notification_email:
        _configure_pipeline_email_notifications(sns_topic=notifications_sns_topic)
    if pipeline_vars.slack_ci_cd_channel_id or pipeline_vars.ms_teams_ci_cd_channel_id:
        pipeline_notifications(scope, sns_topic=notifications_sns_topic, source=source)

    if use_chatbot:
        _configure_pipeline_slack_notifications(scope, notifications_sns_topic, pipeline_vars)
        _configure_pipeline_ms_teams_notifications(scope, notifications_sns_topic, pipeline_vars)
