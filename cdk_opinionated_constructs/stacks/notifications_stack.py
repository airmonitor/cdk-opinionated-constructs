import aws_cdk as cdk
import aws_cdk.aws_chatbot as chatbot
import aws_cdk.aws_iam as iam
import aws_cdk.aws_logs as logs
import aws_cdk.aws_sns as sns
import aws_cdk.aws_sns_subscriptions as sns_subscriptions
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars, NotificationVars
from cdk_opinionated_constructs.sns import SNSTopic
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


class NotificationsStack(cdk.Stack):
    """This stack represents the notifications infrastructure for the
    application.

    It creates an SNS topic, configures subscriptions, and sets up
    integrations with Slack and MS Teams for notifications.
    """

    def _create_sns_topic(self, config_vars: ConfigurationVars) -> sns.ITopic:
        """Creates the central SNS topic for notifications."""
        sns_construct = SNSTopic(self, id="topic_construct")
        sns_topic = sns_construct.create_sns_topic(
            topic_name=f"{config_vars.project}-{config_vars.stage}-alarms", master_key=None
        )

        # Grant necessary permissions
        sns_topic.add_to_resource_policy(
            statement=iam.PolicyStatement(
                sid="CloudWatchPolicy",
                actions=["sns:Publish"],
                resources=[sns_topic.topic_arn],
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                effect=iam.Effect.ALLOW,
            ),
        )
        sns_topic.add_to_resource_policy(
            statement=iam.PolicyStatement(
                sid="AWSBudgetsPolicy",
                actions=["sns:Publish"],
                resources=[sns_topic.topic_arn],
                principals=[iam.ServicePrincipal(service="budgets.amazonaws.com")],
                effect=iam.Effect.ALLOW,
            ),
        )
        return sns_topic

    def _add_sns_topic_parameter(self, config_vars: ConfigurationVars):
        """Stores the SNS topic ARN as an SSM parameter for other services to
        use."""
        ssm.StringParameter(
            self,
            id="sns_topic_ssm_param",
            string_value=self._sns_topic.topic_arn,
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/topic/alarm/arn",
        )

    def _add_email_subscriptions(self, props: dict):
        """Adds email subscriptions to the SNS topic based on provided
        configuration."""
        if ci_cd_notification_email := props.get("ci_cd_notification_email"):
            self._sns_topic.add_subscription(
                topic_subscription=sns_subscriptions.EmailSubscription(email_address=ci_cd_notification_email),
            )
        if alarm_emails := props.get("alarm_emails"):
            for email in alarm_emails:
                self._sns_topic.add_subscription(
                    topic_subscription=sns_subscriptions.EmailSubscription(email_address=email),
                )

    def _create_chatbot_iam_role(self) -> iam.Role:
        """Creates an IAM role for chatbot integrations with necessary
        permissions."""
        chatbot_iam_role = iam.Role(
            self,
            id="iam_role_chatbot",
            assumed_by=iam.ServicePrincipal(service="chatbot.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess")],
        )
        chatbot_iam_role.add_to_policy(
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
        chatbot_iam_role.add_to_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*"],
                resources=["*"],
            ),
        )
        chatbot_iam_role.add_to_policy(
            iam.PolicyStatement(
                actions=["codepipeline:RetryStageExecution"],
                resources=["*"],
            ),
        )
        return chatbot_iam_role

    def _add_slack_integration(
        self, config_vars: ConfigurationVars, notifications_vars: NotificationVars, chatbot_iam_role: iam.Role
    ):
        """Configures Slack integration for notifications."""
        chatbot.SlackChannelConfiguration(
            self,
            "chatbot",
            slack_channel_configuration_name=f"{config_vars.project}-{config_vars.stage}",
            notification_topics=[self._sns_topic],  # type: ignore
            slack_workspace_id=notifications_vars.slack_workspace_id,
            slack_channel_id=notifications_vars.slack_channel_id_alarms,
            log_retention=logs.RetentionDays.ONE_DAY,
            logging_level=chatbot.LoggingLevel.ERROR,
            role=chatbot_iam_role,
        )

    def _add_ms_teams_integration(
        self, config_vars: ConfigurationVars, notifications_vars: NotificationVars, chatbot_iam_role: iam.Role
    ):
        """Configures MS Teams integration for notifications."""
        chatbot.CfnMicrosoftTeamsChannelConfiguration(
            self,
            "ms_teams_chatbot",
            configuration_name=f"{config_vars.project}-{config_vars.stage}-ms-teams",
            iam_role_arn=chatbot_iam_role.role_arn,
            team_id=notifications_vars.ms_teams_team_id,
            teams_channel_id=notifications_vars.ms_teams_channel_id_alarms,
            teams_tenant_id=notifications_vars.ms_teams_tenant_id,
            logging_level="ERROR",
            sns_topic_arns=[self._sns_topic.topic_arn],
        )

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)
        props_env = load_properties(stage=config_vars.stage)
        notifications_vars = NotificationVars(**props_env)

        self._sns_topic = self._create_sns_topic(config_vars)
        self._add_sns_topic_parameter(config_vars)
        self._add_email_subscriptions(props)

        if notifications_vars.slack_workspace_id or notifications_vars.ms_teams_team_id:
            chatbot_iam_role = self._create_chatbot_iam_role()
            if notifications_vars.slack_workspace_id and notifications_vars.slack_channel_id_alarms:
                self._add_slack_integration(config_vars, notifications_vars, chatbot_iam_role)
            if notifications_vars.ms_teams_team_id and notifications_vars.ms_teams_channel_id_alarms:
                self._add_ms_teams_integration(config_vars, notifications_vars, chatbot_iam_role)

        # Validate stack against AWS Solutions checklist
        NagSuppressions.add_stack_suppressions(self, self.nag_suppression())
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list[NagPackSuppression]:
        return [
            NagPackSuppression(id="AwsSolutions-SNS2", reason="Notifications stack, doesn't require encryption"),
            NagPackSuppression(id="AwsSolutions-IAM4", reason="Wildcard permissions are used in Deny section"),
            NagPackSuppression(id="AwsSolutions-IAM5", reason="Wildcard permissions are used in Deny section"),
        ]
