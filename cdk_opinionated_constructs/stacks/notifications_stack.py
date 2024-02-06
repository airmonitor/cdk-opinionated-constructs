import aws_cdk as cdk
import aws_cdk.aws_chatbot as chatbot
import aws_cdk.aws_iam as iam
import aws_cdk.aws_logs as logs
import aws_cdk.aws_sns_subscriptions as sns_subscriptions
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars, NotificationVars
from cdk_opinionated_constructs.sns import SNSTopic
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


class NotificationsStack(cdk.Stack):
    """Service stack.

    Create notifications cloudformation stack.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        """Initializes the NotificationsStack construct.

        Parameters:
        - scope (Construct): The parent construct.
        - construct_id (str): The construct ID.
        - env (cdk.Environment): The CDK environment.
        - props (dict): Stack configuration properties.
        - **kwargs: Additional keyword arguments passed to the Stack constructor.

        The constructor does the following:

        1. Call the parent Stack constructor.

        2. Loads configuration variables from YAML files.

        3. Create a NotificationVars object from props.

        4. Creates an SNS topic for alarms using the SNSTopic construct.

        5. Grants CloudWatch permissions to publish to the SNS topic.

        6. Creates an SSM parameter to store the SNS topic ARN.

        7. Subscribe an email address to the SNS topic.

        8. Conditionally create a Chatbot Slack channel subscription if Slack credentials are provided.

        9. Adds CFN-NAG suppression.

        10. Validates the stack against the AWS Solutions checklist using Aspects.
        """

        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        props_env = load_properties(stage=config_vars.stage)

        notifications_vars = NotificationVars(**props_env)

        sns_construct = SNSTopic(self, id="topic_construct")
        sns_topic = sns_construct.create_sns_topic(
            topic_name=f"{config_vars.project}-{config_vars.stage}-alarms",
            master_key=None,
        )

        # grant cloudwatch permissions to publish to the topic
        sns_topic.add_to_resource_policy(
            statement=iam.PolicyStatement(
                sid="CloudWatchPolicy",
                actions=["sns:Publish"],
                resources=[sns_topic.topic_arn],
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                effect=iam.Effect.ALLOW,
            ),
        )

        # grant aws budgets permissions to publish to the topic
        sns_topic.add_to_resource_policy(
            statement=iam.PolicyStatement(
                sid="AWSBudgetsPolicy",
                actions=["sns:Publish"],
                resources=[sns_topic.topic_arn],
                principals=[iam.ServicePrincipal(service="budgets.amazonaws.com")],
                effect=iam.Effect.ALLOW,
            ),
        )

        ssm.StringParameter(
            self,
            id="sns_topic_ssm_param",
            string_value=sns_topic.topic_arn,
            parameter_name=f"/{config_vars.project}/{config_vars.stage}/topic/alarm/arn",
        )

        sns_topic.add_subscription(
            topic_subscription=sns_subscriptions.EmailSubscription(email_address=props["ci_cd_notification_email"]),
        )

        if notifications_vars.slack_workspace_id and notifications_vars.slack_channel_id_alarms:
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

            chatbot.SlackChannelConfiguration(
                self,
                "chatbot",
                slack_channel_configuration_name=f"{config_vars.project}-{config_vars.stage}",
                notification_topics=[sns_topic],  # type: ignore
                slack_workspace_id=notifications_vars.slack_workspace_id,
                slack_channel_id=notifications_vars.slack_channel_id_alarms,
                log_retention=logs.RetentionDays.ONE_DAY,
                logging_level=chatbot.LoggingLevel.ERROR,
                role=chatbot_iam_role,
            )

        # Validate stack against AWS Solutions checklist
        NagSuppressions.add_stack_suppressions(self, self.nag_suppression())
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            NagPackSuppression(id="AwsSolutions-SNS2", reason="Notifications stack, doesn't require encryption"),
            NagPackSuppression(id="AwsSolutions-IAM4", reason="Wildcard permissions are used in Deny section"),
            NagPackSuppression(id="AwsSolutions-IAM5", reason="Wildcard permissions are used in Deny section"),
        ]
