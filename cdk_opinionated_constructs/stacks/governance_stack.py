import aws_cdk as cdk
import aws_cdk.aws_sns as sns
import aws_cdk.aws_ssm as ssm

from aws_cdk import Aspects
from aws_cdk.aws_budgets import CfnBudget as Budget
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from cdk_opinionated_constructs.schemas.configuration_vars import ConfigurationVars, GovernanceVars
from cdk_opinionated_constructs.utils import load_properties
from constructs import Construct


class GovernanceStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        """Initializes the GovernanceStack.

        This stack is responsible for setting up AWS governance-related resources. It includes:
        - Importing an SNS topic from an ARN stored in SSM Parameter Store.
        - Adding a resource policy to the SNS topic to allow AWS Budgets to publish to it.
        - Suppressing a specific cdk-nag rule for the SNS topic.
        - Creating SNS subscribers for budget alarms with daily and monthly periods.
        - Attaching AWS Solutions checks to the stack for compliance monitoring.

        Args:
            scope (Construct): The parent construct.
            construct_id (str): The construct's unique identifier.
            env: The AWS environment (account/region) where this stack will be deployed.
            props: The properties for configuring the stack.
            **kwargs: Additional keyword arguments.
        """
        super().__init__(scope, construct_id, env=env, **kwargs)
        config_vars = ConfigurationVars(**props)

        props_env = load_properties(stage=config_vars.stage)

        governance_vars = GovernanceVars(**props_env)

        bill_sns_topic = sns.Topic.from_topic_arn(
            self,
            id="imported_sns_topic",
            topic_arn=ssm.StringParameter.value_for_string_parameter(
                self,
                parameter_name=f"/{config_vars.project}/{config_vars.stage}/topic/alarm/arn",
            ),
        )

        NagSuppressions.add_resource_suppressions(
            bill_sns_topic,
            [NagPackSuppression(id="AwsSolutions-SNS2", reason="Notifications stack, doesn't require encryption")],
        )

        bill_sns_subscribers = Budget.SubscriberProperty(address=bill_sns_topic.topic_arn, subscription_type="SNS")

        if governance_vars.budget_limit_monthly and governance_vars.tags.awsApplication:
            monthly_budget_limit = governance_vars.budget_limit_monthly
            self.budget_alarms(
                sns_subscribers=bill_sns_subscribers,
                period="DAILY",
                config_vars=config_vars,
                governance_vars=governance_vars,
                monthly_budget_limit=monthly_budget_limit,
            )
            self.budget_alarms(
                sns_subscribers=bill_sns_subscribers,
                period="MONTHLY",
                config_vars=config_vars,
                governance_vars=governance_vars,
                monthly_budget_limit=monthly_budget_limit,
            )

        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    def budget_alarms(
        self,
        *,
        sns_subscribers: Budget.SubscriberProperty,
        period: str,
        config_vars: ConfigurationVars,
        governance_vars: GovernanceVars,
        monthly_budget_limit: float,
        budget_threshold: int = 95,
    ) -> None:
        """Creates budget alarms for both forecasted and actual spend.

        This method sets up AWS Budgets with alarms for when the forecasted or actual
        costs exceed the specified threshold. It supports different periods (e.g., DAILY, MONTHLY)
        and allows for setting a monthly budget limit. Notifications for breaching the budget
        are sent to the provided SNS subscribers.

        Parameters:
        - sns_subscribers: An instance of Budget.SubscriberProperty to receive notifications.
        - period: The period for the budget, e.g., 'DAILY' or 'MONTHLY'.
        - config_vars: Configuration variables containing project and stage names.
        - governance_vars: Governance-related variables, including tags.
        - monthly_budget_limit: The monthly budget limit in USD.
        - budget_threshold: The threshold percentage for triggering the alarm (default is 95%).

        Returns:
        None
        """
        amount = {
            "DAILY": monthly_budget_limit / 30,
            "MONTHLY": monthly_budget_limit,
        }

        # Forecasted spend, DAILY budget only supports a notification type as ACTUAL
        if period != "DAILY":
            budget_name = f"{config_vars.project}-{config_vars.stage}-forecasted-{period.lower()}"
            Budget(
                self,
                id=budget_name,
                budget=Budget.BudgetDataProperty(
                    budget_limit=Budget.SpendProperty(amount=amount[period], unit="USD"),
                    budget_name=budget_name,
                    budget_type="COST",
                    cost_filters={"TagKeyValue": [f"user:awsApplication${governance_vars.tags.awsApplication}"]},
                    time_unit=period,
                ),
                notifications_with_subscribers=[
                    Budget.NotificationWithSubscribersProperty(
                        notification=Budget.NotificationProperty(
                            threshold=budget_threshold,
                            notification_type="FORECASTED",
                            comparison_operator="GREATER_THAN",
                        ),
                        subscribers=[sns_subscribers],
                    )
                ],
            )
        # Current spend
        budget_name = f"{config_vars.project}-{config_vars.stage}-current-{period.lower()}"
        Budget(
            self,
            id=budget_name,
            budget=Budget.BudgetDataProperty(
                budget_limit=Budget.SpendProperty(amount=amount[period], unit="USD"),
                budget_name=budget_name,
                budget_type="COST",
                cost_filters={"TagKeyValue": [f"user:awsApplication${governance_vars.tags.awsApplication}"]},
                time_unit=period,
            ),
            notifications_with_subscribers=[
                Budget.NotificationWithSubscribersProperty(
                    notification=Budget.NotificationProperty(
                        threshold=budget_threshold, notification_type="ACTUAL", comparison_operator="GREATER_THAN"
                    ),
                    subscribers=[sns_subscribers],
                )
            ],
        )
