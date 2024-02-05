import aws_cdk as cdk

from cdk_opinionated_constructs.stacks.governance_stack import GovernanceStack
from cdk_opinionated_constructs.stacks.notifications_stack import NotificationsStack
from constructs import Construct


class NotificationsStage(cdk.Stage):
    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        """Constructs the Notifications and Governance stacks.

        The NotificationsStack constructs resources related to
        notifications, such as SNS topics and subscriptions.

        The GovernanceStack constructs resources related to governance,
        such as Config and GuardDuty.
        """
        super().__init__(scope, construct_id, env=env, **kwargs)

        NotificationsStack(
            self,
            construct_id="notifications-stack",
            env=env,
            props=props,
        )

        GovernanceStack(
            self,
            construct_id="governance-stack",
            env=env,
            props=props,
        )
