import aws_cdk as cdk

from constructs import Construct

from cdk_opinionated_constructs.stacks.notifications_stack import NotificationsStack


class NotificationsStage(cdk.Stage):
    """NotificationsStage defines a CDK Stage for notifications.

    It creates a NotificationsStack, passing along the stage props.

    Parameters:

    - scope: The CDK scope constructing this stage.
    - construct_id: ID for the stage construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stage.
    - **kwargs: Additional stage options.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        NotificationsStack(
            self,
            construct_id="notifications-stack",
            env=env,
            props=props,
        )
