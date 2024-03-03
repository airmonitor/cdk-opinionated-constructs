import aws_cdk as cdk

from cdk_opinionated_constructs.stacks.services_tests_stack import ServicesTestsStack
from constructs import Construct


class ServicesTestsStage(cdk.Stage):
    """ServicesTestsStage defines a CDK Stage for infrastructure testing.

    It creates a ServicesTestsStack, passing along the stage props.

    Parameters:

    - scope: The CDK scope constructing this stage.
    - construct_id: ID for the stage construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stage.
    - **kwargs: Additional stage options.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        ServicesTestsStack(
            self,
            construct_id="services-tests-stack",
            env=env,
            props=props,
        )
