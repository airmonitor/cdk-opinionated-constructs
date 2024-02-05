import aws_cdk as cdk

from cdk_opinionated_constructs.stacks.integration_tests_stack import IntegrationTestsStack
from constructs import Construct


class IntegrationTestsStage(cdk.Stage):
    """IntegrationTestsStage defines a CDK Stage for integration testing.

    It creates an IntegrationTestsStack, passing along the stage props.

    Parameters:

    - scope: The CDK scope constructing this stage.
    - construct_id: ID for the stage construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stage.
    - **kwargs: Additional stage options.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        IntegrationTestsStack(
            self,
            construct_id="integration-tests-stack",
            env=env,
            props=props,
        )
