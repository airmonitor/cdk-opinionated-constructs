import aws_cdk as cdk

from cdk_opinionated_constructs.stacks.infrastructure_tests_stack import InfrastructureTestsStack
from constructs import Construct


class InfrastructureTestsStage(cdk.Stage):
    """InfrastructureTestsStage defines a CDK Stage for infrastructure testing.

    It creates an InfrastructureTestsStack, passing along the stage props.

    Parameters:

    - scope: The CDK scope constructing this stage.
    - construct_id: ID for the stage construct.
    - env: The CDK environment.
    - props: Configuration properties passed to the stage.
    - **kwargs: Additional stage options.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        InfrastructureTestsStack(
            self,
            construct_id="infrastructure-tests-stack",
            env=env,
            props=props,
        )
