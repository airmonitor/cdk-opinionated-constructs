"""The CI/CD stage - implements jobs to validate code quality.
"""

import aws_cdk as cdk

from constructs import Construct

from cdk_opinionated_constructs.stacks.infrastructure_tests_stack import InfrastructureTestsStack


class InfrastructureTestsStage(cdk.Stage):
    """Create CI/CD stage with one stack and several jobs to check code quality
    using: SonarQube, pre-commit and ansible-lint.

    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        """Initialize default parameters from AWS CDK and configuration file.

        :param scope:
        :param construct_id:
        :param env: The AWS CDK Environment class which provides AWS
            Account ID and AWS Region.
        :param props:
        :param kwargs:
        """
        super().__init__(scope, construct_id, env=env, **kwargs)

        InfrastructureTestsStack(
            self,
            construct_id="infrastructure-tests-stack",
            env=env,
            props=props,
        )
