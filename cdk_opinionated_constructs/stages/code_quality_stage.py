"""The CI/CD stage - implements jobs to validate code quality."""

import aws_cdk as cdk

from cdk_opinionated_constructs.stacks.code_quality_stack import CodeQualityStack
from constructs import Construct


class CodeQualityStage(cdk.Stage):
    """The CodeQualityStage class implements the CI/CD code quality validation
    stage.

    Parameters:

    - scope (Construct): The parent construct that this stage will be added to.
    - construct_id (str): The id of this construct.
    - env (cdk.Environment): The CDK environment.
    - props (dict): Properties passed to the CodeQualityStack.
    - **kwargs: Additional keyword arguments passed to the base Stage constructor.

    The stage contains a single CodeQualityStack which implements the code quality jobs.
    """

    def __init__(self, scope: Construct, construct_id: str, env: cdk.Environment, props: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)

        CodeQualityStack(
            self,
            construct_id="codequality-stack",
            env=env,
            props=props,
        )
