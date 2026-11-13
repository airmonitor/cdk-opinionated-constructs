"""Example code for ECR cdk stack."""

from aws_cdk import Stack, Validations
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.ecr import ECR
from constructs import Construct


class TestECRStack(Stack):
    """TestECRStack defines a CDK stack that creates an ECR repository.

    It creates an ECR construct and configures an ECR repository with provided
    settings.

    It validates the stack against the following checklists:

    - AWS Solutions
    - NIST 800-53 R5, PCI DSS 3.2.1, HIPAA Security (applied in the pytest fixture,
      since cdk-nag v3 plugins are app-wide)

    Parameters:

    - scope: The CDK scope constructing this stack.
    - construct_id: ID for the stack construct.
    - **kwargs: Additional stack options.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ecr_construct = ECR(self, id="ecr_construct")
        ecr_construct.repository(repository_name="repository_name", removal_policy="destroy", max_image_age=90)

        # Validate stack against AWS Solutions checklist
        Validations.of(self).add_plugins(AwsSolutionsChecks(self))
