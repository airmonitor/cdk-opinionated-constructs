"""Example code for ECR cdk stack."""

from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks, NIST80053R5Checks, PCIDSS321Checks
from constructs import Construct

from cdk_opinionated_constructs.ecr import ECR


class TestECRStack(Stack):
    """TestECRStack defines a CDK stack that creates an ECR repository.

    It creates an ECR construct and configures an ECR repository with provided
    settings.

    It validates the stack against the following checklists:

    - AWS Solutions
    - NIST 800-53 R5
    - PCI DSS 3.2.1
    - HIPAA Security

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
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))
