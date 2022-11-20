# -*- coding: utf-8 -*-
"""Example code for ECR cdk stack."""
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.ecr import ECR
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NIST80053R5Checks, PCIDSS321Checks, HIPAASecurityChecks


class TestECRStack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ecr_construct = ECR(self, id="ecr_construct")
        ecr_construct.repository(repository_name="repository_name", removal_policy="destroy", max_image_age=90)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))
