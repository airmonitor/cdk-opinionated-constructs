"""Test SNS construct against cdk-nag."""

import aws_cdk.aws_kms as kms

from aws_cdk import Stack, Validations
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.sns import SNSTopic
from constructs import Construct


class TestSNSStack(Stack):
    """Test generated AWS SNS topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="topic")
        sns_construct.create_sns_topic(topic_name="topic", master_key=shared_kms_key)

        # Validate stack against AWS Solutions checklist
        Validations.of(self).add_plugins(AwsSolutionsChecks(self))
