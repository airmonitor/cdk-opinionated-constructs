"""Opinionated CDK construct to create an SNS topic.

Security parameters are set by default
"""
import aws_cdk.aws_sns as sns

from aws_cdk import aws_iam as iam, aws_kms as kms
from constructs import Construct


class SNSTopic(Construct):
    """CDK SNS topic construct."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, id: str):
        """

        :param scope:
        :param id:
        """
        super().__init__(scope, id)

    def create_sns_topic(self, topic_name: str, master_key: kms.IKey | None) -> sns.Topic | sns.ITopic:
        """Create an SNS topic with resource policy that enforces encrypted
        access.

        :param topic_name: The name of SNS is topic
        :param master_key: The KMS key to encrypted messages going
            through sns topic
        :return: The CDK object for an SNS topic
        """
        topic = sns.Topic(self, id=topic_name, topic_name=topic_name, master_key=master_key)
        topic.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowPublishThroughSSLOnly",
                actions=["sns:Publish"],
                effect=iam.Effect.DENY,
                resources=[topic.topic_arn],
                conditions={
                    "Bool": {"aws:SecureTransport": "false"},
                },
                principals=[iam.AnyPrincipal()],
            )
        )
        return topic
