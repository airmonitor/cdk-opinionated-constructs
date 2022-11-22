# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create SNS topic.

Security parameters are set by default
"""
from constructs import Construct
import aws_cdk.aws_sns as sns
from aws_cdk import aws_kms as kms
from aws_cdk import aws_iam as iam

from typing import Union


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

    def create_sns_topic(self, topic_name: str, master_key: Union[kms.IKey, None]) -> sns.Topic:
        """Create SNS topic with resource policy that enforce encrypted access.

        :param topic_name: The name of SNS topic
        :param master_key: The KMS key to encrypt messages going through sns topic
        :return: The CDK object for SNS topic
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
