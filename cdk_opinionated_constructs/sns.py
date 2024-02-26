"""Opinionated CDK construct to create an SNS topic.

Security parameters are set by default
"""

import aws_cdk.aws_sns as sns

from aws_cdk import aws_kms as kms
from constructs import Construct


class SNSTopic(Construct):
    """CDK SNS topic construct."""

    def __init__(self, scope: Construct, id: str):  # noqa: A002
        super().__init__(scope, id)

    def create_sns_topic(
        self,
        topic_name: str,
        master_key: kms.IKey | None,
        enforce_ssl: bool = True,  # noqa: FBT001, FBT002
    ) -> sns.Topic | sns.ITopic:
        """Creates an SNS topic with opinionated settings.

        Parameters:

        - topic_name: Name of the SNS topic to create.

        - master_key: Optional KMS key to encrypt the topic.

        - enforce_ssl: Whether to enforce SSL for all communication.

        - kwargs: Other options like events, log prefix.

        Returns: The created SNS topic object.

        It creates the SNS topic with the given name.

        It sets a resource policy to enforce SSL for publication requests.

        This prevents unencrypted publishing over HTTP.
        """

        topic = sns.Topic(self, id=topic_name, topic_name=topic_name, master_key=master_key, enforce_ssl=enforce_ssl)

        return topic
