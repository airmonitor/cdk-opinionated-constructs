"""Opinionated CDK construct for AWS ECR repository with enabled security."""

from typing import Literal

import aws_cdk as cdk
import aws_cdk.aws_ecr as ecr

from constructs import Construct


class ECR(Construct):
    """Create ECR resource with tag immutability, lifecycle rule and removal
    policy."""

    def __init__(self, scope: Construct, id: str):  # noqa: A002
        super().__init__(scope, id)

    def repository(
        self, repository_name: str, removal_policy: Literal["retain", "destroy"], **kwargs
    ) -> ecr.Repository | ecr.IRepository:
        """Creates an ECR repository with security best practices enabled.

        Parameters:

        - repository_name: Name of the repository to create.
        - removal_policy: Removal policy when stack is deleted - 'retain' or 'destroy'.
        - max_image_age: Optional max image age in days before cleanup.
        - max_image_count: Optional max number of images to retain.

        Returns:
            The created ECR repository object.

        The repository is created with:

        - Immutable image tagging enabled
        - Lifecycle rules based on max_image_age and max_image_count
        - Removal policy when stack is deleted
        """

        removal_policy_map = {"retain": cdk.RemovalPolicy.RETAIN, "destroy": cdk.RemovalPolicy.DESTROY}

        max_image_age = None
        max_image_count = None

        if kwargs.get("max_image_age"):
            max_image_age = cdk.Duration.days(kwargs.get("max_image_age"))

        if kwargs.get("max_image_count"):
            max_image_age = max_image_count

        return ecr.Repository(
            self,
            id=repository_name,
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.IMMUTABLE,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    max_image_count=max_image_count,
                    max_image_age=max_image_age,
                )
            ],
            repository_name=repository_name,
            removal_policy=removal_policy_map[removal_policy],
        )
