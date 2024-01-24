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
        """Creates an ECR repository with the given name and removal policy.

        Parameters:
        - repository_name (str): The name for the ECR repository.
        - removal_policy (Literal["retain", "destroy"]): The removal policy to use.
        - max_image_age (int, optional): The maximum age in days for images before cleanup.
        - max_image_count (int, optional): The maximum number of images to retain.

        Returns:
        - ecr.Repository | ecr.IRepository: The created ECR repository resource.

        The repository will have encryption, image scanning on push, and immutable
        tagging enabled. A lifecycle rule will be added based on the max_image_age
        and max_image_count if provided.

        The removal_policy will be set to either RETAIN or DESTROY based on the
        removal_policy parameter.
        """

        removal_policy_map = {"retain": cdk.RemovalPolicy.RETAIN, "destroy": cdk.RemovalPolicy.DESTROY}

        lifecycle_rules: None | list = None

        max_image_count = kwargs.get("max_image_count")
        max_image_age = kwargs.get("max_image_age")

        if max_image_age:
            max_image_age = cdk.Duration.days(max_image_age)
            lifecycle_rules = [
                ecr.LifecycleRule(
                    max_image_age=max_image_age,
                )
            ]
        if max_image_count:
            lifecycle_rules = [
                ecr.LifecycleRule(
                    max_image_count=max_image_count,
                )
            ]

        if max_image_age and max_image_count:
            lifecycle_rules = [
                ecr.LifecycleRule(
                    max_image_count=max_image_count,
                ),
                ecr.LifecycleRule(
                    max_image_age=max_image_age,
                ),
            ]
        return ecr.Repository(
            self,
            id=repository_name,
            encryption=ecr.RepositoryEncryption.AES_256,  # type: ignore
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.IMMUTABLE,
            removal_policy=removal_policy_map[removal_policy],
            repository_name=repository_name,
            lifecycle_rules=lifecycle_rules,
        )
