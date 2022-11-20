# -*- coding: utf-8 -*-
"""Opinionated CDK construct for AWS ECR repository with enabled security."""

from typing import Literal

from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_ecr as ecr


class ECR(Construct):
    """Create ECR resource with tag immutability, lifecycle rule and removal
    policy."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, id: str):
        """

        :param scope:
        :param id:
        """
        super().__init__(scope, id)

    def repository(
        self, repository_name: str, removal_policy: Literal["retain", "destroy"], **kwargs
    ) -> ecr.Repository:
        """
        Create ecr repository with default lifecycle rule - max image count 10, tag immutability and image scan on push
        :param removal_policy: The type of removal policy to be applied when cloudformation stack will be deleted.
        If "retain" then ECR repository will not be deleted.
        :param repository_name: The name of the repository
        :param kwargs:
            * max_image_age: int - the amount of days  an image can be stored in the repository before it expires.
            * max_image_count: int - the amount of images to be stored, older images will be deleted.
            max_image_age and max_image_count are mutually exclusive
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
