# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create RDS PostgreSQL Instance with dedicated
S3 bucket for storing access logs.

Security parameters are set by default
"""
from typing import Union
from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_secretsmanager as secretsmanager
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_rds as rds


class RDSInstance(Construct):
    """Create AWS RDS  DB Instance."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, construct_id: str):
        """

        :param scope:
        :param construct_id:
        """
        super().__init__(scope, construct_id)

    def create_db_instance(
        self,
        database_name: str,
        engine: rds.IInstanceEngine,
        secret: Union[secretsmanager.Secret, secretsmanager.ISecret],
        security_group: ec2.SecurityGroup,
        stage: str,
        subnet_group: rds.SubnetGroup,
        vpc: Union[ec2.Vpc, ec2.IVpc],
        preferred_maintenance_window: Union[str, None] = "Sun:04:00-Sun:04:30",
        snapshot_identifier: Union[str, None] = None,
        instance_type: ec2.InstanceType = ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
        **kwargs,
    ) -> rds.DatabaseInstance:
        """Create Aurora RDS with PostgresSQL compatibility.

        :param subnet_group: The RDS subnet group
        :param instance_type: Type of RDS instance
        :param engine: Database engine version
        :param snapshot_identifier: The name of RDS snapshot to be used to create RDS instance from it.
        :param preferred_maintenance_window: The RDS preferred maintenance window
        :param secret: The existing secret in the AWS Secrets Manager
        :param database_name: The name of the database
        :param security_group: The AWS CDK EC2 security group
        :param stage: Stage name
        It contains configuration details about AWS account and resources
        :param vpc: The AWS CDK VPC object in which the Security Group will be created
        :return: The AWS CDK Serverless Cluster object
        """

        return (
            rds.DatabaseInstanceFromSnapshot(
                self,
                "rds-from-snapshot-postgresql",
                allocated_storage=100,
                allow_major_version_upgrade=False,
                backup_retention=cdk.Duration.days(5),
                copy_tags_to_snapshot=True,
                credentials=rds.SnapshotCredentials.from_secret(secret=secret),
                delete_automated_backups=True,
                deletion_protection=stage == "prod",
                enable_performance_insights=True,
                engine=engine,
                iam_authentication=True,
                instance_type=instance_type,
                max_allocated_storage=200,
                multi_az=True,
                preferred_maintenance_window=preferred_maintenance_window,
                publicly_accessible=kwargs.get("publicly_accessible"),
                removal_policy=cdk.RemovalPolicy.DESTROY if stage != "prod" else cdk.RemovalPolicy.RETAIN,
                security_groups=[security_group],
                snapshot_identifier=snapshot_identifier,
                vpc=vpc,
                subnet_group=subnet_group,
            )
            if snapshot_identifier
            else rds.DatabaseInstance(
                self,
                "rds-postgresql",
                allocated_storage=100,
                allow_major_version_upgrade=False,
                backup_retention=cdk.Duration.days(5),
                copy_tags_to_snapshot=True,
                credentials=rds.Credentials.from_secret(secret=secret, username="postgres"),
                database_name=database_name,
                delete_automated_backups=True,
                deletion_protection=stage == "prod",
                enable_performance_insights=True,
                engine=engine,
                iam_authentication=True,
                instance_type=instance_type,
                max_allocated_storage=200,
                multi_az=True,
                preferred_maintenance_window=preferred_maintenance_window,
                publicly_accessible=kwargs.get("publicly_accessible"),
                removal_policy=cdk.RemovalPolicy.RETAIN if stage == "prod" else cdk.RemovalPolicy.DESTROY,
                security_groups=[security_group],
                storage_encrypted=True,
                storage_encryption_key=kwargs.get("storage_encryption_key"),
                subnet_group=subnet_group,
                vpc=vpc,
            )
        )
