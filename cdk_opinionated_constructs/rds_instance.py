"""Opinionated CDK construct to create RDS PostgresSQL Instance with dedicated
S3 bucket for storing access logs.

Security parameters are set by default
"""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_rds as rds
import aws_cdk.aws_secretsmanager as secretsmanager

from constructs import Construct


class RDSInstance(Construct):
    """Create AWS RDS DB Instance."""

    def __init__(self, scope: Construct, construct_id: str):
        super().__init__(scope, construct_id)

    def create_db_instance(
        self,
        database_name: str,
        engine: rds.IInstanceEngine,
        secret: secretsmanager.Secret | secretsmanager.ISecret,
        security_group: ec2.SecurityGroup,
        stage: str,
        subnet_group: rds.SubnetGroup,
        vpc: ec2.Vpc | ec2.IVpc,
        preferred_maintenance_window: str | None = "Sun:04:00-Sun:04:30",
        snapshot_identifier: str | None = None,
        instance_type: ec2.InstanceType = ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),  # noqa: B008
        **kwargs,
    ) -> rds.DatabaseInstance | rds.IDatabaseInstance:
        """Creates an RDS PostgreSQL database instance.

        Parameters:

        - database_name: Name of the database to create.

        - engine: The database engine to use.

        - secret: SecretsManager secret for database credentials.

        - security_group: Security group for instance.

        - stage: The deployment stage (prod/non-prod).

        - subnet_group: Subnet group where instance will be placed.

        - vpc: The VPC for instance.

        - preferred_maintenance_window: When to perform maintenance.

        - snapshot_identifier: Snapshot ID to restore from.

        - instance_type: Instance type to use.

        - kwargs: Other options like an encryption key.

        Returns: The RDS database instance object.

        It enables deletion protection, encryption, and performance insights for production.

        It allows IAM auth, prevents version upgrades, limits storage size.

        It sets backup retention and removal policy based on stage.

        It can restore from a snapshot if snapshot ID is provided.
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
