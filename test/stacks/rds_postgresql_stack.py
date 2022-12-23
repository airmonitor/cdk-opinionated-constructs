# -*- coding: utf-8 -*-
"""Example code for Application Load Balancer cdk stack."""
from aws_cdk import Stack
from constructs import Construct
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_kms as kms
import aws_cdk.aws_rds as rds
from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks
import aws_cdk.aws_secretsmanager as secretsmanager
from cdk_opinionated_constructs.rds_instance import RDSInstance


class TestRDSPostgreSQLStack(Stack):
    """Test generated RDS PostgreSQL stack."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "shared_kms_key", enable_key_rotation=True)

        private_subnet = ec2.SubnetConfiguration(
            name="private_with_nat", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=25
        )
        vpc = ec2.Vpc(
            self,
            id="vpc",
            nat_gateways=0,
            subnet_configuration=[private_subnet],
        )

        security_group = ec2.SecurityGroup(
            self,
            id="security_group",
            vpc=vpc,
            security_group_name="security_group_name",
            allow_all_outbound=False,
        )

        rds_construct = RDSInstance(self, construct_id="rds_construct")

        database_name = "database-name"

        rds_instance = rds_construct.create_db_instance(
            database_name=database_name,
            engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_8),
            publicly_accessible=False,
            secret=secretsmanager.Secret.from_secret_name_v2(self, id="imported_secret", secret_name="secret-name"),
            security_group=security_group,
            snapshot_identifier="snapshot_identifier",
            stage="prod",
            storage_encryption_key=shared_kms_key,
            vpc=vpc,
        )

        NagSuppressions.add_resource_suppressions(
            rds_instance,
            suppressions=[
                {
                    "id": "AwsSolutions-RDS11",
                    "reason": "Default RDS port is allowed to be used.",
                },
                {
                    "id": "AwsSolutions-RDS2",
                    "reason": "The RDS encryption is managed on a snapshot level from which RDS is restored.",
                },
            ],
        )

        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                {
                    "id": "AwsSolutions-VPC7",
                    "reason": "Test VPC, flow logs logs aren't required here.",
                },
            ],
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
