"""Example code for Application Load Balancer cdk stack."""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_kms as kms
import aws_cdk.aws_rds as rds
import aws_cdk.aws_secretsmanager as secretsmanager

from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.rds_instance import RDSInstance


class TestRDSMySQLStack(Stack):
    """Test generated RDS MySQL stack."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "shared_kms_key", enable_key_rotation=True)

        private_subnet = ec2.SubnetConfiguration(
            name="Private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, cidr_mask=25
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
            vpc=vpc,  # type: ignore
            security_group_name="security_group_name",
            allow_all_outbound=False,
        )

        rds_subnet_group = rds.SubnetGroup(
            self,
            id="rds_subnet_group",
            description="rds_subnet_group",
            vpc=vpc,  # type: ignore
            removal_policy=cdk.RemovalPolicy.DESTROY,
            vpc_subnets=ec2.SubnetSelection(
                availability_zones=vpc.availability_zones, one_per_az=False, subnet_group_name="Private"
            ),
        )

        rds_construct = RDSInstance(self, construct_id="rds_construct")

        database_name = "database-name"

        rds_instance = rds_construct.create_db_instance(
            database_name=database_name,
            engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_31),  # type: ignore
            publicly_accessible=False,
            secret=secretsmanager.Secret.from_secret_name_v2(
                self,
                id="imported_secret",
                secret_name="secret-name",  # noqa: S106
            ),
            security_group=security_group,
            snapshot_identifier="snapshot_identifier",
            stage="prod",
            storage_encryption_key=shared_kms_key,
            subnet_group=rds_subnet_group,
            vpc=vpc,
        )

        NagSuppressions.add_resource_suppressions(
            rds_instance,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-RDS2",
                    reason="The RDS encryption is managed on a snapshot level from which RDS is restored.",
                ),
                NagPackSuppression(id="AwsSolutions-RDS11", reason="Default RDS port is allowed to be used."),
            ],
        )

        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                NagPackSuppression(id="AwsSolutions-VPC7", reason="Test VPC, flow logs logs aren't required here.")
            ],
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
