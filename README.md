[![auto-merge](https://github.com/airmonitor/cdk-opinionated-constructs/actions/workflows/auto_merge.yml/badge.svg)](https://github.com/airmonitor/cdk-opinionated-constructs/actions/workflows/auto_merge.yml)
[![tests](https://github.com/airmonitor/cdk-opinionated-constructs/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/airmonitor/cdk-opinionated-constructs/actions/workflows/tests.yml)

# cdk-opinionated-constructs
CDK constructs with added security configuration

## S3 Bucket example:
```python
"""Test S3 construct against cdk-nag."""

import aws_cdk.aws_kms as kms
import aws_cdk.aws_s3 as s3
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.s3 import S3Bucket


class TestS3Stack(Stack):
    """Test generated s3 bucket against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

        s3_bucket_construct = S3Bucket(self, id="bucket")
        access_logs_bucket = s3_bucket_construct.create_bucket(
            bucket_name="access-logs-bucket", encryption=s3.BucketEncryption.S3_MANAGED
        )

        NagSuppressions.add_resource_suppressions(
            access_logs_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "This is the access logs bucket, "
                    "it doesn't require another resource for storing access logs from it",
                },
            ],
        )

        s3_bucket_construct.create_bucket(
            bucket_name="test-s3-bucket",
            kms_key=shared_kms_key,
            encryption=s3.BucketEncryption.KMS,
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="test-s3-bucket",
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
```
## SNS topic example:

```python
"""Test SNS construct against cdk-nag."""

import aws_cdk.aws_kms as kms
from aws_cdk import Aspects, Stack
from cdk_nag import (
    AwsSolutionsChecks,
    HIPAASecurityChecks,
    NIST80053R5Checks,
    PCIDSS321Checks,
)
from constructs import Construct

from cdk_opinionated_constructs.sns import SNSTopic


class TestSNSStack(Stack):
    """Test generated AWS SNS topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="topic")
        sns_construct.create_sns_topic(topic_name="topic", master_key=shared_kms_key)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))
```
## AWS Lambda example:

```python
"""Test AWS Lambda function construct.."""

import aws_cdk.aws_lambda as lmb
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.lmb import AWSPythonLambdaFunction


class TestAWSPythonLambdaFunctionStack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(
        self, scope: Construct, construct_id: str, env, props, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lmb_construct = AWSPythonLambdaFunction(self, id="lmb_construct")
        lmb_signing = lmb_construct.signing_config(
            signing_profile_name="signing_profile_name"
        )
        lmb_construct.create_lambda_function(
            code_path=f'{props["service_name"]}',
            env=env,
            function_name=props["service_name"],
            timeout=6,
            layers=[
                lmb.LayerVersion.from_layer_version_arn(
                    self,
                    id="aws_lambda_powertools_layer",
                    layer_version_arn="arn:aws:lambda:eu-west-1:123456789012:layer:aws-lambda-powertools-python-layer:1",
                )
            ],
            env_variables={
                "POWERTOOLS_SERVICE_NAME": props["service_name"],
                "LOG_LEVEL": "DEBUG",
            },
            reserved_concurrent_executions=1,
            signing_config=lmb_signing,
        )

        # Validate stack against AWS Solutions checklist
        nag_suppression_rule_list = self.nag_suppression()
        NagSuppressions.add_stack_suppressions(self, nag_suppression_rule_list)
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            {
                "id": "AwsSolutions-IAM4",
                "reason": "Using managed policies is allowed",
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "There isn't a way to tailor IAM policy using more restrictive permissions for "
                "used API calls logs:CreateLogGroup, xray:PutTelemetryRecords, xray:PutTraceSegments",
            },
        ]
```
## AWS Lambda monitoring example:

```python
"""Test AWS Lambda function construct."""

import aws_cdk.aws_kms as kms
import aws_cdk.aws_lambda as lmb
import cdk_monitoring_constructs as cdk_monitoring
from aws_cdk import Duration, Stack

from cdk_opinionated_constructs.sns import SNSTopic


class TestAWSPythonLambdaFunctionStackMonitoring(Stack):
    """Create monitoring resources for PRS.

    This includes:
    * AWS CW Dashboard
    * Metrics
    * Alarms
    * Subscription to an SNS topic
    * similar
    """

    # pylint: disable=W0613
    def __init__(self, scope, name, env, props):
        super().__init__(scope, name)
        lmb_function: lmb.Function = props["lmb_function"]

        kms_key = kms.Key(self, id="kms_key", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="alarm_topic")
        alarm_topic = sns_construct.create_sns_topic(
            topic_name="alarm_topic", master_key=kms_key
        )

        documentation = "https://https://github.com/airmonitor/cdk-opinionated-constructs/blob/main/README.md"

        monitoring = cdk_monitoring.MonitoringFacade(
            self,
            id="monitoring_facade",
            alarm_factory_defaults=cdk_monitoring.AlarmFactoryDefaults(
                action=cdk_monitoring.SnsAlarmActionStrategy(
                    on_alarm_topic=alarm_topic
                ),
                alarm_name_prefix=f'{props["service_name"]}',
                actions_enabled=True,
            ),
        )

        monitoring.add_large_header("Lambda").monitor_lambda_function(
            lambda_function=lmb_function,
            lambda_insights_enabled=True,
            rate_computation_method=cdk_monitoring.RateComputationMethod.PER_SECOND,
            add_concurrent_executions_count_alarm={
                "Critical": cdk_monitoring.RunningTaskCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    fill_alarm_range=True,
                    period=Duration.seconds(10),
                    max_running_tasks=190,
                ),
                "Warning": cdk_monitoring.RunningTaskCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    fill_alarm_range=True,
                    period=Duration.seconds(10),
                    max_running_tasks=180,
                ),
            },
            add_fault_count_alarm={
                "Critical": cdk_monitoring.ErrorCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_error_count=1,
                )
            },
            add_throttles_count_alarm={
                "Critical": cdk_monitoring.ErrorCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_error_count=1,
                )
            },
            add_latency_p99_alarm={
                "Critical": cdk_monitoring.LatencyThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_latency=Duration.seconds(
                        round(lmb_function.timeout.to_seconds() * 0.99)
                    ),
                )
            },
        )
```
## AWS Lambda Docker example:
```python
"""Test AWS Lambda docker function construct."""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_ecr as ecr
import aws_cdk.aws_lambda as lmb
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.lmb import AWSDockerLambdaFunction


class TestAWSPythonLambdaFunctionStack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(
        self, scope: Construct, construct_id: str, env, props, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(self, id="vpc")
        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                {
                    "id": "AwsSolutions-VPC7",
                    "reason": "Test VPC, flow logs logs aren't required here.",
                },
            ],
        )

        ecr_repository = ecr.Repository(
            self,
            id="ecr_repository",
            auto_delete_images=True,
            encryption=ecr.RepositoryEncryption.AES_256,  # type: ignore
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.IMMUTABLE,
            repository_name="test_ecr_repository",
        )

        lmb_construct = AWSDockerLambdaFunction(self, id="lmb_construct")
        lmb_function = lmb_construct.create_lambda_function(
            code=lmb.DockerImageCode.from_ecr(
                repository=ecr_repository,
                tag="0",
            ),
            env=env,
            ephemeral_storage_size=cdk.Size.gibibytes(amount=10),
            function_name=props["service_name"],
            timeout=60,
            memory_size=512,
            env_variables={
                "POWERTOOLS_SERVICE_NAME": props["service_name"],
                "LOG_LEVEL": "DEBUG",
            },
            reserved_concurrent_executions=1,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        self.output_props = props.copy()
        self.output_props["lmb_function"] = lmb_function

        # Validate stack against AWS Solutions checklist
        nag_suppression_rule_list = self.nag_suppression()
        NagSuppressions.add_stack_suppressions(self, nag_suppression_rule_list)
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            {
                "id": "AwsSolutions-IAM4",
                "reason": "Using managed policies is allowed",
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "There isn't a way to tailor IAM policy using more restrictive permissions for "
                "used API calls logs:CreateLogGroup, xray:PutTelemetryRecords, xray:PutTraceSegments",
            },
        ]

    @property
    def outputs(self):
        """Update props dictionary.

        :return: Updated props dict
        """
        return self.output_props
```
## WAFv2 example

```python
"""Test AWS WAFv2 construct against cdk-nag."""

import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.alb import ApplicationLoadBalancer
from cdk_opinionated_constructs.wafv2 import WAFv2


class TestWAFv2Stack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")

        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                {
                    "id": "AwsSolutions-VPC7",
                    "reason": "Test VPC, flow logs logs aren't required here.",
                },
            ],
        )

        alb_construct = ApplicationLoadBalancer(self, construct_id="alb_construct")

        alb_name = "alb"
        alb = albv2.ApplicationLoadBalancer(
            self,
            id=f"{alb_name}_load_balancer",
            internet_facing=True,
            load_balancer_name=alb_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", expiration_days=7
        )

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        wafv2_construct = WAFv2(self, construct_id="wafv2_construct")

        wafv2_acl = wafv2_construct.web_acl(
            name="wafv2",
            rate_value=500,
            aws_common_rule=True,
            aws_common_rule_ignore_list=[
                "SizeRestrictions_BODY",
            ],
            aws_sqli_rule=True,
            aws_anony_list=True,
            aws_bad_inputs_rule=True,
            aws_account_takeover_prevention={
                "login_path": "/portal/login",
                "payload_type": "FORM_ENCODED",
                "password_field": "data[AuthUser][password]",
                "username_field": "data[AuthUser][userId]",
            },
        )

        wafv2_construct.web_acl_log(
            log_group_name="aws-waf-logs-wafv2", web_acl_arn=wafv2_acl.attr_arn
        )

        wafv2_construct.web_acl_association(
            resource_arn=alb.load_balancer_arn, web_acl_arn=wafv2_acl.attr_arn
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
```
## ApplicationLoadBalancer example

```python
"""Example code for Application Load Balancer cdk stack."""

import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from aws_cdk import Aspects, Duration, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.alb import ApplicationLoadBalancer


class TestALBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        certificate = certificate_manager.Certificate(
            self, "certificate", domain_name="example.com"
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

        alb_construct = ApplicationLoadBalancer(self, construct_id="alb_construct")

        alb_name = "alb"
        alb = albv2.ApplicationLoadBalancer(
            self,
            id=f"{alb_name}_load_balancer",
            internet_facing=True,
            load_balancer_name=alb_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", expiration_days=7
        )

        alb.log_access_logs(bucket=alb_access_logs_bucket)

        alb_construct.add_connections(
            alb=alb,
            certificates=[certificate],
            ports=[
                {
                    "back_end_port": 8088,
                    "front_end_port": 443,
                    "back_end_protocol": albv2.ApplicationProtocol.HTTP,
                    "targets": [],
                    "healthy_http_codes": "200,302",
                    "deregistration_delay": Duration.minutes(1),
                }
            ],
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
```
## ECR example

```python
from aws_cdk import Aspects, Stack
from cdk_nag import (
    AwsSolutionsChecks,
    HIPAASecurityChecks,
    NIST80053R5Checks,
    PCIDSS321Checks,
)
from constructs import Construct

from cdk_opinionated_constructs.ecr import ECR


class TestECRStack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ecr_construct = ECR(self, id="ecr_construct")
        ecr_construct.repository(
            repository_name="repository_name",
            removal_policy="destroy",
            max_image_age=90,
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))
```
## Network Load Balancer example
```python
"""Example code for Network Load Balancer cdk stack."""

import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.nlb import NetworkLoadBalancer


class TestNLBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        NagSuppressions.add_resource_suppressions(
            vpc,
            suppressions=[
                {
                    "id": "AwsSolutions-VPC7",
                    "reason": "Test VPC, flow logs logs aren't required here.",
                },
            ],
        )

        nlb_construct = NetworkLoadBalancer(self, construct_id="nlb_construct")
        nlb_name = "nlb"
        nlb = albv2.NetworkLoadBalancer(
            self,
            id=f"{nlb_name}_load_balancer",
            cross_zone_enabled=False,
            internet_facing=True,
            load_balancer_name=nlb_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        nlb_access_logs_bucket = nlb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", expiration_days=7
        )
        nlb.log_access_logs(bucket=nlb_access_logs_bucket)

        network_load_balancer_construct = NetworkLoadBalancer(
            self, construct_id="network_load_balancer_construct"
        )

        network_load_balancer_construct.add_connections(
            nlb=nlb,
            certificates=[],
            ports=[
                {
                    "front_end_port": 6001,
                    "front_end_protocol": albv2.Protocol.UDP,
                    "targets": [],
                    "back_end_port": 6001,
                    "back_end_protocol": albv2.Protocol.UDP,
                },
            ],
        )
        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
```
## RDS PostgresSQL Instance example
```python
"""Example code for Application Load Balancer cdk stack."""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_kms as kms
import aws_cdk.aws_rds as rds
import aws_cdk.aws_secretsmanager as secretsmanager
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from constructs import Construct

from cdk_opinionated_constructs.rds_instance import RDSInstance


class TestRDSPostgresSQLStack(Stack):
    """Test generated RDS PostgresSQL stack."""

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
            vpc=vpc,
            security_group_name="security_group_name",
            allow_all_outbound=False,
        )

        rds_subnet_group = rds.SubnetGroup(
            self,
            id="rds_subnet_group",
            description="rds_subnet_group",
            vpc=vpc,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            vpc_subnets=ec2.SubnetSelection(
                availability_zones=vpc.availability_zones,
                one_per_az=False,
                subnet_group_name="Private",
            ),
        )

        rds_construct = RDSInstance(self, construct_id="rds_construct")

        database_name = "database-name"

        rds_instance = rds_construct.create_db_instance(
            database_name=database_name,
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_13_8  # type: ignore
            ),
            publicly_accessible=False,
            secret=secretsmanager.Secret.from_secret_name_v2(
                self, id="imported_secret", secret_name="secret-name"
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
```
## RDS MySQL Instance example
```python
"""Example code for Application Load Balancer cdk stack."""

import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_kms as kms
import aws_cdk.aws_rds as rds
import aws_cdk.aws_secretsmanager as secretsmanager
from aws_cdk import Aspects, Stack
from cdk_nag import AwsSolutionsChecks, NagSuppressions
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
            vpc=vpc,
            security_group_name="security_group_name",
            allow_all_outbound=False,
        )

        rds_subnet_group = rds.SubnetGroup(
            self,
            id="rds_subnet_group",
            description="rds_subnet_group",
            vpc=vpc,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            vpc_subnets=ec2.SubnetSelection(
                availability_zones=vpc.availability_zones,
                one_per_az=False,
                subnet_group_name="Private",
            ),
        )

        rds_construct = RDSInstance(self, construct_id="rds_construct")

        database_name = "database-name"

        rds_instance = rds_construct.create_db_instance(
            database_name=database_name,
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_31  # type: ignore
            ),
            publicly_accessible=False,
            secret=secretsmanager.Secret.from_secret_name_v2(
                self, id="imported_secret", secret_name="secret-name"
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
```
