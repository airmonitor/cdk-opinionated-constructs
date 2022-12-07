# cdk-opinionated-constructs
CDK constructs with added security configuration

## S3 Bucket example:

```python
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.s3 import S3Bucket
import aws_cdk.aws_kms as kms

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestS3Stack(Stack):
    """Test generated s3 bucket against AWS solutions  checks"""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

        s3_bucket_construct = S3Bucket(self, id="bucket")
        access_logs_bucket = s3_bucket_construct.create_bucket(bucket_name="access-logs-bucket", kms_key=shared_kms_key)

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
            server_access_logs_bucket=access_logs_bucket,
            server_access_logs_prefix="test-s3-bucket"
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))


```

## SNS topic example:

```python
# -*- coding: utf-8 -*-
"""Test SNS construct against cdk-nag."""
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.sns import SNSTopic
import aws_cdk.aws_kms as kms

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NIST80053R5Checks, PCIDSS321Checks, HIPAASecurityChecks


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
# -*- coding: utf-8 -*-
"""Test AWS Lambda function construct.."""
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.lmb import AWSPythonLambdaFunction
import aws_cdk.aws_lambda as lmb

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestAWSPythonLambdaFunctionStack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lmb_construct = AWSPythonLambdaFunction(self, id="lmb_construct")
        lmb_signing = lmb_construct.signing_config(signing_profile_name="signing_profile_name")
        lmb_construct.create_lambda_function(
            code_path=f'{props["service_name"]}',
            env=env,
            function_name=props["service_name"],
            timeout=6,
            layer=lmb.LayerVersion.from_layer_version_arn(
                self,
                id="aws_lambda_powertools_layer",
                layer_version_arn="arn:aws:lambda:eu-west-1:123456789012:layer:aws-lambda-powertools-python-layer:1",
            ),
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
# -*- coding: utf-8 -*-
"""Test AWS Lambda function construct."""
from aws_cdk import Stack, Duration
from cdk_opinionated_constructs.sns import SNSTopic

import aws_cdk.aws_lambda as lmb
import aws_cdk.aws_kms as kms
import cdk_monitoring_constructs as cdk_monitoring


class TestAWSPythonLambdaFunctionStackMonitoring(Stack):
    """Create monitoring resources for PRS.

    This includes:
    * AWS CW Dashboard
    * Metrics
    * Alarms
    * Subscription to SNS topic
    * similar
    """

    # pylint: disable=W0613
    def __init__(self, scope, name, env, props):
        super().__init__(scope, name)
        lmb_function: lmb.Function = props["lmb_function"]

        kms_key = kms.Key(self, id="kms_key", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="alarm_topic")
        alarm_topic = sns_construct.create_sns_topic(topic_name="alarm_topic", master_key=kms_key)

        documentation = (
            "https://https://github.com/airmonitor/cdk-opinionated-constructs/blob/main/README.md"
        )

        monitoring = cdk_monitoring.MonitoringFacade(
            self,
            id="monitoring_facade",
            alarm_factory_defaults=cdk_monitoring.AlarmFactoryDefaults(
                action=cdk_monitoring.SnsAlarmActionStrategy(on_alarm_topic=alarm_topic),
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
                    max_latency=Duration.seconds(round(lmb_function.timeout.to_seconds() * 0.99)),
                )
            },
        )


```
## WAFv2 example

```python
# -*- coding: utf-8 -*-
"""Test AWS WAFv2 construct against cdk-nag."""
from aws_cdk import Stack
from constructs import Construct
import aws_cdk.aws_ec2 as ec2
from aws_cdk import aws_kms as kms
from cdk_opinionated_constructs.alb import ApplicationLoadBalancer
from cdk_opinionated_constructs.wafv2 import WAFv2

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestWAFv2Stack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

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

        alb = alb_construct.create_alb(
            load_balancer_name="alb",
            internet_facing=True,
            vpc=vpc,
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", kms_key=shared_kms_key, expiration_days=7
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
            log_group_name="aws-waf-logs-wafv2",
            web_acl_arn=wafv2_acl.attr_arn
        )

        wafv2_construct.web_acl_association(resource_arn=alb.load_balancer_arn, web_acl_arn=wafv2_acl.attr_arn)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

```

## ApplicationLoadBalancer example

```python
# -*- coding: utf-8 -*-
"""Example code for Application Load Balancer cdk stack."""
from aws_cdk import Stack, Duration
from constructs import Construct

from aws_cdk import aws_kms as kms
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_certificatemanager as certificate_manager
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from cdk_opinionated_constructs.alb import ApplicationLoadBalancer

from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


class TestALBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        shared_kms_key = kms.Key(self, "shared_kms_key", enable_key_rotation=True)
        certificate = certificate_manager.Certificate(self, "certificate", domain_name="example.com")

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

        alb = alb_construct.create_alb(
            load_balancer_name="alb",
            internet_facing=True,
            vpc=vpc,
        )

        alb_access_logs_bucket = alb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", kms_key=shared_kms_key, expiration_days=7
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
                    "deregistration_delay": Duration.minutes(1)
                }
            ],
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
```

## ECR example

```python
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.ecr import ECR
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NIST80053R5Checks, PCIDSS321Checks, HIPAASecurityChecks


class TestECRStack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        ecr_construct = ECR(self, id="ecr_construct")
        ecr_construct.repository(
            repository_name="repository_name",
            removal_policy="destroy",
            max_image_age=90
        )

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))

```

## Network Load Balancer example
```python
# -*- coding: utf-8 -*-
"""Example code for Network Load Balancer cdk stack."""
from aws_cdk import Stack
from constructs import Construct

import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_kms as kms
import aws_cdk.aws_elasticloadbalancingv2 as albv2
from cdk_opinionated_constructs.nlb import NetworkLoadBalancer

from cdk_nag import NagSuppressions
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


class TestNLBStack(Stack):
    """Test generated EC2 ALB against AWS recommendations."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(self, id="vpc")
        shared_kms_key = kms.Key(self, "shared_kms_key", enable_key_rotation=True)
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
        nlb = nlb_construct.create_nlb(load_balancer_name="nlb", vpc=vpc)

        nlb_access_logs_bucket = nlb_construct.create_access_logs_bucket(
            bucket_name="bucket-name", kms_key=shared_kms_key, expiration_days=7
        )
        nlb.log_access_logs(bucket=nlb_access_logs_bucket)

        network_load_balancer_construct = NetworkLoadBalancer(self, construct_id="network_load_balancer_construct")

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
