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
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        shared_kms_key = kms.Key(self, "SharedKmsKey", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="topic")
        sns_topic = sns_construct.create_sns_topic(topic_name="topic", master_key=shared_kms_key)
        sns_construct.create_sns_topic_policy(sns_topic)

        # Validate stack against AWS Solutions checklist
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))
        Aspects.of(self).add(NIST80053R5Checks(log_ignores=True))
        Aspects.of(self).add(PCIDSS321Checks(log_ignores=True))
        Aspects.of(self).add(HIPAASecurityChecks(log_ignores=True))

```
## AWS Lambda example:

```python
from cdk_opinionated_constructs.lmb import AWSLambdaFunction

aws_lambda_construct = AWSLambdaFunction(self, id=f"aws_lambda_construct")
aws_lambda_function = aws_lambda_construct.create_lambda_function(
    code_path="service/first_function",
    env=env,
    function_name="first_function",
    props=props,
    timeout=10,
    layer=lmb.LayerVersion.from_layer_version_arn(
        self,
        id=f"first_function_lambda_layer",
        layer_version_arn="arn:aws:lambda:eu-west-1:11223344:layer:aws-lambda-powertools-python-layer:1",
    ),
    env_variables={
        "POWERTOOLS_SERVICE_NAME": "service/first_function",
        "LOG_LEVEL": "DEBUG",
    },
    reserved_concurrent_executions=1,
)
```
