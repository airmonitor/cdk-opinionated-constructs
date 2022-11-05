# cdk-opinionated-constructs
CDK constructs with added security configuration

## S3 Bucket example:

```python
from cdk_opinionated_constructs.s3 import S3Bucket

s3_bucket_construct = S3Bucket(self, id="bucket")
shared_s3_bucket = s3_bucket_construct.create_bucket(
    bucket_name="bucket-name",
    kms_key=shared_kms_key,
)
```

## SNS topic example:

```python
from cdk_opinionated_constructs.sns import SNSTopic

sns_construct = SNSTopic(self, id=f"sns_notification_topic_construct")
sns_topic = sns_construct.create_sns_topic(
    topic_name="topic_name",
    master_key=shared_kms_key,
)
sns_construct.create_sns_topic_policy(sns_topic=sns_topic)
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
