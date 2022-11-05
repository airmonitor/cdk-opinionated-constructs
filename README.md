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
