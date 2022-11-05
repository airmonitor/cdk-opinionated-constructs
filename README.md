# cdk-opinionated-constructs
CDK constructs with added security configuration

## S3 Bucket example

```python
from cdk_opinionated_constructs.s3 import S3Bucket

s3_bucket_construct = S3Bucket(self, id="bucket")
shared_s3_bucket = s3_bucket_construct.create_bucket(
    bucket_name="bucket-name",
    kms_key=shared_kms_key,
)
```
