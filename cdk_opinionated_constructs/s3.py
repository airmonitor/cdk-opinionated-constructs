"""Opinionated CDK construct to create S3 bucket.

Security parameters are set by default
"""
from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_kms as kms
import aws_cdk.aws_iam as iam


class S3Bucket(Construct):
    """Create opinionated S3 bucket including restricted public access,
    enforced encryption in transit as well as in rest, versioning and lifecycle
    rules."""

    # pylint: disable=W0235
    # pylint: disable=W0622
    def __init__(self, scope: Construct, id: str):
        """

        :param scope:
        :param id:
        """
        super().__init__(scope, id)

    def create_bucket(
        self,
        bucket_name: str,
        encryption: s3.BucketEncryption,
        kms_key: kms.IKey | None = None,
        server_access_logs_bucket: s3.IBucket | None = None,
        enforce_ssl: bool = True,
        **kwargs,
    ) -> s3.Bucket:
        """Create S3 bucket.

        :param encryption: The type of encryption.
        :param enforce_ssl: Bool value if SSL should be enforced.
        :param kms_key: The kms to be used.
        :param bucket_name: The name of S3 bucket.
        :param server_access_logs_bucket: The CDK object for S3 bucket.
        :param kwargs:
         Event_bridge_enabled: bool - set to True if s3 events should be sent to event bridge
         server_access_logs_prefix: str - in which prefix logs should be stored
        :return: The S3 bucket CDK object
        """

        bucket = s3.Bucket(
            self,
            id=bucket_name,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
            bucket_name=bucket_name,
            encryption=encryption,
            encryption_key=kms_key,
            event_bridge_enabled=bool(kwargs.get("event_bridge_enabled")),
            lifecycle_rules=[
                s3.LifecycleRule(
                    enabled=True,
                    noncurrent_version_expiration=cdk.Duration.days(amount=1),
                ),
                s3.LifecycleRule(
                    enabled=True,
                    expired_object_delete_marker=True,
                    abort_incomplete_multipart_upload_after=cdk.Duration.days(7),
                ),
            ],
            public_read_access=False,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            server_access_logs_prefix=kwargs.get("server_access_logs_prefix"),
            server_access_logs_bucket=server_access_logs_bucket,
            versioned=True,
        )

        if enforce_ssl:
            bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="EnforceTLSv12orHigher",
                    principals=[iam.AnyPrincipal()],
                    actions=["*"],
                    effect=iam.Effect.DENY,
                    resources=[bucket.bucket_arn, f"{bucket.bucket_arn}/*"],
                    conditions={"Bool": {"aws:SecureTransport": "false"}, "NumericLessThan": {"s3:TlsVersion": 1.2}},
                )
            )

        return bucket
