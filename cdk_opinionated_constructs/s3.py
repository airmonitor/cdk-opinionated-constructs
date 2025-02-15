"""Opinionated CDK construct to create S3 bucket.

Security parameters are set by default
"""

import aws_cdk as cdk
import aws_cdk.aws_kms as kms
import aws_cdk.aws_s3 as s3

from constructs import Construct


class S3Bucket(Construct):
    """Create opinionated S3 bucket including restricted public access,
    enforced encryption in transit as well as in rest, versioning and lifecycle
    rules."""

    def __init__(self, scope: Construct, id: str):  # noqa: A002
        super().__init__(scope, id)

    def create_bucket(
        self,
        bucket_name: str,
        encryption: s3.BucketEncryption,
        kms_key: kms.IKey | None = None,
        server_access_logs_bucket: s3.IBucket | None = None,
        enforce_ssl: bool = True,  # noqa: FBT001, FBT002
        **kwargs,
    ) -> s3.Bucket | s3.IBucket:
        """Creates an S3 bucket with opinionated security settings.

        Parameters:

        - bucket_name: Name of the S3 bucket.

        - encryption: Encryption type like S3_MANAGED.

        - kms_key: Optional KMS key for encryption.

        - server_access_logs_bucket: Bucket to store access logs.

        - enforce_ssl: Enforce SSL for all communications.

        - kwargs: Other options like events, log prefix.

        Returns: The S3 Bucket object.

        It sets:

        - Auto object delete on bucket removal
        - Blocks all public access
        - Enables default encryption
        - Versioning and lifecycle rules
        - Secure SSL policy

        It can send logs to another bucket and integrate with EventBridge.
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
            enforce_ssl=bool(enforce_ssl),
            minimum_tls_version=1.2,
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

        return bucket

    def create_cloudfront_bucket(
        self,
        bucket_name: str,
        encryption: s3.BucketEncryption,
        kms_key: kms.IKey | None = None,
        server_access_logs_bucket: s3.IBucket | None = None,
        enforce_ssl: bool = True,  # noqa: FBT001, FBT002
        **kwargs,
    ) -> s3.Bucket | s3.IBucket:
        """
        Parameters:
            bucket_name (str): Name of the S3 bucket to be created
            encryption (s3.BucketEncryption): Type of encryption to be used for the bucket
            kms_key (kms.IKey | None): Optional KMS key for bucket encryption
            server_access_logs_bucket (s3.IBucket | None): Optional bucket for storing server access logs
            enforce_ssl (bool): Flag to enforce SSL for all bucket communications, defaults to True
            **kwargs: Additional keyword arguments for bucket configuration

        Functionality:
            Creates an S3 bucket specifically configured for CloudFront usage with enhanced security settings:
            - Sets object ownership to OBJECT_WRITER
            - Enables automatic object deletion on bucket removal
            - Blocks all public access
            - Configures encryption settings
            - Enforces SSL and TLS 1.2
            - Sets up lifecycle rules for version management
            - Configures server access logging
            - Enables versioning
            - Supports EventBridge integration through kwargs

        Returns:
            s3.Bucket | s3.IBucket: The created S3 bucket instance
        """

        bucket = s3.Bucket(
            self,
            id=bucket_name,
            object_ownership=s3.ObjectOwnership.OBJECT_WRITER,
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
            enforce_ssl=bool(enforce_ssl),
            minimum_tls_version=1.2,
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

        return bucket
