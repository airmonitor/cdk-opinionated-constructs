"""OCI image validation CodeBuild project configuration.

This module provides functions to create and configure CodeBuild projects
for validating OCI image signatures using AWS Signer and Notation.
"""

from functools import partial
from itertools import chain
from typing import Any, Literal, TypedDict

import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.libs.pipeline_v2 import (
    install_default,
    install_pre_backed,
    use_fleet,
)
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    assume_role_commands,
    attach_role,
    get_build_image_for_architecture,
    revert_to_original_role_command,
)

# =============================================================================
# Type Definitions - Better Type Safety and Documentation
# =============================================================================


class OciValidationCommands(TypedDict):
    """Type definition for OCI validation command structure."""

    install_commands: list[str]
    commands: list[str]


class ValidationContext(TypedDict):
    """Context for OCI validation command generation."""

    region: str
    account: str
    project: str
    stage_name: str
    bucket_name: str


# =============================================================================
# Pure Helper Functions - High Cohesion, Single Responsibility
# =============================================================================


def _create_signer_install_command(cpu_architecture: Literal["arm64", "amd64"]) -> tuple[str, ...]:
    """Generate AWS Signer Notation CLI installation commands.

    Args:
        cpu_architecture: Target CPU architecture

    Returns:
        Tuple of commands to install AWS Signer Notation CLI
    """
    return (
        f"wget https://d2hvyiie56hcat.cloudfront.net/linux/{cpu_architecture}/installer/rpm/latest/aws-signer-notation-cli_{cpu_architecture}.rpm",
        f"sudo rpm -U aws-signer-notation-cli_{cpu_architecture}.rpm",
        "notation plugin ls",
    )


def _create_oras_install_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    oras_version: str,
) -> tuple[str, ...]:
    """Generate ORAS (OCI Registry As Storage) installation commands.

    Args:
        cpu_architecture: Target CPU architecture
        oras_version: Version of ORAS to install

    Returns:
        Tuple of commands to install ORAS
    """
    return (
        f"curl -LO 'https://github.com/oras-project/oras/releases/download/v{oras_version}/oras_{oras_version}_linux_{cpu_architecture}.tar.gz'",
        "mkdir -p oras-install/",
        f"tar -xzf oras_{oras_version}_linux_{cpu_architecture}.tar.gz -C oras-install/",
        "sudo mv oras-install/oras /usr/local/bin/",
    )


def _create_security_tools_install_commands() -> tuple[str, ...]:
    """Generate Anchore security tools installation commands.

    Returns:
        Tuple of commands to install Grype and Syft
    """
    return (
        "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
    )


def _create_service_readiness_commands() -> tuple[str, ...]:
    """Generate commands to wait for service readiness.

    Returns:
        Tuple of commands for service readiness wait
    """
    return (
        "echo waiting 1 minute for service readiness...",
        "sleep 60",
    )


def _create_ecr_login_commands(ctx: ValidationContext) -> tuple[str, ...]:
    """Generate ECR login commands.

    Args:
        ctx: Validation context containing AWS environment details

    Returns:
        Tuple of ECR login commands
    """
    return (
        f"export PASSWORD=$(aws ecr get-login-password --region {ctx['region']})",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {ctx['region']} | "
        f"docker login --username AWS --password-stdin {ctx['account']}.dkr.ecr.{ctx['region']}.amazonaws.com",
    )


def _create_ssm_parameter_commands(ctx: ValidationContext) -> tuple[str, ...]:
    """Generate commands to retrieve SSM parameters for image validation.

    Args:
        ctx: Validation context containing AWS environment details

    Returns:
        Tuple of SSM parameter retrieval commands
    """
    return (
        f"IMAGE_URI=$(aws ssm get-parameter "
        f'--name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/image/uri" '
        f"--region {ctx['region']} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_URI",
        f"SIGNER_PROFILE_ARN=$(aws ssm get-parameter "
        f'--name "/{ctx["project"]}/{ctx["stage_name"]}/signer/profile/arn" '
        f"--region {ctx['region']} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $SIGNER_PROFILE_ARN",
        f"REPOSITORY_URI=$(aws ssm get-parameter "
        f'--name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/repository/uri" '
        f"--region {ctx['region']} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $REPOSITORY_URI",
        f"IMAGE_TAG=$(aws ssm get-parameter "
        f'--name "/{ctx["project"]}/{ctx["stage_name"]}/ecr/image/tag" '
        f"--region {ctx['region']} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_TAG",
    )


def _create_trust_policy_commands() -> tuple[str, ...]:
    """Generate commands to create and configure the trust policy for signature verification.

    Returns:
        Tuple of trust policy creation commands
    """
    return (
        """cat > policy.json << EOF
        {
          "version": "1.0",
          "trustPolicies": [
            {
              "name": "aws-signer-tp",
              "registryScopes": ["*"],
              "signatureVerification": {
                "level": "strict"
              },
              "trustStores": ["signingAuthority:aws-signer-ts"],
              "trustedIdentities": ["$SIGNER_PROFILE_ARN"]
            }
          ]
        }
        """,
        "TOTAL_LINES=$(wc -l < policy.json)",
        "LINES_TO_KEEP=$((TOTAL_LINES - 4))",
        "head -n $LINES_TO_KEEP policy.json > policy.json.tmp && mv policy.json.tmp policy.json",
        "echo Generated policy.json",
        "cat policy.json",
        "notation policy import policy.json --force",
    )


def _create_signature_verification_commands() -> tuple[str, ...]:
    """Generate commands to verify the container image signature.

    Returns:
        Tuple of signature verification commands
    """
    return ("notation verify $IMAGE_URI",)


def _create_image_definitions_commands(ctx: ValidationContext) -> tuple[str, ...]:
    """Generate commands to create and upload image definitions file.

    Args:
        ctx: Validation context containing bucket name

    Returns:
        Tuple of image definitions creation and upload commands
    """
    return (
        """cat > image_definitions.json << EOF
        [
          {
            "name": "signer-fargate-container",
            "imageUri": "$IMAGE_URI"
          }
        ]
        """,
        "TOTAL_LINES=$(wc -l < image_definitions.json)",
        "LINES_TO_KEEP=$((TOTAL_LINES - 4))",
        "head -n $LINES_TO_KEEP image_definitions.json > image_definitions.json.tmp && "
        "mv image_definitions.json.tmp image_definitions.json",
        revert_to_original_role_command,
        "echo image definitions in artifacts bucket",
        f"aws s3 cp image_definitions.json s3://{ctx['bucket_name']}/image_definitions/image_definitions.json",
    )


# =============================================================================
# Function Composition - Building Complex Commands from Simple Ones
# =============================================================================


def _compose_install_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    oras_version: str,
) -> list[str]:
    """Compose all installation commands using function composition.

    Args:
        cpu_architecture: Target CPU architecture
        oras_version: Version of ORAS to install

    Returns:
        List of all installation commands
    """
    return list(
        chain(
            _create_signer_install_command(cpu_architecture),
            _create_oras_install_commands(cpu_architecture, oras_version),
            _create_security_tools_install_commands(),
        )
    )


def _compose_validation_commands(
    ctx: ValidationContext,
    assume_commands: list[str],
) -> list[str]:
    """Compose all validation commands using function composition.

    This function chains together multiple command generators to create
    the complete validation command sequence.

    Args:
        ctx: Validation context containing AWS environment details
        assume_commands: Commands to assume the required IAM role

    Returns:
        List of all validation commands in execution order
    """
    # Create partial applications for context-dependent functions
    ecr_login = partial(_create_ecr_login_commands, ctx)
    ssm_params = partial(_create_ssm_parameter_commands, ctx)
    image_definitions = partial(_create_image_definitions_commands, ctx)

    # Compose all command sequences
    return list(
        chain(
            assume_commands,
            _create_service_readiness_commands(),
            ecr_login(),
            ssm_params(),
            _create_trust_policy_commands(),
            _create_signature_verification_commands(),
            image_definitions(),
        )
    )


def _create_validation_context(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> ValidationContext:
    """Create an immutable validation context from environment parameters.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        pipeline_artifacts_bucket: S3 bucket for pipeline artifacts

    Returns:
        Immutable context dictionary for validation operations
    """
    return ValidationContext(
        region=str(env.region),
        account=str(env.account),
        project=pipeline_vars.project,
        stage_name=stage_name,
        bucket_name=pipeline_artifacts_bucket.bucket_name,
    )


# =============================================================================
# Public API Functions
# =============================================================================


def create_oci_validation_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    oras_version: str = "1.3.0",
) -> OciValidationCommands:
    """Create OCI image validation installation and execution commands.

    This function generates all necessary commands for installing validation tools
    and verifying OCI image signatures using AWS Signer and Notation.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        cpu_architecture: CPU architecture for installing the appropriate tools
        assume_commands: Commands to assume the required IAM role
        pipeline_artifacts_bucket: S3 bucket to store pipeline artifacts
        oras_version: Version of ORAS to install, defaults to "1.3.0"

    Returns:
        Dictionary containing:
            - "install_commands": List of commands to install required tools
            - "commands": List of commands to execute the validation process
    """
    ctx = _create_validation_context(env, pipeline_vars, stage_name, pipeline_artifacts_bucket)

    return OciValidationCommands(
        install_commands=_compose_install_commands(cpu_architecture, oras_version),
        commands=_compose_validation_commands(ctx, assume_commands),
    )


def attach_oci_validation_iam_role(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
) -> None:
    """Attach the OCI image validation IAM role to a CodeBuild project.

    This role provides the necessary permissions for validating OCI image signatures,
    accessing ECR repositories, and reading SSM parameters.

    Args:
        project: The CodeBuild pipeline project to attach the IAM role to
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
    """
    attach_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="oci-image-validation",
    )


def attach_s3_upload_policy(
    *,
    project: codebuild.PipelineProject,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> None:
    """Attach S3 upload policy to a CodeBuild project.

    Grants permission to upload image definitions to the pipeline artifacts bucket.

    Args:
        project: The CodeBuild pipeline project to attach the policy to
        pipeline_artifacts_bucket: S3 bucket for pipeline artifacts
    """
    project.add_to_role_policy(
        statement=iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{pipeline_artifacts_bucket.bucket_arn}/*"],
        ),
    )


def create_build_environment(
    scope: Any,
    pipeline_vars: PipelineVars,
    stage_name: str,
    project_name: str,
    compute_type: codebuild.ComputeType,
) -> codebuild.BuildEnvironment:
    """Create the build environment configuration for the OCI validation project.

    Args:
        scope: CDK construct scope
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        project_name: Name of the project
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured BuildEnvironment for the CodeBuild project
    """
    build_image = get_build_image_for_architecture(
        self=scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
    )

    fleet = use_fleet(
        self=scope,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        stage_type=project_name,
    )

    return codebuild.BuildEnvironment(
        build_image=build_image,  # type: ignore
        privileged=True,
        compute_type=compute_type,
        fleet=fleet,
    )


def create_build_spec(
    commands: OciValidationCommands,
    pipeline_vars: PipelineVars,
) -> codebuild.BuildSpec:
    """Create the build specification for the OCI validation CodeBuild project.

    Args:
        commands: OCI validation installation and execution commands
        pipeline_vars: Pipeline variables containing project information

    Returns:
        BuildSpec object for the CodeBuild project
    """
    install_phase = (
        install_pre_backed() if pipeline_vars.codebuild_docker_ecr_repo_arn else install_default(dict(commands))
    )

    return codebuild.BuildSpec.from_object({
        "version": "0.2",
        "phases": {
            "install": install_phase,
            "build": {
                "commands": commands["commands"],
            },
        },
    })


def create_environment_variables() -> dict[str, codebuild.BuildEnvironmentVariable]:
    """Create environment variables for the OCI validation CodeBuild project.

    Returns:
        Dictionary of environment variables
    """
    return {
        "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
            value="/var/run/docker/containerd/containerd.sock",
            type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
        ),
    }


def create_oci_image_validation_project(
    *,
    scope: Any,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> codebuild.PipelineProject:
    """Create a CodeBuild pipeline project for OCI image validation.

    This function creates a fully configured CodeBuild project for validating
    OCI image signatures using AWS Signer and Notation. The project:
    1. Selects the appropriate build image based on CPU architecture
    2. Generates installation and validation commands
    3. Configures the build environment with Docker privileges
    4. Applies default permissions and attaches required IAM policies

    Args:
        scope: CDK construct scope
        env: AWS environment containing region and account information
        stage_name: Name of the stage being deployed
        pipeline_vars: Pipeline variables containing project information
        cpu_architecture: CPU architecture for the build environment
        compute_type: Compute type for the CodeBuild project
        pipeline_artifacts_bucket: S3 bucket to store pipeline artifacts

    Returns:
        Configured CodeBuild pipeline project for OCI image validation
    """
    project_name = "oci_image_validation_project"

    # Generate assume role commands
    assume_commands = assume_role_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="oci-image-validation",
    )

    # Create OCI validation commands using functional composition
    commands = create_oci_validation_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
        assume_commands=assume_commands,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )

    # Create the CodeBuild project
    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_{project_name}",
        environment=create_build_environment(
            scope=scope,
            pipeline_vars=pipeline_vars,
            stage_name=stage_name,
            project_name=project_name,
            compute_type=compute_type,
        ),
        auto_retry_limit=3,
        environment_variables=create_environment_variables(),
        build_spec=create_build_spec(commands, pipeline_vars),
    )

    # Apply permissions and attach IAM policies
    apply_default_permissions(project, env)
    attach_s3_upload_policy(
        project=project,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )
    attach_oci_validation_iam_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
    )

    return project
