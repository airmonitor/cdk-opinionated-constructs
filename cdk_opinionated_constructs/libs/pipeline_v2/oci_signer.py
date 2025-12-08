"""OCI image signing CodeBuild project configuration.

This module provides functions to create and configure CodeBuild projects
for signing OCI container images using AWS Signer and attaching SBOM/CVE artifacts.
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
# Type Definitions for Better Type Safety and Documentation
# =============================================================================


class OciSignerCommands(TypedDict):
    """Type definition for OCI signer command structure."""

    install_commands: list[str]
    commands: list[str]


class SignerContext(TypedDict):
    """Immutable context for OCI signer command generation."""

    region: str
    account: str
    project: str
    stage_name: str
    bucket_name: str


# =============================================================================
# Pure Helper Functions - High Cohesion, Single Responsibility
# =============================================================================


def _create_aws_signer_install_command(cpu_architecture: Literal["arm64", "amd64"]) -> str:
    """Generate AWS Signer Notation CLI installation command.

    Args:
        cpu_architecture: Target CPU architecture

    Returns:
        Installation command for AWS Signer Notation CLI
    """
    return (
        f"wget https://d2hvyiie56hcat.cloudfront.net/linux/{cpu_architecture}/"
        f"installer/rpm/latest/aws-signer-notation-cli_{cpu_architecture}.rpm"
    )


def _create_aws_signer_rpm_command(cpu_architecture: Literal["arm64", "amd64"]) -> str:
    """Generate AWS Signer RPM installation command.

    Args:
        cpu_architecture: Target CPU architecture

    Returns:
        RPM installation command
    """
    return f"sudo rpm -U aws-signer-notation-cli_{cpu_architecture}.rpm"


def _create_oras_install_commands(
    cpu_architecture: Literal["arm64", "amd64"],
    oras_version: str,
) -> tuple[str, ...]:
    """Generate ORAS tool installation commands.

    Args:
        cpu_architecture: Target CPU architecture
        oras_version: Version of ORAS to install

    Returns:
        Tuple of ORAS installation commands
    """
    return (
        f"curl -LO 'https://github.com/oras-project/oras/releases/download/"
        f"v{oras_version}/oras_{oras_version}_linux_{cpu_architecture}.tar.gz'",
        "mkdir -p oras-install/",
        f"tar -xzf oras_{oras_version}_linux_{cpu_architecture}.tar.gz -C oras-install/",
        "sudo mv oras-install/oras /usr/local/bin/",
    )


def _create_security_tools_install_commands() -> tuple[str, ...]:
    """Generate security tools (Grype, Syft) installation commands.

    Returns:
        Tuple of security tools installation commands
    """
    return (
        "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
    )


def _get_ssm_parameter_command(
    ssm_path: str,
    region: str,
    variable_name: str,
) -> str:
    """Generate SSM parameter retrieval command.

    Args:
        ssm_path: Full SSM parameter path
        region: AWS region
        variable_name: Environment variable name to store the value

    Returns:
        Command to retrieve SSM parameter and store in environment variable
    """
    return (
        f"{variable_name}=$(aws ssm get-parameter "
        f'--name "{ssm_path}" '
        f"--region {region} "
        f'--query "Parameter.Value" '
        f"--output text)"
    )


def _create_ecr_login_commands(ctx: SignerContext) -> tuple[str, ...]:
    """Generate ECR login and image retrieval commands.

    Args:
        ctx: Signer context containing AWS environment details

    Returns:
        Tuple of ECR login commands
    """
    ssm_base = f"/{ctx['project']}/{ctx['stage_name']}/ecr"

    return (
        f"export PASSWORD=$(aws ecr get-login-password --region {ctx['region']})",
        _get_ssm_parameter_command(f"{ssm_base}/image/uri", ctx["region"], "IMAGE_URI"),
        "echo $IMAGE_URI",
        _get_ssm_parameter_command(
            f"/{ctx['project']}/{ctx['stage_name']}/signer/profile/arn",
            ctx["region"],
            "SIGNER_PROFILE_ARN",
        ),
        "echo $SIGNER_PROFILE_ARN",
        _get_ssm_parameter_command(f"{ssm_base}/repository/uri", ctx["region"], "REPOSITORY_URI"),
        "echo $REPOSITORY_URI",
        _get_ssm_parameter_command(f"{ssm_base}/image/tag", ctx["region"], "IMAGE_TAG"),
        "echo $IMAGE_TAG",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {ctx['region']} | "
        f"docker login --username AWS --password-stdin {ctx['account']}.dkr.ecr.{ctx['region']}.amazonaws.com",
        "docker pull $IMAGE_URI",
    )


def _create_cve_report_commands(bucket_name: str) -> tuple[str, ...]:
    """Generate CVE report generation and storage commands.

    Args:
        bucket_name: S3 bucket name for storing artifacts

    Returns:
        Tuple of CVE report commands
    """
    return (
        "echo Generating CVE report",
        "grype $IMAGE_URI -o json > cve.json",
        "echo Storing CVE report in artifacts bucket",
        f"aws s3 cp cve.json s3://{bucket_name}/CVE/cve.json",
    )


def _create_sbom_report_commands(bucket_name: str) -> tuple[str, ...]:
    """Generate SBOM generation and storage commands.

    Args:
        bucket_name: S3 bucket name for storing artifacts

    Returns:
        Tuple of SBOM report commands
    """
    return (
        "echo Generating SBOM ",
        "syft $IMAGE_URI -o cyclonedx-json > sbom.spdx.json",
        "echo Storing SBOM content in artifacts bucket",
        f"aws s3 cp sbom.spdx.json s3://{bucket_name}/SBOM/sbom.spdx.json",
    )


def _create_oras_attach_commands() -> tuple[str, ...]:
    """Generate ORAS artifact attachment commands.

    Note: ORAS 1.3.0+ uses --format instead of deprecated -o flag.
    The referrers list is returned under .referrers[] in the JSON output.

    Returns:
        Tuple of ORAS attachment commands
    """
    return (
        "echo Attaching reports to the image",
        "oras attach --artifact-type cve/example $IMAGE_URI cve.json:application/json",
        "oras attach --artifact-type sbom/example $IMAGE_URI sbom.spdx.json:application/json",
        # ORAS 1.3.0+ uses --format json; referrers are under .referrers[] array
        "CVEDIGEST=$(oras discover --format json $IMAGE_URI | jq -r '.referrers[0].digest')",
        "SBOMDIGEST=$(oras discover --format json $IMAGE_URI | jq -r '.referrers[1].digest')",
        "echo $AWS_REGION",
    )


def _create_notation_sign_command(
    target: str,
    region: str,
) -> str:
    """Generate a notation sign command.

    Args:
        target: Target to sign (image URI or digest reference)
        region: AWS region for the signer plugin

    Returns:
        Notation sign command string
    """
    return (
        f"notation sign {target} "
        f"--plugin-config aws-region={region} "
        '--plugin "com.amazonaws.signer.notation.plugin" '
        '--id "$SIGNER_PROFILE_ARN"'
    )


def _create_signing_commands(region: str) -> tuple[str, ...]:
    """Generate container image and artifact signing commands.

    Args:
        region: AWS region for the signer plugin

    Returns:
        Tuple of signing commands
    """
    return (
        _create_notation_sign_command("--verbose $IMAGE_URI", region),
        _create_notation_sign_command("$REPOSITORY_URI@$CVEDIGEST", region),
        _create_notation_sign_command("$REPOSITORY_URI@$SBOMDIGEST", region),
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
            (
                _create_aws_signer_install_command(cpu_architecture),
                _create_aws_signer_rpm_command(cpu_architecture),
                "notation plugin ls",
            ),
            _create_oras_install_commands(cpu_architecture, oras_version),
            _create_security_tools_install_commands(),
        )
    )


def _compose_scan_commands(
    ctx: SignerContext,
    assume_commands: list[str],
) -> list[str]:
    """Compose all scanning and signing commands using function composition.

    This function chains together multiple command generators to create
    the complete OCI signing command sequence.

    Args:
        ctx: Signer context containing AWS environment details
        assume_commands: Commands to assume the required IAM role

    Returns:
        List of all commands in execution order
    """
    # Create partial applications for context-dependent functions
    ecr_login = partial(_create_ecr_login_commands, ctx)
    cve_report = partial(_create_cve_report_commands, ctx["bucket_name"])
    sbom_report = partial(_create_sbom_report_commands, ctx["bucket_name"])
    signing = partial(_create_signing_commands, ctx["region"])

    # Compose all command sequences
    return list(
        chain(
            assume_commands,
            ecr_login(),
            (revert_to_original_role_command,),
            cve_report(),
            sbom_report(),
            _create_oras_attach_commands(),
            assume_commands,
            signing(),
        )
    )


def _create_signer_context(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    bucket_name: str,
) -> SignerContext:
    """Create an immutable signer context from environment parameters.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        bucket_name: S3 bucket name for storing artifacts

    Returns:
        Immutable context dictionary for signer operations
    """
    return SignerContext(
        region=str(env.region),
        account=str(env.account),
        project=pipeline_vars.project,
        stage_name=stage_name,
        bucket_name=bucket_name,
    )


# =============================================================================
# Public API Functions
# =============================================================================


def create_oci_signer_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    oras_version: str = "1.3.0",
) -> OciSignerCommands:
    """Create OCI signer installation and execution commands.

    This function generates all necessary commands for installing signing tools
    and executing the OCI image signing workflow including SBOM/CVE generation.

    Args:
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        pipeline_artifacts_bucket: S3 bucket to store artifacts like SBOM and CVE reports
        cpu_architecture: CPU architecture for which to install tools
        assume_commands: Commands to assume the required IAM role
        oras_version: Version of ORAS tool to install, defaults to "1.3.0"

    Returns:
        Dictionary containing:
            - "install_commands": Commands to install required tools
            - "commands": Commands to execute the signing workflow
    """
    ctx = _create_signer_context(
        env,
        pipeline_vars,
        stage_name,
        pipeline_artifacts_bucket.bucket_name,
    )

    return OciSignerCommands(
        install_commands=_compose_install_commands(cpu_architecture, oras_version),
        commands=_compose_scan_commands(ctx, assume_commands),
    )


def attach_oci_signer_iam_policies(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> None:
    """Attach necessary IAM policies to the OCI signer project.

    This function attaches:
    1. S3 object write access for storing artifacts (SBOM, CVE reports)
    2. The oci-signer role for signing operations

    Args:
        project: The CodeBuild project to attach IAM policies to
        env: AWS environment containing region and account information
        pipeline_vars: Pipeline variables containing project information
        stage_name: Name of the stage being deployed
        pipeline_artifacts_bucket: S3 bucket for storing artifacts
    """
    project.add_to_role_policy(
        statement=iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{pipeline_artifacts_bucket.bucket_arn}/*"],
        )
    )

    attach_role(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="oci-signer",
    )


def create_build_environment(
    scope: Any,
    pipeline_vars: PipelineVars,
    stage_name: str,
    project_name: str,
    compute_type: codebuild.ComputeType,
) -> codebuild.BuildEnvironment:
    """Create the build environment configuration for the OCI signer project.

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
    commands: OciSignerCommands,
    pipeline_vars: PipelineVars,
) -> codebuild.BuildSpec:
    """Create the build specification for the OCI signer CodeBuild project.

    Args:
        commands: OCI signer installation and execution commands
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
                "commands": [
                    ". /.venv/bin/activate",
                    *commands["commands"],
                ],
            },
        },
    })


def create_environment_variables() -> dict[str, codebuild.BuildEnvironmentVariable]:
    """Create environment variables for the OCI signer CodeBuild project.

    Returns:
        Dictionary of environment variables
    """
    return {
        "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
            value="/var/run/docker/containerd/containerd.sock",
            type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
        ),
    }


def create_oci_signer_project(
    *,
    scope: Any,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    compute_type: codebuild.ComputeType,
) -> codebuild.PipelineProject:
    """Create a CodeBuild pipeline project for OCI image signing workflow.

    This function creates a fully configured CodeBuild project for signing
    OCI container images. The project:
    1. Selects appropriate build image based on CPU architecture
    2. Generates OCI signer role assumption commands
    3. Constructs installation and build commands for signing process
    4. Configures optional CodeBuild fleet if provided
    5. Creates PipelineProject with privileged Docker access and auto-retry enabled
    6. Applies default IAM permissions and OCI signer-specific policies

    Args:
        scope: CDK construct scope
        env: AWS environment containing region and account information
        stage_name: Name of the stage being deployed
        pipeline_vars: Pipeline variables containing project information
        cpu_architecture: CPU architecture for the build environment
        pipeline_artifacts_bucket: S3 bucket for storing build artifacts
        compute_type: Compute type for the CodeBuild project

    Returns:
        Configured CodeBuild project for OCI image signing operations
    """
    project_name = "oci_signer_project"

    # Generate assume role commands
    assume_commands = assume_role_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        role_name="oci-signer",
    )

    # Create OCI signer commands using functional composition
    commands = create_oci_signer_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
        cpu_architecture=cpu_architecture,
        assume_commands=assume_commands,
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
    attach_oci_signer_iam_policies(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )

    return project
