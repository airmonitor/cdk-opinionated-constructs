from typing import Any, Literal

import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars
from cdk_opinionated_constructs.stages.logic import (
    apply_default_permissions,
    assume_role_commands,
    attach_role,
    default_install_commands,
    get_build_image_for_architecture,
    revert_to_original_role_command,
    runtime_versions,
)


def _create_oci_signer_install_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    oras_version: str = "1.2.2",
) -> dict[str, list[str] | list[str | Any]]:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket to store artifacts like SBOM and CVE reports
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for which to install tools
        oras_version (str): Version of ORAS tool to install, defaults to "1.2.2"

    Functionality:
        Generates commands for OCI artifact signing workflow, including:
        1. Installing necessary tools (AWS Signer Notation CLI, ORAS, Grype, Syft)
        2. Retrieving image information from SSM parameters
        3. Pulling the Docker image from ECR
        4. Generating vulnerability (CVE) reports with Grype
        5. Generating Software Bill of Materials (SBOM) with Syft
        6. Storing reports in the S3 artifacts bucket
        7. Attaching reports to the container image using ORAS
        8. Signing the container image and attached artifacts using AWS Signer

    Returns:
        dict[str, list[str] | list[str | Any]]: Dictionary containing two keys:
            - "install_commands": Commands to install required tools
            - "commands": Commands to execute the signing workflow
    """

    _install_commands = [
        f"wget https://d2hvyiie56hcat.cloudfront.net/linux/{cpu_architecture}/installer/rpm/latest/aws-signer-notation-cli_{cpu_architecture}.rpm",
        f"sudo rpm -U aws-signer-notation-cli_{cpu_architecture}.rpm",
        "notation plugin ls",
        f"curl -LO 'https://github.com/oras-project/oras/releases/download/v{oras_version}/oras_{oras_version}_linux_{cpu_architecture}.tar.gz'",
        "mkdir -p oras-install/",
        f"tar -xzf oras_{oras_version}_linux_{cpu_architecture}.tar.gz -C oras-install/",
        "sudo mv oras-install/oras /usr/local/bin/",
        "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
    ]

    ssm_path_base = f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}"
    ecr_ssm_path_base = f"{ssm_path_base}/ecr"

    commands = [
        *assume_commands,
        f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
        f"IMAGE_URI=$(aws ssm get-parameter "
        f'--name "{ecr_ssm_path_base}/image/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_URI",
        f"SIGNER_PROFILE_ARN=$(aws ssm get-parameter "
        f'--name "{ssm_path_base}/signer/profile/arn" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $SIGNER_PROFILE_ARN",
        f"REPOSITORY_URI=$(aws ssm get-parameter "
        f'--name "{ecr_ssm_path_base}/repository/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $REPOSITORY_URI",
        f"IMAGE_TAG=$(aws ssm get-parameter "
        f'--name "{ecr_ssm_path_base}/image/tag" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_TAG",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {env.region} | "
        f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
        "docker pull $IMAGE_URI",
        revert_to_original_role_command,
        "echo Generating CVE report",
        "grype $IMAGE_URI -o json > cve.json",
        "echo Storing CVE report in artifacts bucket",
        f"aws s3 cp cve.json s3://{pipeline_artifacts_bucket.bucket_name}/CVE/cve.json",
        "echo Generating SBOM ",
        "syft $IMAGE_URI -o cyclonedx-json > sbom.spdx.json",
        "echo Storing SBOM content in artifacts bucket",
        f"aws s3 cp sbom.spdx.json s3://{pipeline_artifacts_bucket.bucket_name}/SBOM/sbom.spdx.json",
        "echo Attaching reports to the image",
        "oras attach --artifact-type cve/example $IMAGE_URI cve.json:application/json",
        "oras attach --artifact-type sbom/example $IMAGE_URI sbom.spdx.json:application/json",
        "CVEDIGEST=`oras discover -o json $IMAGE_URI | jq -r '.manifests[0].digest'`",
        "SBOMDIGEST=`oras discover -o json $IMAGE_URI | jq -r '.manifests[1].digest'`",
        "echo $AWS_REGION",
        *assume_commands,
        f"notation sign --verbose $IMAGE_URI "
        f"--plugin-config aws-region={env.region} "
        '--plugin "com.amazonaws.signer.notation.plugin" '
        '--id "$SIGNER_PROFILE_ARN"',
        f"notation sign $REPOSITORY_URI@$CVEDIGEST "
        f"--plugin-config aws-region={env.region} "
        '--plugin "com.amazonaws.signer.notation.plugin" '
        '--id "$SIGNER_PROFILE_ARN"',
        f"notation sign $REPOSITORY_URI@$SBOMDIGEST "
        f"--plugin-config aws-region={env.region} "
        '--plugin "com.amazonaws.signer.notation.plugin" '
        '--id "$SIGNER_PROFILE_ARN"',
    ]

    return {"install_commands": _install_commands, "commands": commands}


def _attach_oci_signer_iam_policies(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild project to attach IAM policies to
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed

    Functionality:
        Attaches necessary IAM policies to the OCI image validation project:
        1. S3 object write access to store generated artifacts (SBOM, CVE reports) in the pipeline artifacts bucket
        2. Attach oci-signer role
    """

    project.add_to_role_policy(
        statement=iam.PolicyStatement(
            actions=[
                "s3:PutObject",
            ],
            resources=[
                f"{pipeline_artifacts_bucket.bucket_arn}/*",
            ],
        )
    )

    attach_role(project=project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="oci-signer")


def create_oci_signer_project(
    *,
    scope,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    compute_type: codebuild.ComputeType,
) -> codebuild.PipelineProject:
    """
    Parameters:
        scope: The CDK construct scope (parent) for creating this resource
        env (Environment): AWS environment containing region and account information
        stage_name (str): Name of the stage being deployed
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket to store artifacts like SBOM and CVE reports
        compute_type (codebuild.ComputeType): The CodeBuild compute resource type to use

    Functionality:
        Creates a CodeBuild pipeline project configured for OCI image signing workflow.
        The project:
        1. Sets up a build environment with the specified architecture
        2. Installs necessary tools (AWS Signer Notation CLI, ORAS, Grype, Syft)
        3. Configures Docker container access through containerd
        4. Attaches required IAM policies for ECR, SSM, S3, and AWS Signer operations
        5. Creates a build specification with install and build commands for the OCI signing process

    Returns:
        codebuild.PipelineProject: The configured CodeBuild project for OCI signing
    """
    build_image = get_build_image_for_architecture(cpu_architecture)

    _assume_oci_signer_role_commands = assume_role_commands(
        env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="oci-signer"
    )

    commands = _create_oci_signer_install_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
        cpu_architecture=cpu_architecture,
        assume_commands=_assume_oci_signer_role_commands,
    )

    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_oci_signer_project",
        environment=codebuild.BuildEnvironment(
            build_image=build_image,  # type: ignore
            privileged=True,
            compute_type=compute_type,
        ),
        environment_variables={
            "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                value="/var/run/docker/containerd/containerd.sock",
                type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
            ),
        },
        build_spec=codebuild.BuildSpec.from_object({
            "version": "0.2",
            "phases": {
                "install": {
                    "runtime-versions": runtime_versions,
                    "commands": [
                        "pip install uv",
                        "make venv",
                        ". .venv/bin/activate",
                        *default_install_commands,
                        *commands["install_commands"],
                    ],
                },
                "build": {
                    "commands": [
                        *commands["commands"],
                    ],
                },
            },
        }),
    )

    apply_default_permissions(project, env)
    _attach_oci_signer_iam_policies(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )

    return project
