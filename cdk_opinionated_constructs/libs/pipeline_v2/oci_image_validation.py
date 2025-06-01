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


def _create_oci_image_validation_commands(
    *,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    assume_commands: list[str],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    oras_version: str = "1.2.2",
) -> dict[str, list[str] | list[str | Any]]:
    """
    Parameters:
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture to use for installation
        assume_commands (list[str]): Commands to assume the necessary IAM role
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket to store artifacts
        oras_version (str): Version of ORAS tool to install, defaults to "1.2.2"

    Functionality:
        Generates shell commands for OCI image validation in two categories:
        1. Install commands:
           - Downloads and installs AWS Signer Notation CLI for the specified architecture
           - Installs ORAS (OCI Registry As Storage) tool
           - Installs Anchore's Grype and Syft security scanning tools

        2. Validation commands:
           - Assumes the specified role using provided commands
           - Retrieves container image information from SSM parameters
           - Logs into Amazon ECR
           - Creates a trust policy for signature verification
           - Verifies the container image signature using Notation
           - Creates an image definitions file for deployment
           - Uploads the image definitions file to the artifacts S3 bucket

    Returns:
        dict[str, list[str] | list[str | Any]]: Dictionary containing two keys:
            - "install_commands": List of commands to install required tools
            - "commands": List of commands to validate OCI image signatures
    """
    install_commands = [
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

    commands = [
        *assume_commands,
        "echo waiting 1 minute for service readiness...",
        "sleep 60",
        f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
        f"IMAGE_URI=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_URI",
        f"SIGNER_PROFILE_ARN=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/signer/profile/arn" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $SIGNER_PROFILE_ARN",
        f"REPOSITORY_URI=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/ecr/repository/uri" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $REPOSITORY_URI",
        f"IMAGE_TAG=$(aws ssm get-parameter "
        f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/tag" '
        f"--region {env.region} "
        f'--query "Parameter.Value" '
        f"--output text)",
        "echo $IMAGE_TAG",
        "echo Logging in to Amazon ECR...",
        f"aws ecr get-login-password --region {env.region} | "
        f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
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
        "notation verify $IMAGE_URI",
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
        f"aws s3 cp image_definitions.json s3://{pipeline_artifacts_bucket.bucket_name}/image_definitions/image_definitions.json",
    ]

    return {"install_commands": install_commands, "commands": commands}


def _attach_oci_image_validation_iam_policies(
    *,
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild project to attach policies to
        env (Environment): AWS environment containing region and account information
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        stage_name (str): Name of the stage being deployed
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket to store artifacts

    Functionality:
        Attaches IAM policies to the CodeBuild project that are required for OCI image validation:
        - Grants S3 PutObject permissions to allow writing to the pipeline artifacts bucket
        - Attaches a predefined role with additional permissions needed for OCI image validation
          using the attach_role helper function
    """

    project.add_to_role_policy(
        statement=iam.PolicyStatement(
            actions=[
                "s3:PutObject",
            ],
            resources=[
                f"{pipeline_artifacts_bucket.bucket_arn}/*",
            ],
        ),
    )
    attach_role(
        project=project, env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="oci-image-validation"
    )


def create_oci_image_validation_project(
    *,
    scope,
    env: Environment,
    stage_name: str,
    pipeline_vars: PipelineVars,
    cpu_architecture: Literal["arm64", "amd64"],
    compute_type: codebuild.ComputeType,
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
) -> codebuild.PipelineProject:
    """
    Parameters:
        scope (Construct): The scope in which to define this construct
        env (Environment): AWS environment containing region and account information
        stage_name (str): Name of the stage being deployed
        pipeline_vars (PipelineVars): Pipeline variables containing project information
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture to use for the build
        compute_type (codebuild.ComputeType): The compute resources for the build environment
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket to store artifacts including image definitions

    Functionality:
        Creates a CodeBuild pipeline project that validates OCI image signatures.
        The project:
        1. Uses the appropriate build image based on CPU architecture
        2. Installs AWS Signer Notation CLI and other required tools
        3. Retrieves Docker image information from SSM parameters
        4. Creates a trust policy for signature verification
        5. Verifies the container image signature using Notation
        6. Creates an image definitions file with container information
        7. Uploads the image definitions file to S3 for use in deployment
        8. Applies necessary IAM permissions for ECR, SSM, AWS Signer, and S3 operations

    Returns:
        codebuild.PipelineProject: The created CodeBuild project for OCI image validation
    """
    build_image = get_build_image_for_architecture(cpu_architecture)

    _assume_role_commands = assume_role_commands(
        env=env, pipeline_vars=pipeline_vars, stage_name=stage_name, role_name="oci-image-validation"
    )

    commands = _create_oci_image_validation_commands(
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        cpu_architecture=cpu_architecture,
        assume_commands=_assume_role_commands,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )

    project = codebuild.PipelineProject(
        scope,
        f"{stage_name}_oci_image_validation_project",
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
                    "commands": [*commands["commands"]],
                },
            },
        }),
    )

    apply_default_permissions(project, env)
    _attach_oci_image_validation_iam_policies(
        project=project,
        env=env,
        pipeline_vars=pipeline_vars,
        stage_name=stage_name,
        pipeline_artifacts_bucket=pipeline_artifacts_bucket,
    )

    return project
