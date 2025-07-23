from typing import Any, Literal

import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_codepipeline as codepipeline
import aws_cdk.aws_codepipeline_actions as codepipeline_actions
import aws_cdk.aws_iam as iam
import aws_cdk.aws_s3 as s3

from aws_cdk import Duration, Environment, pipelines
from cdk.schemas.configuration_vars import PipelineVars

runtime_versions = {"nodejs": "22", "python": "3.13"}
default_install_commands = [
    "npm install -g aws-cdk",
    "pip install uv",
    "make install",
]


def default_environment_variables(pipeline_vars: PipelineVars) -> dict[str, Any]:  # noqa: ARG001
    """Returns a dictionary of default environment variables for a CodeBuild project."""
    return {}


def jfrog_pip_default_environment_variables(pipeline_vars: PipelineVars) -> dict[str, Any]:
    """Returns a dictionary of default environment variables for a CodeBuild project."""
    return {
        "UV_INDEX_URL": f"https://{pipeline_vars.jfrog_artifactory_service_account_id}:"
        f"{pipeline_vars.jfrog_artifactory_service_account_api_key}@"
        f"{pipeline_vars.jfrog_artifactory_pypi_uri}",
        "PIP_INDEX_URL": f"https://{pipeline_vars.jfrog_artifactory_service_account_id}:"
        f"{pipeline_vars.jfrog_artifactory_service_account_api_key}@"
        f"{pipeline_vars.jfrog_artifactory_pypi_uri}",
    }


revert_to_original_role_command = "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN"


def assume_role_commands(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    role_name: str,
) -> list[str]:
    """
    Parameters:
        env (Environment): The AWS environment containing account information
        pipeline_vars (PipelineVars): Configuration variables for the pipeline
        stage_name (str): Name of the deployment stage
        role_name (str): Base name of the IAM role to assume

    Functionality:
        Generates a list of shell commands that:
        1. Outputs a message indicating role assumption is in progress
        2. Uses AWS CLI to assume a role in the target account with a formatted role ARN
        3. Parses the credentials from the assume-role output
        4. Sets the AWS credential environment variables

    Returns:
        list[str]: A list of shell commands to execute for assuming the specified IAM role
    """
    return [
        'echo "Assuming role into target account..."',
        f"ASSUME_OUTPUT=$(aws sts assume-role "
        f"--role-arn arn:aws:iam::{env.account}:role/{pipeline_vars.project}-{stage_name}-{role_name}-role "
        f"--role-session-name {role_name}-session "
        f"--output text "
        f"--query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]')",
        'read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<< "$ASSUME_OUTPUT"',
        "export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
    ]


def attach_role(
    project: codebuild.PipelineProject,
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    role_name: str,
) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild project to which the role policy will be attached
        env (Environment): The AWS environment containing account information
        pipeline_vars (PipelineVars): Configuration variables for the pipeline
        stage_name (str): Name of the deployment stage
        role_name (str): Base name of the IAM role to be attached

    Functionality:
        Attaches a policy to the CodeBuild project's execution role that grants permission
        to assume a specific IAM role in the target account. The function creates a policy
        statement with sts:AssumeRole and sts:TagSession permissions targeting a role with
        a name constructed from the project name, stage name, and role name parameters.

    The role ARN follows the pattern:
    arn:aws:iam::{account}:role/{project}-{stage_name}-{role_name}-role

    """
    project.add_to_role_policy(
        statement=iam.PolicyStatement(
            actions=["sts:AssumeRole", "sts:TagSession"],
            resources=[f"arn:aws:iam::{env.account}:role/{pipeline_vars.project}-{stage_name}-{role_name}-role"],
        )
    )


def apply_default_permissions(project: codebuild.PipelineProject, env: Environment) -> None:
    """
    Parameters:
        project (codebuild.PipelineProject): The CodeBuild pipeline project to which permissions will be applied
        env (Environment): AWS environment object containing account and region information

    Functionality:
        Applies a comprehensive set of default IAM permissions to a CodeBuild pipeline project for AWS CDK operations.
        The function adds multiple policy statements to the project's IAM role:
        - S3 permissions for CDK asset management (GetObject, PutObject, ListBucket, GetBucketLocation)
        - STS permissions for role assumption and session tagging
        - SSM Parameter Store permissions for getting and putting parameters
        - CloudFormation permissions for complete stack lifecycle management
        (create, update, delete, describe operations)
        - IAM PassRole permissions for CDK execution roles across all AWS regions

    Returns:
        None
    """

    project.add_to_role_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
            resources=["arn:aws:s3:::cdk-*-assets-*", "arn:aws:s3:::cdk-*-assets-*/*"],
        )
    )
    project.add_to_role_policy(
        iam.PolicyStatement(
            actions=["sts:AssumeRole", "sts:TagSession"],
            resources=["arn:aws:iam::*:role/cdk-hnb659fds-*"],
        )
    )
    project.add_to_role_policy(
        iam.PolicyStatement(
            actions=["ssm:GetParameter", "ssm:PutParameter"],
            resources=["*"],
        )
    )
    project.add_to_role_policy(
        iam.PolicyStatement(
            actions=[
                "cloudformation:ContinueUpdateRollback",
                "cloudformation:CreateChangeSet",
                "cloudformation:CreateStack",
                "cloudformation:DeleteChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:DescribeStackEvents",
                "cloudformation:DescribeStacks",
                "cloudformation:ExecuteChangeSet",
                "cloudformation:GetTemplate",
                "cloudformation:RollbackStack",
                "cloudformation:UpdateStack",
                "cloudformation:DeleteStack",
            ],
            resources=["*"],
        )
    )

    aws_regions_list = [
        "ap-south-1",
        "eu-north-1",
        "eu-west-3",
        "eu-west-2",
        "eu-west-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-northeast-1",
        "me-central-1",
        "il-central-1",
        "ca-central-1",
        "sa-east-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "eu-central-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]
    for region_name in aws_regions_list:
        project.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:PassRole",
                ],
                resources=[f"arn:aws:iam::{env.account}:role/cdk-hnb659fds-cfn-exec-role-{env.account}-{region_name}"],
            )
        )


def get_build_image_for_architecture(cpu_architecture: Literal["arm64", "amd64"]):
    """Get the appropriate build image based on CPU architecture."""
    return (
        codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5
        if cpu_architecture == "amd64"
        else codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0
    )


def soci_image_builder(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    soci_snapshotter_version: str = "0.9.0",
) -> pipelines.CodeBuildStep:
    """
    Parameters:
        env (Environment): AWS environment configuration containing region and account details
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        stage_name (str): Name of the deployment stage
        cpu_architecture (str): CPU architecture for the build environment
        soci_snapshotter_version (str): Version of SOCI snapshotter to install

    Functionality:
        Creates a CodeBuild step that builds SOCI (Seekable OCI) indices for container images.
        The function:
        - Sets up a privileged build environment with containerd socket access
        - Downloads and installs SOCI binaries
        - Retrieves container image URI from SSM Parameter Store
        - Authenticates with ECR
        - Pulls the container image
        - Generates and pushes SOCI index to ECR
        - Configures necessary IAM permissions for ECR and SSM operations

    Returns:
        pipelines.CodeBuildStep: Configured CodeBuild step for SOCI index generation
    """

    return pipelines.CodeBuildStep(
        "soci_index_builder",
        build_environment=codebuild.BuildEnvironment(
            compute_type=codebuild.ComputeType.SMALL,
            privileged=True,
            environment_variables={
                "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                    value="/var/run/docker/containerd/containerd.sock",
                    type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                ),
            },
        ),
        commands=[
            f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
            f"IMAGE_URI=$(aws ssm get-parameter "
            f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/uri" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $IMAGE_URI",
            "echo Download the SOCI Binaries",
            f"wget --quiet https://github.com/awslabs/soci-snapshotter/releases/download/v{soci_snapshotter_version}/soci-snapshotter-{soci_snapshotter_version}-linux-{cpu_architecture}.tar.gz",
            f"tar xvzf soci-snapshotter-{soci_snapshotter_version}-linux-{cpu_architecture}.tar.gz soci",
            "mv soci /usr/local/bin/soci",
            "echo Logging in to Amazon ECR...",
            f"aws ecr get-login-password --region {env.region} | "
            f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
            "ctr image pull -user AWS:$PASSWORD $IMAGE_URI",
            "echo Generating SOCI index ",
            "soci create $IMAGE_URI ",
            "echo Push the SOCI index to ECR ",
            "soci push --user AWS:$PASSWORD $IMAGE_URI ",
        ],
        role_policy_statements=[
            iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:PutImage",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter",
                ],
                resources=[
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/image/uri"
                ],
            ),
        ],
    )


def oci_image_signer(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    oras_version: str = "1.2.3",
) -> pipelines.CodeBuildStep:
    """
    Parameters:
        env (Environment): AWS environment configuration containing region and account details
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        stage_name (str): Name of the deployment stage
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket for storing build artifacts
        oras_version (str): Version of ORAS tool to install (defaults to "1.0.0")

    Functionality:
        Creates a CodeBuild step that performs container image signing and security scanning:
        - Installs required tools: AWS Signer Notation CLI, ORAS, Grype, and Syft
        - Pulls container image from ECR
        - Generates CVE vulnerability report using Grype
        - Creates SBOM (Software Bill of Materials) using Syft
        - Stores reports in S3 artifacts bucket
        - Attaches CVE and SBOM reports to the image using ORAS
        - Signs the container image and attached artifacts using AWS Signer
        - Configures necessary IAM permissions for ECR, SSM, Signer, and S3 operations

    Returns:
        pipelines.CodeBuildStep: Configured CodeBuild step for image signing and security scanning
    """
    build_image = (
        codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5
        if cpu_architecture == "amd64"
        else codebuild.LinuxArmBuildImage.AMAZON_LINUX_2023_STANDARD_3_0
    )
    return pipelines.CodeBuildStep(
        "oci_image_signer",
        build_environment=codebuild.BuildEnvironment(
            compute_type=codebuild.ComputeType.SMALL,
            build_image=build_image,  # type: ignore
            privileged=True,
            environment_variables={
                "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                    value="/var/run/docker/containerd/containerd.sock",
                    type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                ),
            },
        ),
        install_commands=[
            f"wget https://d2hvyiie56hcat.cloudfront.net/linux/{cpu_architecture}/installer/rpm/latest/aws-signer-notation-cli_{cpu_architecture}.rpm",
            f"sudo rpm -U aws-signer-notation-cli_{cpu_architecture}.rpm",
            "notation plugin ls",
            f"curl -LO 'https://github.com/oras-project/oras/releases/download/v{oras_version}/oras_{oras_version}_linux_{cpu_architecture}.tar.gz'",
            "mkdir -p oras-install/",
            f"tar -xzf oras_{oras_version}_linux_{cpu_architecture}.tar.gz -C oras-install/",
            "sudo mv oras-install/oras /usr/local/bin/",
            "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        ],
        commands=[
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
            "docker pull $IMAGE_URI",
            "echo Generating CVE report",
            "grype $IMAGE_URI -o json > cve.json",
            "echo Storing CVE report in artifacts bucket",
            f"aws s3 cp cve.json s3://{pipeline_artifacts_bucket.bucket_name}/CVE/cve.json",
            "echo Generating SBOM ",
            "syft $IMAGE_URI -o spdx-json > sbom.spdx.json",
            "echo Storing SBOM content in artifacts bucket",
            f"aws s3 cp sbom.spdx.json s3://{pipeline_artifacts_bucket.bucket_name}/SBOM/sbom.spdx.json",
            "echo Attaching reports to the image",
            "oras attach --artifact-type cve/example $IMAGE_URI cve.json:application/json",
            "oras attach --artifact-type sbom/example $IMAGE_URI sbom.spdx.json:application/json",
            "CVEDIGEST=`oras discover -o json $IMAGE_URI | jq -r '.manifests[0].digest'`",
            "SBOMDIGEST=`oras discover -o json $IMAGE_URI | jq -r '.manifests[1].digest'`",
            "echo $AWS_REGION",
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
        ],
        role_policy_statements=[
            iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter",
                ],
                resources=[
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/image/tag",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/image/uri",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/repository/uri",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"signer/profile/arn",
                ],
            ),
            iam.PolicyStatement(
                actions=["signer:PutSigningProfile", "signer:SignPayload", "signer:GetRevocationStatus"],
                resources=["*"],
            ),
            iam.PolicyStatement(
                actions=[
                    "s3:PutObject",
                ],
                resources=[
                    f"{pipeline_artifacts_bucket.bucket_arn}/*",
                ],
            ),
        ],
    )


def validate_oci_image(
    env: Environment,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    docker_image_project_name: str,
    oras_version: str = "1.2.3",
) -> pipelines.CodeBuildStep:
    """
    Parameters:
        env (Environment): AWS environment configuration containing region and account details
        stage_name (str): Name of the deployment stage
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket for storing build artifacts
        docker_image_project_name (str): Name of the Docker image project
        oras_version (str): Version of ORAS tool to install (defaults to "1.0.0")

    Functionality:
        Creates a CodeBuild step that validates container image signatures and artifacts:
        - Installs required tools: AWS Signer Notation CLI, ORAS, Grype, and Syft
        - Retrieves container image and repository information from SSM parameters
        - Creates and imports a trust policy for signature verification
        - Verifies signatures on:
            - Main container image
        - Generates image definitions file and stores it in S3
        - Configures necessary IAM permissions for ECR, SSM, Signer, and S3 operations

    Returns:
        pipelines.CodeBuildStep: Configured CodeBuild step for image validation and verification
    """

    build_image = (
        codebuild.LinuxBuildImage.AMAZON_LINUX_2_5
        if cpu_architecture == "amd64"
        else codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0
    )
    return pipelines.CodeBuildStep(
        f"validate_oci_image_{docker_image_project_name.replace('-', '_')}",
        build_environment=codebuild.BuildEnvironment(
            compute_type=codebuild.ComputeType.SMALL,
            build_image=build_image,  # type: ignore
            privileged=True,
            environment_variables={
                "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                    value="/var/run/docker/containerd/containerd.sock",
                    type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                ),
            },
        ),
        install_commands=[
            f"wget https://d2hvyiie56hcat.cloudfront.net/linux/{cpu_architecture}/installer/rpm/latest/aws-signer-notation-cli_{cpu_architecture}.rpm",
            f"sudo rpm -U aws-signer-notation-cli_{cpu_architecture}.rpm",
            "notation plugin ls",
            f"curl -LO 'https://github.com/oras-project/oras/releases/download/v{oras_version}/oras_{oras_version}_linux_{cpu_architecture}.tar.gz'",
            "mkdir -p oras-install/",
            f"tar -xzf oras_{oras_version}_linux_{cpu_architecture}.tar.gz -C oras-install/",
            "sudo mv oras-install/oras /usr/local/bin/",
            "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        ],
        commands=[
            f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
            f"IMAGE_URI=$(aws ssm get-parameter "
            f'--name "/{docker_image_project_name}/{stage_name}/ecr/image/uri" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $IMAGE_URI",
            f"SIGNER_PROFILE_ARN=$(aws ssm get-parameter "
            f'--name "/{docker_image_project_name}/{stage_name}/signer/profile/arn" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $SIGNER_PROFILE_ARN",
            f"REPOSITORY_URI=$(aws ssm get-parameter "
            f'--name "/{docker_image_project_name}/{stage_name}/ecr/repository/uri" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $REPOSITORY_URI",
            f"IMAGE_TAG=$(aws ssm get-parameter "
            f'--name "/{docker_image_project_name}/{stage_name}/ecr/image/tag" '
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
            "echo image definitions in artifacts bucket",
            f"aws s3 cp image_definitions.json s3://{pipeline_artifacts_bucket.bucket_name}/image_definitions/image_definitions.json",
        ],
        role_policy_statements=[
            iam.PolicyStatement(
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter",
                ],
                resources=[
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{docker_image_project_name}/{stage_name}/"
                    f"ecr/image/tag",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{docker_image_project_name}/{stage_name}/"
                    f"ecr/image/uri",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{docker_image_project_name}/{stage_name}/"
                    f"ecr/repository/uri",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{docker_image_project_name}/{stage_name}/"
                    f"signer/profile/arn",
                ],
            ),
            iam.PolicyStatement(
                actions=["signer:PutSigningProfile", "signer:SignPayload", "signer:GetRevocationStatus"],
                resources=["*"],
            ),
            iam.PolicyStatement(
                actions=[
                    "s3:PutObject",
                ],
                resources=[
                    f"{pipeline_artifacts_bucket.bucket_arn}/*",
                ],
            ),
        ],
    )


def scan_image_with_trivy(
    env: Environment,
    pipeline_vars: PipelineVars,
    stage_name: str,
    cpu_architecture: Literal["arm64", "amd64"],
    pipeline_artifacts_bucket: s3.Bucket | s3.IBucket,
    trivy_version: str = "0.64.1",
    cdk_opinionated_constructs_version: str = "4.5.3",
) -> pipelines.CodeBuildStep:
    """
    Parameters:
        env (Environment): AWS environment configuration containing region and account details
        pipeline_vars (PipelineVars): Pipeline variables containing project configuration
        stage_name (str): Name of the deployment stage
        cpu_architecture (Literal["arm64", "amd64"]): CPU architecture for the build environment
        pipeline_artifacts_bucket (s3.Bucket | s3.IBucket): S3 bucket for storing build artifacts
        trivy_version (str): Version of Trivy scanner to install (defaults to "0.64.1")
        cdk_opinionated_constructs_version (str): Version of CDK constructs package (defaults to "4.5.3")

    Functionality:
        Creates a CodeBuild step that performs security scanning of container images using Trivy:
        - Installs required tools: wget, boto3, click, and Trivy scanner
        - Downloads security findings parser script
        - Pulls container image from ECR
        - Performs vulnerability scanning on:
            - Container image (looking for HIGH and CRITICAL vulnerabilities)
            - Software Bill of Materials (SBOM)
        - Sends scan results to AWS Security Hub
        - Enforces security standards by failing the build if HIGH or CRITICAL vulnerabilities are found
        - Configures necessary IAM permissions for ECR, SSM, S3, and Security Hub operations

    Returns:
        pipelines.CodeBuildStep: Configured CodeBuild step for Trivy security scanning
    """

    build_image = (
        codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5
        if cpu_architecture == "amd64"
        else codebuild.LinuxArmBuildImage.AMAZON_LINUX_2023_STANDARD_3_0
    )

    _install_commands = [
        "pip3 install boto3 click",
        f"wget https://raw.githubusercontent.com/airmonitor/cdk-opinionated-constructs/refs/heads/"
        f"{cdk_opinionated_constructs_version}/cdk_opinionated_constructs/utils/"
        f"trivy_docker_image_security_hub_parser.py",
    ]

    if cpu_architecture == "amd64":
        _install_commands.extend([
            f"rpm -ivh https://github.com/aquasecurity/trivy/releases/download/"
            f"v{trivy_version}/trivy_{trivy_version}_Linux-64bit.rpm",
        ])
    else:
        _install_commands.extend([
            f"rpm -ivh https://github.com/aquasecurity/trivy/releases/download/"
            f"v{trivy_version}/trivy_{trivy_version}_Linux-ARM64.rpm",
        ])
    return pipelines.CodeBuildStep(
        "scan_image_with_trivy",
        build_environment=codebuild.BuildEnvironment(
            compute_type=codebuild.ComputeType.MEDIUM,
            build_image=build_image,  # type: ignore
            privileged=True,
            environment_variables={
                "CONTAINERD_ADDRESS": codebuild.BuildEnvironmentVariable(
                    value="/var/run/docker/containerd/containerd.sock",
                    type=codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                ),
            },
        ),
        timeout=Duration.minutes(80),
        install_commands=_install_commands,
        commands=[
            "echo waiting 3 minutes for docker image and SBOM to be ready...",
            "sleep 180",
            f"export PASSWORD=$(aws ecr get-login-password --region {env.region})",
            f"IMAGE_URI=$(aws ssm get-parameter "
            f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/uri" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $IMAGE_URI",
            f"IMAGE_TAG=$(aws ssm get-parameter "
            f'--name "/{pipeline_vars.project}/{stage_name}/ecr/image/tag" '
            f"--region {env.region} "
            f'--query "Parameter.Value" '
            f"--output text)",
            "echo $IMAGE_TAG",
            "echo Logging in to Amazon ECR...",
            f"aws ecr get-login-password --region {env.region} | "
            f"docker login --username AWS --password-stdin {env.account}.dkr.ecr.{env.region}.amazonaws.com",
            "docker pull $IMAGE_URI",
            "echo Scanning image vulnerabilities...",
            "echo #################################################",
            "trivy image"
            " --timeout 60m"
            " --no-progress"
            " --scanners vuln,misconfig,secret"
            " -f json "
            " -o trivy_image_scan_result.json"
            " --severity HIGH,CRITICAL $IMAGE_URI",
            "echo #################################################",
            "echo sending trivy Docker image results to Security Hub...",
            f"python3 trivy_docker_image_security_hub_parser.py "
            f"--aws-account {env.account} "
            f"--aws-region {env.region} "
            f"--project-name {pipeline_vars.project} "
            f"--container-name {pipeline_vars.project}-{stage_name} "
            f"--container-tag $IMAGE_TAG "
            f"--results-file trivy_image_scan_result.json",
            "echo #################################################",
            "echo Scanning SBOM vulnerabilities...",
            f"aws s3 cp s3://{pipeline_artifacts_bucket.bucket_name}/SBOM/sbom.spdx.json /tmp/sbom.spdx.json",
            "trivy sbom "
            " --timeout 60m"
            " --no-progress"
            " --scanners vuln"
            " -f json "
            " -o sbom_trivy_results.json "
            "--severity HIGH,CRITICAL"
            " /tmp/sbom.spdx.json",
            "echo #################################################",
            "echo sending trivy SBOM results to Security Hub...",
            f"python3 trivy_docker_image_security_hub_parser.py "
            f"--aws-account {env.account} "
            f"--aws-region {env.region} "
            f"--project-name {pipeline_vars.project} "
            f"--container-name {pipeline_vars.project}-{stage_name} "
            f"--container-tag $IMAGE_TAG "
            f"--results-file sbom_trivy_results.json",
            "echo #################################################",
            "trivy image "
            "--scanners vuln,misconfig,secret "
            "--timeout 60m "
            "--severity CRITICAL,HIGH "
            "--exit-code 1 "
            " $IMAGE_URI ",
            "echo #################################################",
            "trivy sbom --scanners vuln --timeout 60m --severity CRITICAL,HIGH --exit-code 1 /tmp/sbom.spdx.json",
        ],
        role_policy_statements=[
            iam.PolicyStatement(
                sid="AllowECRAccess",
                actions=[
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                resources=["*"],
            ),
            iam.PolicyStatement(
                sid="AllowSSMParameterAccess",
                actions=[
                    "ssm:GetParameter",
                ],
                resources=[
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/image/tag",
                    f"arn:aws:ssm:{env.region}:{env.account}:parameter/{pipeline_vars.project}/{stage_name}/"
                    f"ecr/image/uri",
                ],
            ),
            iam.PolicyStatement(
                sid="AllowS3ArtifactAccess",
                actions=[
                    "s3:GetObject",
                ],
                resources=[
                    f"{pipeline_artifacts_bucket.bucket_arn}/*",
                ],
            ),
            iam.PolicyStatement(
                sid="AllowImportingSecurityDetailsToSecurityHub",
                actions=[
                    "securityhub:BatchImportFindings",
                ],
                resources=["*"],
            ),
        ],
    )


def add_docker_pipeline_stage(
    *,
    pipeline: codepipeline.Pipeline,
    stage_name: str,
    pipeline_vars: PipelineVars,
    source_artifact: codepipeline.Artifact,
    docker_project: codebuild.PipelineProject,
    trivy_project: codebuild.PipelineProject,
    oci_signer_project: codebuild.PipelineProject,
    soci_index_project: codebuild.PipelineProject,
    oci_image_validation_project: codebuild.PipelineProject,
    docker_project_name: str,
):
    """
    Parameters:
        pipeline (codepipeline.Pipeline): The CodePipeline to add the Docker stage to
        stage_name (str): Base name for the stage
        pipeline_vars (PipelineVars): Configuration variables for the pipeline
        source_artifact (codepipeline.Artifact): The source code artifact to use as input
        docker_project (codebuild.PipelineProject): The CodeBuild project for Docker image building
        trivy_project (codebuild.PipelineProject): The CodeBuild project for Trivy security scanning
        oci_signer_project (codebuild.PipelineProject): The CodeBuild project for OCI image signing
        soci_index_project (codebuild.PipelineProject): The CodeBuild project for SOCI indexing
        oci_image_validation_project (codebuild.PipelineProject): The CodeBuild project for OCI image validation
        docker_project_name (str): Name identifier for the Docker project

    Functionality:
        Adds a complete Docker build and validation pipeline stage to an AWS CodePipeline.
        The stage includes sequential actions for:
        1. Building the Docker image (run_order=1)
        2. Signing the OCI image and creating SOCI indexes (run_order=2)
        3. Running Trivy security scans and OCI image validation (run_order=3)

        All actions use the same source artifact and default environment variables.
    """
    pipeline.add_stage(
        stage_name=f"{stage_name}-{pipeline_vars.project}-{docker_project_name}-docker-stage",
        actions=[  # type: ignore
            codepipeline_actions.CodeBuildAction(
                input=source_artifact,
                type=codepipeline_actions.CodeBuildActionType.BUILD,
                environment_variables=default_environment_variables(pipeline_vars),
                project=docker_project,  # type: ignore
                action_name="docker",
                run_order=1,
            ),
            codepipeline_actions.CodeBuildAction(
                input=source_artifact,
                type=codepipeline_actions.CodeBuildActionType.BUILD,
                environment_variables=default_environment_variables(pipeline_vars),
                project=oci_signer_project,  # type: ignore
                action_name="oci_signer",
                run_order=2,
            ),
            codepipeline_actions.CodeBuildAction(
                input=source_artifact,
                type=codepipeline_actions.CodeBuildActionType.BUILD,
                environment_variables=default_environment_variables(pipeline_vars),
                project=soci_index_project,  # type: ignore
                action_name="soci_index",
                run_order=2,
            ),
            codepipeline_actions.CodeBuildAction(
                input=source_artifact,
                type=codepipeline_actions.CodeBuildActionType.BUILD,
                environment_variables=default_environment_variables(pipeline_vars),
                project=trivy_project,  # type: ignore
                action_name="trivy_scan",
                run_order=2,
            ),
            codepipeline_actions.CodeBuildAction(
                input=source_artifact,
                type=codepipeline_actions.CodeBuildActionType.BUILD,
                environment_variables=default_environment_variables(pipeline_vars),
                project=oci_image_validation_project,  # type: ignore
                action_name="oci_image_validation",
                run_order=3,
            ),
        ],
    )
