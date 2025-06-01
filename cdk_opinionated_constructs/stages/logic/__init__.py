from typing import Any, Literal

import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_codepipeline as codepipeline
import aws_cdk.aws_codepipeline_actions as codepipeline_actions
import aws_cdk.aws_iam as iam

from aws_cdk import Environment
from cdk.schemas.configuration_vars import PipelineVars

runtime_versions = {"nodejs": "22", "python": "3.13"}
default_install_commands = [
    "npm install -g aws-cdk",
    "pip install uv",
    "make install",
]

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
        env (Environment): The CDK environment object containing account and region information

    Functionality:
        Applies a comprehensive set of default IAM permissions to a CodeBuild pipeline project to enable CDK operations.
        The function adds multiple policy statements to the project's role, including:
        - S3 permissions for CDK asset operations (GetObject, PutObject, ListBucket, GetBucketLocation)
        - STS permissions for role assumption and session tagging
        - SSM permissions for parameter retrieval
        - CloudFormation permissions for stack management operations
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
            actions=["ssm:GetParameter"],
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


def default_environment_variables(pipeline_vars: PipelineVars) -> dict[str, Any]:  # noqa: ARG001
    """Returns a dictionary of default environment variables for a CodeBuild project."""
    return {}


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
