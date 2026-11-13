"""Test AWS Lambda function construct."""

import aws_cdk.aws_lambda as lmb

from aws_cdk import Acknowledgment, Stack, Validations
from cdk_nag import AwsSolutionsChecks
from cdk_opinionated_constructs.lmb import AWSPythonLambdaFunction
from constructs import Construct


class TestAWSPythonLambdaFunctionStack(Stack):
    """Test generated sns topic against AWS solutions checks."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lmb_construct = AWSPythonLambdaFunction(self, id="lmb_construct")
        lmb_signing = lmb_construct.signing_config(signing_profile_name="signing_profile_name")
        lmb_function = lmb_construct.create_lambda_function(
            code_path=f"{props['service_name']}",
            env=env,
            function_name=props["service_name"],
            timeout=10,
            layers=[
                lmb.LayerVersion.from_layer_version_arn(
                    self,
                    id="aws_lambda_powertools_layer",
                    layer_version_arn="arn:aws:lambda:eu-west-1:123456789012:layer:aws-lambda-powertools-python-layer:1",
                )
            ],
            env_variables={
                "POWERTOOLS_SERVICE_NAME": props["service_name"],
                "LOG_LEVEL": "DEBUG",
            },
            reserved_concurrent_executions=1,
            signing_config=lmb_signing,
        )

        self.output_props = props.copy()
        self.output_props["lmb_function"] = lmb_function

        # Validate stack against AWS Solutions checklist
        nag_suppression_rule_list = self.nag_suppression()
        Validations.of(self).acknowledge(*nag_suppression_rule_list)
        Validations.of(self).add_plugins(AwsSolutionsChecks(self))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            Acknowledgment(
                id="AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/CloudWatchLambdaInsightsExecutionRolePolicy]",
                reason="Using managed policies is allowed",
            ),
            Acknowledgment(
                id="AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole]",
                reason="Using managed policies is allowed",
            ),
            Acknowledgment(
                id="AwsSolutions-IAM5[Resource::*]",
                reason="There isn't a way to tailor IAM policy using more restrictive "
                "permissions for used API calls logs:CreateLogGroup, "
                "xray:PutTelemetryRecords, xray:PutTraceSegments",
            ),
            Acknowledgment(
                id="AwsSolutions-IAM5[Resource::arn:aws:logs:*:*:log-group:/aws/lambda-insights:*]",
                reason="There isn't a way to tailor IAM policy using more restrictive "
                "permissions for used API calls logs:CreateLogGroup, "
                "xray:PutTelemetryRecords, xray:PutTraceSegments",
            ),
            Acknowledgment(id="AwsSolutions-L1", reason="The custom resource lambda runtime is managed by CDK itself"),
        ]

    @property
    def outputs(self):
        """Update props dictionary.

        :return: Updated props dict
        """
        return self.output_props
