# -*- coding: utf-8 -*-
"""Test AWS Lambda function construct against cdk-nag."""
from aws_cdk import Stack
from constructs import Construct
from cdk_opinionated_constructs.lmb import AWSPythonLambdaFunction
import aws_cdk.aws_lambda as lmb

from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks, NagSuppressions


class TestAWSPythonLambdaFunctionStack(Stack):
    """Test generated sns topic against AWS solutions  checks."""

    def __init__(self, scope: Construct, construct_id: str, env, props, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lmb_construct = AWSPythonLambdaFunction(self, id="lmb_construct")
        lmb_signing_profile = lmb_construct.signing_profile(signing_profile_name="signing_profile_name")
        lmb_signing = lmb_construct.signing_config(lmb_signing_profile)
        lmb_construct.create_lambda_function(
            code_path=f'{props["service_name"]}',
            env=env,
            function_name=props["service_name"],
            timeout=6,
            layer=lmb.LayerVersion.from_layer_version_arn(
                self,
                id="aws_lambda_powertools_layer",
                layer_version_arn="arn:aws:lambda:eu-west-1:123456789012:layer:aws-lambda-powertools-python-layer:1",
            ),
            env_variables={
                "POWERTOOLS_SERVICE_NAME": props["service_name"],
                "LOG_LEVEL": "DEBUG",
            },
            reserved_concurrent_executions=1,
            signing_config=lmb_signing,
        )

        # Validate stack against AWS Solutions checklist
        nag_suppression_rule_list = self.nag_suppression()
        NagSuppressions.add_stack_suppressions(self, nag_suppression_rule_list)
        Aspects.of(self).add(AwsSolutionsChecks(log_ignores=True))

    @staticmethod
    def nag_suppression() -> list:
        """Create CFN-NAG suppression.

        :return:
        """
        return [
            {
                "id": "AwsSolutions-IAM4",
                "reason": "Using managed policies is allowed",
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "There isn't a way to tailor IAM policy using more restrictive permissions for "
                "used API calls logs:CreateLogGroup, xray:PutTelemetryRecords, xray:PutTraceSegments",
            },
        ]
