# -*- coding: utf-8 -*-
"""Main app."""

import aws_cdk as cdk
import os
from stacks.test_s3_stack import TestS3Stack
from stacks.test_sns_stack import TestSNSStack
from stacks.test_lmb_stack import TestAWSPythonLambdaFunctionStack
from stacks.test_wafv2_stack import TestWAFv2Stack
from stacks.alb_stack import TestALBStack


CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])

app = cdk.App()
TestS3Stack(app, "TestS3Stack")
TestSNSStack(app, "TestSNSStack")
TestAWSPythonLambdaFunctionStack(
    app,
    "TestAWSLambdaFunctionStack",
    env=CDK_ENV,
    props={"stage": "dev", "project": "test_project", "service_name": "example_lambda_function"},
)
TestWAFv2Stack(app, "TestWAFv2Stack")
TestALBStack(app, "TestALBStack", env=CDK_ENV)

app.synth()
