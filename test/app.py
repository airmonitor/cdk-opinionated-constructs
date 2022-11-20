# -*- coding: utf-8 -*-
"""Main app."""

import aws_cdk as cdk
import os
from stacks.s3_stack import TestS3Stack
from stacks.sns_stack import TestSNSStack
from stacks.lmb_stack import TestAWSPythonLambdaFunctionStack
from stacks.wafv2_stack import TestWAFv2Stack
from stacks.alb_stack import TestALBStack
from stacks.ecr_stack import TestECRStack


CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])

app = cdk.App()
TestS3Stack(app, "TestS3Stack")
TestSNSStack(app, "TestSNSStack")
TestAWSPythonLambdaFunctionStack(
    app,
    "TestAWSLambdaFunctionStack",
    env=CDK_ENV,
    props={"project": "test_project", "service_name": "example_lambda_function"},
)
TestWAFv2Stack(app, "TestWAFv2Stack", env=CDK_ENV)
TestALBStack(app, "TestALBStack", env=CDK_ENV)
TestECRStack(app, "TestECRStack", env=CDK_ENV)

app.synth()
