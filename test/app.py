# -*- coding: utf-8 -*-
"""Main app."""

import aws_cdk as cdk

from test.test_s3_stack import TestS3Stack
from test.test_sns_stack import TestSNSStack
from test.test_lmb_stack import TestAWSPythonLambdaFunctionStack

app = cdk.App()
TestS3Stack(app, "TestS3Stack")
TestSNSStack(app, "TestSNSStack")
TestAWSPythonLambdaFunctionStack(
    app,
    "TestAWSLambdaFunctionStack",
    env=cdk.Environment(account="123456789012", region="eu-west-1"),
    props={"stage": "dev", "project": "test_project", "service_name": "example_lambda_function"},
)

app.synth()
