"""Main app."""

import os

import aws_cdk as cdk

from stacks.alb_stack import TestALBStack
from stacks.ecr_stack import TestECRStack
from stacks.lmb_docker_stack import TestAWSLambdaDockerFunctionStack
from stacks.lmb_monitoring_stack import TestAWSPythonLambdaFunctionStackMonitoring
from stacks.lmb_stack import TestAWSPythonLambdaFunctionStack
from stacks.nlb_stack import TestNLBStack
from stacks.rds_mysql_stack import TestRDSMySQLStack
from stacks.rds_postgresql_stack import TestRDSPostgreSQLStack
from stacks.s3_stack import TestS3Stack
from stacks.sns_stack import TestSNSStack
from stacks.wafv2_stack import TestWAFv2Stack

CDK_ENV = cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"])

app = cdk.App()
TestS3Stack(app, "TestS3Stack")
TestSNSStack(app, "TestSNSStack")
TestLambdaStack = TestAWSPythonLambdaFunctionStack(
    app,
    "TestAWSLambdaFunctionStack",
    env=CDK_ENV,
    props={"project": "test_project", "service_name": "example_lambda_function"},
)
TestLambdaMonitoringStack = TestAWSPythonLambdaFunctionStackMonitoring(
    app,
    "TestAWSLambdaFunctionMonitoringStack",
    env=CDK_ENV,
    props=TestLambdaStack.output_props,
)
TestAWSPythonLambdaFunctionStack = TestAWSLambdaDockerFunctionStack(
    app,
    "TestAWSLambdaDockerFunctionStack",
    env=CDK_ENV,
    props={"project": "test_project", "service_name": "example_lambda_function"},
)
TestWAFv2Stack(app, "TestWAFv2Stack", env=CDK_ENV)
TestALBStack(app, "TestALBStack", env=CDK_ENV)
TestECRStack(app, "TestECRStack", env=CDK_ENV)
TestNLBStack(app, "TestNLBStack", env=CDK_ENV)
TestRDSPostgreSQLStack(app, "TestRDSPostgresSQLStack", env=CDK_ENV)
TestRDSMySQLStack(app, "TestRDSMySQLStack", env=CDK_ENV)

app.synth()
