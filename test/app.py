# -*- coding: utf-8 -*-
"""Main app."""

import aws_cdk as cdk

from test.test_s3_stack import TestS3Stack
from test.test_sns_stack import TestSNSStack


app = cdk.App()
TestS3Stack(app, "TestS3Stack")
TestSNSStack(app, "TestSNSStack")

app.synth()
