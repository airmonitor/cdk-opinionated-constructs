#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main app."""

import aws_cdk as cdk

from test.test_s3_stack import TestS3Stack


app = cdk.App()
TestS3Stack(app, "TestS3Stack")

app.synth()
