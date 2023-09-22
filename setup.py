# -*- coding: utf-8 -*-
"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
"""

from setuptools import setup, find_packages

setup(
    name="cdk-opinionated-constructs",
    version="3.1.0",
    description="AWS CDK constructs come without added security configurations.",
    long_description="The idea behind this project is to create secured constructs from the start. \n"
    "Supported constructs: ALB, ECR, LMB, NLB, S3, SNS, WAF, RDS",
    license="MIT",
    package_dir={"": "."},
    packages=find_packages(where="."),
    install_requires=[
        "aws-cdk-lib>=2.93.0",
        "constructs>=10.2.69,<11.0.0",
        "cdk-monitoring-constructs>=4.0.0,<6.0.0",
    ],
    python_requires=">=3.11",
)
