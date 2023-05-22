# -*- coding: utf-8 -*-
"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
"""

from setuptools import setup, find_packages

setup(
    name="cdk-opinionated-constructs",
    version="2.1.3",
    description="AWS CDK constructs come without added security configurations.",
    long_description="The idea behind this project is to create secured constructs from the start. \n"
    "Supported constructs: ALB, ECR, LMB, NLB, S3, SNS, WAF, RDS",
    license="MIT",
    package_dir={"": "."},
    packages=find_packages(where="."),
    install_requires=[
        "aws-cdk-lib>=2.69.0",
        "constructs>=10.1.232,<11.0.0",
        "cdk-monitoring-constructs>=3.0.0,<5.0.0",
    ],
    python_requires=">=3.10",
)
