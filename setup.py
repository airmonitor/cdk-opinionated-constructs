"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
"""

from setuptools import find_packages, setup

setup(
    name="cdk-opinionated-constructs",
    version="4.2.6",
    description="AWS CDK constructs come without added security configurations.",
    long_description="The idea behind this project is to create secured constructs from the start. \n"
    "Supported constructs: ALB, ECR, LMB, NLB, S3, SNS, WAF, RDS",
    license="MIT",
    package_dir={"": "."},
    packages=find_packages(where="."),
    install_requires=[
        "aws-cdk-lib>=2.177.0",
        "constructs>=10.4.2",
        "cdk-monitoring-constructs>=6.0.0",
        "pydantic>=2.9.0",
        "pydantic-core>=2.23.0",
        "pyyaml>=6.0.0",
        "tenacity>=8.0.1",
        "click>=8.1.3",
        "typeguard~=2.13.3",
    ],
    python_requires=">=3.11",
)
