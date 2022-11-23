# -*- coding: utf-8 -*-
"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
"""

from setuptools import setup, find_packages

setup(
    name="cdk-opinionated-constructs",
    version="1.9.1",
    description="AWS CDK constructs come without added security configurations.",
    long_description="Very rarely this is validated during the CI pipeline via tools like CDK-NAG. The idea behind this project is to create secured constructs from the start.",
    license="MIT",
    package_dir={"": "."},
    packages=find_packages(where="."),
    install_requires=[
        "aws-cdk-lib>=2.51.1",
        "constructs>=10.0.0,<11.0.0",
    ],
    python_requires=">=3.9",
)
