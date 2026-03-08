## [4.7.37] - 2026-02-05

### ⚙️ Miscellaneous Tasks

- *(setup)* Bump version to 4.7.37 and fix formatting

## [4.7.36] - 2026-02-03

### 🚀 Features

- *(stacks)* \[**breaking**\] Export create_pipeline_notifications helper

## [4.7.35] - 2026-02-02

### 🚜 Refactor

- *(stacks)* Extract notification helpers to dedicated module

## [4.7.34] - 2026-01-30

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.235.1 to 2.236.0 in /test
- *(deps)* Bump constructs from 10.4.4 to 10.4.5 in /test
- *(deps)* Bump aws-cdk-lib from 2.234.1 to 2.235.1 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test

### ⚙️ Miscellaneous Tasks

- *(test)* Add nosec annotation to password field in wafv2 stack

## [4.7.33] - 2026-01-11

### ⚙️ Miscellaneous Tasks

- *(utils)* Rename pip_audit_files to pip_audit and bump version

## [4.7.32] - 2026-01-11

### 📚 Documentation

- *(utils)* Add comprehensive documentation for pip_audit_checker
- *(utils)* Add penetration test report for pip_audit_checker

### 🧪 Testing

- *(utils)* Add comprehensive unit tests for pip_audit_checker module

### ⚙️ Miscellaneous Tasks

- *(test)* Update test paths in Makefile
- *(lint)* Ignore assert and subprocess import in test files

## [4.7.31] - 2026-01-11

### 🚀 Features

- *(utils)* Add pip_audit_checker module for security vulnerability scanning

### ⚙️ Miscellaneous Tasks

- *(test)* Add nosec comment for bandit B106 security check
- *(pre-commit)* Downgrade ruff from v0.14.11 to v0.14.10
- *(pre-commit)* Update tool versions and security checks

## [4.7.30] - 2026-01-06

### 🐛 Bug Fixes

- *(s3)* Narrow return type from union to concrete bucket type

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.232.2 to 2.233.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test

### ⚙️ Miscellaneous Tasks

- *(pre-commit)* Add python-safety-dependencies-check hook

## [4.7.29] - 2025-12-19

### 📚 Documentation

- *(guidelines)* Add comprehensive development guidelines

### 🎨 Styling

- *(trivy_scanner)* Wrap multi-line f-strings in parentheses for readability
- *(soci_index)* Wrap multi-line f-strings in parentheses for readability
- *(oci_signer)* Wrap multi-line f-strings in parentheses for readability
- *(pipeline)* Wrap multi-line f-strings in parentheses for readability
- *(pipeline)* Wrap multi-line f-strings in parentheses for readability
- *(pipeline)* Wrap multi-line f-strings in parentheses for readability
- *(stages)* Wrap multi-line f-strings in parentheses for improved readability
- *(test)* Reorganize imports in test infrastructure files
- *(imports)* Organize imports and fix quote style in test stacks

### ⚙️ Miscellaneous Tasks

- *(release)* Bump version to 4.7.29
- *(makefile)* Extend pre-commit checks to stages/logic and test directories
- *(pre-commit)* Exclude test directory from bandit and detect-secrets
- *(pre-commit)* Configure large file check and bump ruff

## [4.7.28] - 2025-12-17

### 💼 Other

- *(deps)* Bump constructs from 10.4.3 to 10.4.4 in /test
- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.232.1 to 2.232.2 in /test

### ⚙️ Miscellaneous Tasks

- *(pipeline_v2,stages)* Bump Trivy version to 0.68.2

## [4.7.27] - 2025-12-12

### 🎨 Styling

- *(pipeline_v2)* Reorder function parameters for consistency

## [4.7.26] - 2025-12-09

### ⚙️ Miscellaneous Tasks

- *(pipeline_v2,stages)* Remove privileged mode from build environments

## [4.7.25] - 2025-12-08

### ⚙️ Miscellaneous Tasks

- *(pipeline_v2)* Remove privileged mode from Trivy scanner build environment

## [4.7.24] - 2025-12-08

### 💼 Other

- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps-dev)* Bump pytest from 9.0.1 to 9.0.2 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test

### ⚙️ Miscellaneous Tasks

- *(stages)* Bump ORAS version to 1.3.0

## [4.7.23] - 2025-12-08

### 🚀 Features

- *(oci_signer)* \[**breaking**\] Update ORAS commands for v1.3.0 compatibility

### ⚙️ Miscellaneous Tasks

- *(pipeline_v2)* Bump tool versions

## [4.7.22] - 2025-12-07

### ⚙️ Miscellaneous Tasks

- *(pipeline_v2)* Remove SSM parameter support for CodeBuild fleet

## [4.7.21] - 2025-12-06

### 🚀 Features

- *(pipeline_v2)* Add SSM parameter support for CodeBuild image tag

## [4.7.20] - 2025-12-06

### 🚀 Features

- *(pipeline_v2)* Add SSM parameter support for CodeBuild fleet configuration

## [4.7.19] - 2025-12-05

### 🚜 Refactor

- *(docker)* Restructure for improved maintainability and testability
- *(oci_image_validation)* Restructure for improved maintainability and testability
- *(oci_signer)* Restructure for improved maintainability and testability
- *(soci_index)* Restructure for improved maintainability and testability

## [4.7.17] - 2025-12-04

### 🚜 Refactor

- *(docker)* Consolidate install config and clean up imports

## [4.7.16] - 2025-12-04

### 🚜 Refactor

- *(pipeline_v2)* Restructure trivy scanner for improved maintainability

## [4.7.15] - 2025-12-03

### 🚜 Refactor

- *(pipeline_v2)* Extract install and fleet configs to functions

## [4.7.14] - 2025-12-03

### 🚜 Refactor

- *(pipeline_v2)* Extract reusable build configuration functions

## [4.7.13] - 2025-12-03

### 🚜 Refactor

- *(docker)* Extract fleet and install configs to functions

## [4.7.11] - 2025-12-03

### 🚜 Refactor

- *(pipeline)* Extract fleet and install configs to functions

## [4.7.10] - 2025-12-03

### 🚜 Refactor

- *(pipeline)* Extract install configs for conditional docker support

## [4.7.9] - 2025-12-03

### 🚜 Refactor

- *(pipeline)* Extract install configs for conditional docker support
- *(pipeline)* Simplify trivy scanner script execution

## [4.7.8] - 2025-12-02

### ⚙️ Miscellaneous Tasks

- *(pipeline)* Bump version to 4.7.8

## [4.7.7] - 2025-12-02

### 🚜 Refactor

- *(stages)* Enforce keyword-only arguments in build functions

## [4.7.6] - 2025-12-02

### 🚜 Refactor

- *(stages)* Enhance build image selection with architecture support

## [4.7.5] - 2025-12-02

### 🚜 Refactor

- *(stages)* Extract codebuild image selection logic

## [4.7.4] - 2025-12-02

### 🚀 Features

- *(stages)* Add codebuild build environment configuration

### 💼 Other

- *(deps)* Bump cdk-opinionated-constructs in /test

## [4.7.3] - 2025-12-01

### 🚀 Features

- *(stages)* Add configurable compute type for codebuild steps

### 💼 Other

- *(deps-dev)* Bump pytest from 8.4.2 to 9.0.1 in /test

## [4.7.2] - 2025-11-28

### 🐛 Bug Fixes

- *(wafv2)* Adjust bot control rule priority from 7 to 9

## [4.7.1] - 2025-11-28

### 🚀 Features

- *(utils)* Add cross-region SSM parameter retrieval

## [4.6.1] - 2025-11-25

### 🚀 Features

- *(pipeline)* Optimize docker build with image cache

## [4.6.0] - 2025-11-25

### 🚀 Features

- *(pipeline)* Add codebuild fleet support to oci image validation
- *(pipeline)* Add codebuild fleet support to docker builder
- *(pipeline)* Add codebuild fleet support to lambda builder

## [4.5.17] - 2025-11-24

### 🚀 Features

- *(pipeline)* Add auto-retry limit to codebuild projects

### 💼 Other

- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.225.0 to 2.228.0 in /test

## [4.5.16] - 2025-11-18

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.223.0 to 2.224.0 in /test
- *(deps)* Bump constructs from 10.4.2 to 10.4.3 in /test
- *(deps)* Bump aws-cdk-lib from 2.221.1 to 2.223.0 in /test
- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump cdk-opinionated-constructs in /test

### 📚 Documentation

- *(alb)* Update docstring for add_connections method

## [4.5.15] - 2025-10-30

### 🐛 Bug Fixes

- *(deps)* Update Trivy scanner version to 0.67.2

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.220.0 to 2.221.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump cdk-nag from 2.37.51 to 2.37.55 in /test
- *(deps)* Bump aws-cdk-lib from 2.219.0 to 2.220.0 in /test
- *(deps)* Bump cdk-nag from 2.37.49 to 2.37.51 in /test

## [4.5.14] - 2025-10-10

### 🐛 Bug Fixes

- Update package version to 4.5.14
- *(deps)* Update Trivy scanner version to 0.67.1
- *(deps)* Update cdk-opinionated-constructs to 4.5.13 in test requirements
- *(deps)* Update CDK dependencies to latest versions
- *(deps)* Update ruff and uv-secure pre-commit hook versions

### 💼 Other

- *(deps)* Bump cdk-nag from 2.37.39 to 2.37.45 in /test
- *(deps)* Bump aws-cdk-lib from 2.218.0 to 2.219.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test

## [4.5.13] - 2025-09-30

### 💼 Other

- *(deps)* Bump cdk-nag from 2.37.27 to 2.37.38 in /test
- *(deps)* Bump aws-cdk-lib from 2.216.0 to 2.218.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.214.0 to 2.216.0 in /test
- *(deps)* Bump cdk-nag from 2.37.20 to 2.37.27 in /test
- *(deps)* Bump cdk-nag from 2.37.15 to 2.37.20 in /test
- *(deps-dev)* Bump pytest from 8.4.1 to 8.4.2 in /test

## [4.5.11] - 2025-09-03

### 💼 Other

- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.210.0 to 2.212.0 in /test
- *(deps)* Bump cdk-nag from 2.37.0 to 2.37.9 in /test
- *(deps)* Bump aws-cdk-lib from 2.209.1 to 2.210.0 in /test
- *(deps)* Bump cdk-nag from 2.36.55 to 2.37.0 in /test

## [4.5.7] - 2025-08-06

### 💼 Other

- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.206.0 to 2.208.0 in /test
- *(deps)* Bump cdk-nag from 2.36.42 to 2.36.53 in /test

## [4.5.3] - 2025-07-23

### 🚀 Features

- *(pipeline)* Improve timestamp handling for Docker images and SSM parameters

## [4.5.2] - 2025-07-23

### 🚀 Features

- *(pipeline)* Add timestamp to Docker image tags and parameters

## [4.5.0] - 2025-07-22

### 🚀 Features

- *(pipeline)* Add container image signing, validation, and vulnerability scanning

## [4.4.2] - 2025-07-21

### 💼 Other

- *(deps)* Bump cdk-nag from 2.36.34 to 2.36.38 in /test
- *(deps)* Bump cdk-nag from 2.36.30 to 2.36.34 in /test
- *(deps)* Bump aws-cdk-lib from 2.202.0 to 2.204.0 in /test
- *(deps)* Bump cdk-nag from 2.36.23 to 2.36.30 in /test
- *(deps)* Bump aws-cdk-lib from 2.201.0 to 2.202.0 in /test
- *(deps-dev)* Bump pytest from 8.4.0 to 8.4.1 in /test
- *(deps)* Bump cdk-nag from 2.36.18 to 2.36.23 in /test
- *(deps)* Bump cdk-nag from 2.36.13 to 2.36.18 in /test
- *(deps)* Bump aws-cdk-lib from 2.200.1 to 2.201.0 in /test

## [4.4.0] - 2025-06-12

### 🚀 Features

- *(pipeline)* Add MS Teams notification support and enhance chatbot integration

### 🐛 Bug Fixes

- *(stacks)* Update type annotation for pipeline_notifications function
- *(stacks)* Correct type annotation for pipeline notifications parameter

### 💼 Other

- *(deps)* Bump cdk-nag from 2.36.12 to 2.36.13 in /test
- *(deps-dev)* Bump pytest from 8.3.5 to 8.4.0 in /test

## [4.3.4] - 2025-06-07

### 🚀 Features

- *(pipeline)* Add image tag parameter support and bump version to 4.3.4

## [4.3.2] - 2025-06-07

### 🚀 Features

- *(pipeline)* Update dependencies and bump version to 4.3.3
- *(logic)* Enhance IAM permissions for CodeBuild projects

## [4.3.1] - 2025-06-06

### 🚀 Features

- *(alb)* Add stickiness support and update pipeline dependencies

## [4.3.0] - 2025-06-05

### 🚀 Features

- *(waf)* Add rules for PHP applications and POSIX OS protection

## [4.2.7] - 2025-06-03

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.198.0 to 2.199.0 in /test
- *(deps)* Bump cdk-nag from 2.35.107 to 2.36.6 in /test

## [4.2.6] - 2025-06-03

### 🚀 Features

- *(pipeline)* Enhance Trivy scanner with SBOM support and update tooling

## [4.2.5] - 2025-06-01

### ⚙️ Miscellaneous Tasks

- *(pipeline)* Bump default versions for constructs and setup.py

## [4.2.3] - 2025-06-01

### 🚜 Refactor

- *(logic)* Replace `cdk.Environment` with `Environment` in imports

## [4.2.2] - 2025-06-01

### ⚙️ Miscellaneous Tasks

- *(pipeline)* Bump versions for cdk_opinionated_constructs and Trivy
- *(pre-commit)* Update hook versions for tooling improvements

## [4.2.1] - 2025-05-30

### 🚜 Refactor

- *(pipeline)* Update module imports to use consistent paths

## [4.2.0] - 2025-05-30

### 🚀 Features

- *(cdk)* Introduce opinionated constructs for Docker, Lambda, and OCI pipelines

## [4.1.4] - 2025-05-28

### 🚀 Features

- *(tooling)* Update pre-commit hooks and refine Trivy JSON parser

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.196.0 to 2.198.0 in /test
- *(deps)* Bump cdk-nag from 2.35.101 to 2.35.106 in /test
- *(deps)* Bump cdk-nag from 2.35.95 to 2.35.101 in /test
- *(deps)* Bump aws-cdk-lib from 2.195.0 to 2.196.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.194.0 to 2.195.0 in /test
- *(deps)* Bump cdk-nag from 2.35.89 to 2.35.95 in /test
- *(deps)* Bump cdk-nag from 2.35.82 to 2.35.89 in /test
- *(deps)* Bump aws-cdk-lib from 2.192.0 to 2.194.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.190.0 to 2.192.0 in /test
- *(deps)* Bump cdk-nag from 2.35.76 to 2.35.82 in /test
- *(deps)* Bump cdk-nag from 2.35.69 to 2.35.76 in /test
- *(deps)* Bump aws-cdk-lib from 2.189.0 to 2.190.0 in /test

## [3.1.3] - 2025-04-15

### 🚀 Features

- *(security)* Enhance Trivy container scan reporting to Security Hub
- *(runtime)* \[**breaking**\] Upgrade Python runtime from 3.11 to 3.13 (#427)

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.188.0 to 2.189.0 in /test
- *(deps)* Bump cdk-nag from 2.35.65 to 2.35.69 in /test
- *(deps)* Bump cdk-nag from 2.35.59 to 2.35.65 in /test
- *(deps)* Bump aws-cdk-lib from 2.186.0 to 2.188.0 in /test
- *(deps)* Bump cdk-nag from 2.35.54 to 2.35.59 in /test
- *(deps)* Bump aws-cdk-lib from 2.185.0 to 2.186.0 in /test
- *(deps)* Bump cdk-nag from 2.35.47 to 2.35.54 in /test
- *(deps)* Bump aws-cdk-lib from 2.184.1 to 2.185.0 in /test

## [4.1.2] - 2025-03-24

### 🚀 Features

- *(s3)* \[**breaking**\] Add specialized S3 bucket creation for CloudFront distributions (#414)

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.182.0 to 2.184.1 in /test
- *(deps)* Bump cdk-nag from 2.35.41 to 2.35.47 in /test
- *(deps)* Bump aws-cdk-lib from 2.181.1 to 2.182.0 in /test
- *(deps)* Bump cdk-nag from 2.35.35 to 2.35.41 in /test
- *(deps)* Bump cdk-nag from 2.35.29 to 2.35.35 in /test
- *(deps)* Bump aws-cdk-lib from 2.180.0 to 2.181.1 in /test
- *(deps-dev)* Bump pytest from 8.3.4 to 8.3.5 in /test
- *(deps)* Bump cdk-nag from 2.35.22 to 2.35.29 in /test
- *(deps)* Bump aws-cdk-lib from 2.178.2 to 2.180.0 in /test
- *(deps)* Bump cdk-nag from 2.35.14 to 2.35.22 in /test
- *(deps)* Bump aws-cdk-lib from 2.178.1 to 2.178.2 in /test

## [4.1.1] - 2025-03-24

### 🚀 Features

- *(runtime)* \[**breaking**\] Upgrade Python runtime from 3.11 to 3.13

## [3.15.11] - 2025-02-15

### 🚀 Features

- *(s3)* Add specialized S3 bucket creation for CloudFront distributions

## [3.15.10] - 2025-02-15

### 🚀 Features

- *(s3)* Add specialized S3 bucket creation for CloudFront distributions

## [3.15.8] - 2025-02-12

### 🐛 Bug Fixes

- *(lambda)* \[**breaking**\] Downgrade Python runtime from 3.13 to 3.11 (#411)

## [3.15.6] - 2025-02-12

### 🚀 Features

- *(lambda)* Add ephemeral storage support and enhance documentation

## [3.15.5] - 2025-02-12

### 🐛 Bug Fixes

- *(lambda)* Downgrade Python runtime from 3.13 to 3.11

## [3.15.4] - 2025-02-12

### 🐛 Bug Fixes

- *(alb)* \[**breaking**\] Update health check path parameter name

## [3.15.3] - 2025-02-12

### ⚙️ Miscellaneous Tasks

- *(ci)* Upgrade GitHub Actions artifacts dependencies to v4

## [3.15.0] - 2025-02-12

### 🚀 Features

- *(alb)* Enhance ALB with health checks and load balancing improvements

### 💼 Other

- *(deps)* Bump cdk-nag from 2.35.8 to 2.35.14 in /test
- *(deps)* Bump aws-cdk-lib from 2.177.0 to 2.178.1 in /test
- *(deps)* Bump cdk-nag from 2.35.1 to 2.35.8 in /test
- *(deps)* Bump aws-cdk-lib from 2.176.0 to 2.177.0 in /test
- *(deps)* Bump cdk-nag from 2.34.23 to 2.35.1 in /test
- *(deps)* Bump aws-cdk-lib from 2.175.1 to 2.176.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.174.0 to 2.175.1 in /test
- *(deps)* Bump aws-cdk-lib from 2.173.4 to 2.174.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.173.2 to 2.173.4 in /test

### ⚙️ Miscellaneous Tasks

- *(security)* Enhance code security with additional pre-commit hooks

## [3.14.3] - 2024-12-27

### 🐛 Bug Fixes

- *(security)* Add explicit region handling for SecurityHub integration

## [3.14.0] - 2024-12-27

### 🚀 Features

- *(security)* Add Trivy container scan results parser for Security Hub

## [4.1.0] - 2024-12-27

### 🚀 Features

- *(security)* Add Trivy container scan results parser for Security Hub
- \[**breaking**\] Upgrade Python runtime to 3.13 and bump version to 4.0.0 (#380)

### 💼 Other

- *(deps)* Bump aws-cdk-lib from 2.173.1 to 2.173.2 in /test
- *(deps)* Bump cdk-nag from 2.34.20 to 2.34.23 in /test
- *(deps)* Bump aws-cdk-lib from 2.172.0 to 2.173.1 in /test
- *(deps-dev)* Bump pytest from 8.3.3 to 8.3.4 in /test
- *(deps)* Bump cdk-nag from 2.34.6 to 2.34.20 in /test
- *(deps)* Bump aws-cdk-lib from 2.171.0 to 2.172.0 in /test
- *(deps)* Bump cdk-nag from 2.34.2 to 2.34.6 in /test
- *(deps)* Bump aws-cdk-lib from 2.167.1 to 2.171.0 in /test
- *(deps)* Bump cdk-nag from 2.32.2 to 2.34.2 in /test
- *(deps)* Bump aws-cdk-lib from 2.166.0 to 2.167.1 in /test

## [3.13.1] - 2024-11-14

### 🚀 Features

- *(version)* Bump to 3.12.1 and remove unused test file (#366)
- *(notifications)* \[**breaking**\] Add Microsoft Teams support to NotificationsStack (#333)
- *(wafv2)* Add AWS Bot Control rule option to WebACL (#332)
- *(tests)* Add retry logic for CloudWatch metric retrieval (#330)
- *(integration-tests)* Add configurable time range for Step Functions metrics (#325)
- *(lambda-metrics)* Add configurable time range for metric retrieval (#324)
- *(integration-tests)* Add Step Functions execution monitoring scripts (#315)

### 🐛 Bug Fixes

- *(pipeline)* Update MS Teams notification configuration (#335)
- *(lambda)* Change metric name from Invocations to Errors (#331)

### 💼 Other

- *(deps)* Bump cdk-monitoring-constructs from 8.3.5 to 8.3.6 in /test
- *(deps)* Bump cdk-nag from 2.31.2 to 2.32.2 in /test
- *(deps)* Bump aws-cdk-lib from 2.165.0 to 2.166.0 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.3.3 to 8.3.5 in /test
- *(deps)* Bump cdk-nag from 2.29.12 to 2.31.2 in /test
- *(deps)* Bump aws-cdk-lib from 2.164.1 to 2.165.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.162.1 to 2.164.1 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.3.2 to 8.3.3 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.3.1 to 8.3.2 in /test
- *(deps)* Bump cdk-nag from 2.29.6 to 2.29.12 in /test
- *(deps)* Bump cdk-nag from 2.28.196 to 2.29.6 in /test
- *(deps)* Bump constructs from 10.3.0 to 10.4.2 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.161.1 to 2.162.1 in /test
- *(deps)* Bump aws-cdk-lib from 2.159.1 to 2.161.1 in /test
- *(deps)* Bump cdk-nag from 2.28.195 to 2.28.196 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.3.0 to 8.3.1 in /test
- *(deps)* Bump aws-cdk-lib from 2.158.0 to 2.159.1 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.2.0 to 8.3.0 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.1.1 to 8.2.0 in /test
- *(deps-dev)* Bump pytest from 8.3.2 to 8.3.3 in /test
- *(deps)* Bump aws-cdk-lib from 2.156.0 to 2.158.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.155.0 to 2.156.0 in /test
- *(deps)* Bump cdk-nag from 2.28.189 to 2.28.195 in /test
- *(deps)* Bump aws-cdk-lib from 2.154.1 to 2.155.0 in /test
- *(deps)* Bump cdk-nag from 2.28.183 to 2.28.189 in /test
- *(deps)* Bump aws-cdk-lib from 2.152.0 to 2.154.1 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.1.0 to 8.1.1 in /test
- *(deps)* Bump cdk-nag from 2.28.177 to 2.28.183 in /test
- *(deps)* Bump aws-cdk-lib from 2.151.0 to 2.152.0 in /test
- *(deps)* Bump cdk-nag from 2.28.173 to 2.28.177 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.0.1 to 8.1.0 in /test
- *(deps)* Bump cdk-nag from 2.28.168 to 2.28.173 in /test
- *(deps)* Bump aws-cdk-lib from 2.150.0 to 2.151.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.149.0 to 2.150.0 in /test
- *(deps-dev)* Bump pytest from 8.3.1 to 8.3.2 in /test
- *(deps)* Bump cdk-nag from 2.28.163 to 2.28.168 in /test
- *(deps)* Bump cdk-nag from 2.28.159 to 2.28.163 in /test
- *(deps-dev)* Bump pytest from 8.2.2 to 8.3.1 in /test
- *(deps)* Bump cdk-monitoring-constructs from 8.0.0 to 8.0.1 in /test
- *(deps)* Bump aws-cdk-lib from 2.148.0 to 2.149.0 in /test
- *(deps)* Bump cdk-nag from 2.28.157 to 2.28.159 in /test
- *(deps)* Bump cdk-nag from 2.28.156 to 2.28.157 in /test
- *(deps)* Bump aws-cdk-lib from 2.147.3 to 2.148.0 in /test
- *(deps)* Bump cdk-opinionated-constructs in /test
- *(deps)* Bump cdk-nag from 2.28.148 to 2.28.154 in /test
- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump aws-cdk-lib from 2.147.0 to 2.147.2 in /test
- *(deps)* Bump cdk-nag from 2.28.144 to 2.28.148 in /test
- *(deps)* Bump aws-cdk-lib from 2.146.0 to 2.147.0 in /test
- *(deps)* Bump aws-cdk-lib from 2.145.0 to 2.146.0 in /test
- *(deps)* Bump cdk-nag from 2.28.139 to 2.28.144 in /test
- *(deps-dev)* Bump pytest from 8.2.1 to 8.2.2 in /test
- *(deps)* Bump aws-cdk-lib from 2.144.0 to 2.145.0 in /test
- *(deps)* Bump cdk-nag from 2.28.132 to 2.28.139 in /test
- *(deps)* Bump aws-cdk-lib from 2.143.0 to 2.144.0 in /test
- *(deps)* Bump cdk-nag from 2.28.125 to 2.28.132 in /test
- *(deps)* Bump cdk-monitoring-constructs in /test
- *(deps)* Bump cdk-nag from 2.28.118 to 2.28.125 in /test
- *(deps)* Bump aws-cdk-lib from 2.142.1 to 2.143.0 in /test

### 🚜 Refactor

- *(notifications)* \[**breaking**\] Simplify MS Teams integration and update stack initialization (#359)
- *(notifications)* Improve pipeline notification configuration (#334)

## [3.7.3] - 2024-05-09

### 🚀 Features

- *(pipeline)* Expand CodePipeline SNS event notifications (#291)

## [3.7.2] - 2024-04-25

### 🚀 Features

- *(pipeline)* Add new CodePipeline execution event notifications (#284)
- *(pipeline-notifications)* Enhance pipeline notifications configuration (#283)

## [0.1.0] - 2022-11-05
