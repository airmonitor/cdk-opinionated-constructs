# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`cdk-opinionated-constructs` is a Python package published to PyPI. It wraps AWS CDK L2/L3
constructs with security-hardened defaults so they pass `cdk-nag` compliance packs
(AwsSolutions, NIST 800-53 R5, PCI DSS 3.2.1, HIPAA) out of the box. Consumers `pip install`
it and `from cdk_opinionated_constructs.<module> import <Construct>`.

Python 3.13, `uv` for env/deps, `aws-cdk-lib>=2.177`, `pydantic>=2.9`.

## Commands

Everything runs inside the `uv`-managed `.venv`. Use `.venv/bin/python` / `.venv/bin/pytest`
directly, or `source .venv/bin/activate` first.

- `make venv` — create the virtualenv (`uv venv --seed --python python3.13 .venv`).
- `make install` — install runtime + dev deps (from `test/requirements*.txt`) plus tooling.
- `make pre-commit` — run the full lint/format/type/security gate (see below). Run before committing.
- `make tests` — runs unit tests then the infrastructure tests. `STAGE` defaults to `ppe`
  (`make tests STAGE=prod` to override).
- `make build` / `make build_upload` — build the wheel / build and publish to PyPI
  (`build_upload` needs `PYPI_TOKEN`). Normally publishing is done by CI, not locally (see Release).

### Running a single test

Unit tests need no environment:

```bash
.venv/bin/pytest -v test/unit/test_pip_audit_checker.py
```

Infrastructure tests synthesize real CDK stacks and read AWS env vars **at collection time**
(`test/app.py`, every `test/infrastucture/test_*.py`). They fail with `KeyError` unless these are
set, so a bare `pytest -k <name>` will not work on stack tests:

```bash
CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=eu-west-1 STAGE=ppe \
  .venv/bin/pytest -v test/infrastucture/test_s3_stack.py
```

Infra tests are assertion-based: they build `Template.from_stack(...)` and assert with
`resource_count_is` / `has_resource_properties`. There are no snapshot tests and no
`make update-tests` target in this repo.

## Architecture

Two distinct bodies of code live under `cdk_opinionated_constructs/`. Treat them differently.

### 1. The published constructs (the product; tested)

Top-level modules — `s3.py`, `sns.py`, `lmb.py`, `alb.py`, `nlb.py`, `ecr.py`, `rds_instance.py`,
`wafv2.py`. Each defines a `Construct` subclass whose factory methods (`create_bucket`,
`create_sns_topic`, `create_lambda_function`, `web_acl`, `create_db_instance`, …) return AWS
resources pre-wired with encryption, access logging, TLS, immutability, least-privilege, etc.
`README.md` has a worked example per construct — that is the canonical usage reference.

The `test/` tree exercises only these:

- `test/stacks/*.py` — thin CDK stacks that instantiate a construct.
- `test/infrastucture/test_*.py` — synthesize those stacks and assert on the CloudFormation.
- `test/unit/` — plain unit tests (currently `test_pip_audit_checker`).
- `test/app.py` + `test/cdk.json` — the CDK app wiring the demo stacks together.

When you change a construct, the verification loop is: edit the construct → update/add a
`test/stacks/` stack if the API changed → assert in `test/infrastucture/` → `make tests`.

### 2. The CI/CD pipeline subsystem (library building blocks; NOT tested here)

`stacks/`, `stages/`, `stages/logic/`, `schemas/configuration_vars.py`, `libs/pipeline_v2/`,
and `utils/` implement a CDK Pipelines-based delivery framework (code-quality gate, governance,
notifications, integration/services/infrastructure test stages, Trivy image scanning, OCI
signing, SBOM/SOCI, plugin triggers). `pydantic` models in `schemas/configuration_vars.py`
validate stage configuration.

Important caveats before editing this subsystem:

- It is **not covered by the test suite** — there is no synth/verify loop for it in this repo.
- Some modules assume a *consumer's* project layout, not this one: e.g.
  `libs/pipeline_v2/trivy_scaner.py` imports `from cdk.schemas.configuration_vars import PipelineVars`
  (no `cdk` package or `PipelineVars` class exists here), and `utils/helpers.py` reads
  `cdk/config/config-ci-cd.yaml` (no such path here). Do not assume these resolve in-repo; they
  are meant to run in a downstream CDK app. Verify imports against the actual consumer before
  relying on them.

## Tooling gate (`make pre-commit`)

Configured in `.pre-commit-config.yaml`; lint/format rules in `ruff.toml` (line length 120,
`target-version = py313`, large `select` set with project-specific `ignore`s). The gate includes:
`ruff` (+`--fix`) and `ruff-format`, `ssort`, `mypy` (namespace packages, pydantic plugin),
`bandit`, `xenon` (complexity), `gitleaks` + `detect-secrets` + `detect-aws-credentials`,
`hadolint`, `pip-audit`, `uv-secure`, and `mdformat`. There is no `autoformat.sh` despite older
docs referencing one — `make pre-commit` is the formatter/linter entry point.

## Release

Releases are tag-driven (`.github/workflows/release.yaml`). Bump the version in `setup.py`, push
a git tag matching `X.Y.Z` (or `aN`/`bN`/`rcN` prerelease suffix); CI runs `make pre-commit`,
creates the GitHub release, builds, and publishes to PyPI via trusted publishing. The working
branch is named after the target version (e.g. branch `4.7.42` → `version="4.7.42"`).

## Conventions

- Commit messages: Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`).
- Python style, testing idioms, and error-handling conventions: see `AGENTS.md`. Note that
  `AGENTS.md`'s "Repository overview" and "Local workflow" sections are stale (they reference a
  `cdk/` source dir, `cdk/tests/`, `documentation/`, dev/prod stage loops, and `make update-tests`
  — none of which exist). Use this file for paths and commands; use `AGENTS.md` only for the
  Python/style/testing guidance.
