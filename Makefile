# Makefile for setting up and activating a Python virtual environment

# Set the desired Python interpreter (change if needed)
PYTHON := python3.13
# Virtual environment directory
VENV := .venv

STAGE?=ppe

# Default target
all: venv activate install

venv: # Create new Python virtual environment
	@echo "Creating Python virtual environment..."
	uv venv --seed --python $(PYTHON) $(VENV)

activate: # Activate Python virtual environment
	@echo "Activating Python virtual environment..."
	@echo "Run 'deactivate' to exit the virtual environment."
	@. $(VENV)/bin/activate

install: # Install all project dependencies and development tools
	@echo "Installing dependencies from requirements files"
	pip install --upgrade pip
	pip install --upgrade uv
	uv pip install pre-commit pytest pytest-snapshot
	uv pip install -r test/requirements.txt
	uv pip install -r test/requirements-dev.txt

pre-commit: # Run code quality checks on all Python files
	@echo "Running pre-commit"
	pre-commit run --files cdk_opinionated_constructs/*.py
	pre-commit run --files cdk_opinionated_constructs/schemas/*.py
	pre-commit run --files cdk_opinionated_constructs/stacks/*.py
	pre-commit run --files cdk_opinionated_constructs/stages/*.py
	pre-commit run --files cdk_opinionated_constructs/tests/integration/*.py
	pre-commit run --files cdk_opinionated_constructs/utils/*.py
	pre-commit run --files cdk_opinionated_constructs/libs/pipeline_v2/*.py

tests: # Run infrastructure tests for specified stage
	@echo "Running pytest for stage "
	STAGE=$(STAGE) pytest -v cdk/tests/infrastructure/

update: # Update all dependencies and tools to latest versions
	@echo "Updating used tools and scripts"
	pre-commit autoupdate
	pur -r test/requirements.txt
	pur -r test/requirements-dev.txt

clean: # Remove virtual environment and cleanup project files
	@echo "Cleaning up..."
	rm -rf $(VENV)

build:
	@echo "Building and uploading to PyPi"
	rm -rf dist/*
	uv build

upload:
	@echo "Building and uploading to PyPi"
	uv publish --token $(PYPI_TOKEN)
	rm -rf dist/*

build_upload:
	@echo "Building and uploading to PyPi"
	rm -rf dist/*
	uv build
	uv publish --token $(PYPI_TOKEN)
	rm -rf dist/*

help: # Display this help message
	@printf "\n\033[1;32mAvailable commands: \033[00m\n\n"
	@awk 'BEGIN {FS = ":.*#"; printf "\033[36m%-30s\033[0m %s\n", "target", "help"} /^[a-zA-Z0-9_-]+:.*?#/ { printf "\033[36m%-30s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)



.PHONY: all venv activate test clean pre-commit update help
