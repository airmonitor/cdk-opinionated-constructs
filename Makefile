# Makefile for setting up and activating a Python virtual environment

# Set the desired Python interpreter (change if needed)
PYTHON := python3.11
VERSION := 3.15.0
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
	pip install uv
	uv pip install --system --native-tls --upgrade pip
	uv pip install --system --native-tls -r requirements.txt
	uv pip install --system --native-tls -r requirements-dev.txt
	uv pip install --system --native-tls pre-commit pytest pytest-snapshot

local_install: # Install minimal set of local development dependencies
	@echo "Installing dependencies from requirements files"
	uv pip install pur
	uv pip install -r requirements.txt
	uv pip install pre-commit pytest pytest-snapshot


pre-commit: # Run code quality checks on all Python files
	@echo "Running pre-commit"
	pre-commit run --files cdk_opinionated_constructs/*.py
	pre-commit run --files cdk_opinionated_constructs/schemas/*.py
	pre-commit run --files cdk_opinionated_constructs/stacks/*.py
	pre-commit run --files cdk_opinionated_constructs/stages/*.py
	pre-commit run --files cdk_opinionated_constructs/tests/integration/*.py
	pre-commit run --files cdk_opinionated_constructs/utils/*.py

tests: # Run infrastructure tests for specified stage
	@echo "Running pytest for stage "
	STAGE=$(STAGE) pytest -v cdk/tests/infrastructure/

update: # Update all dependencies and tools to latest versions
	@echo "Updating used tools and scripts"
	pre-commit autoupdate

clean:
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

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  all        : Set up the virtual environment (default target)"
	@echo "  venv       : Create the virtual environment"
	@echo "  activate   : Activate the virtual environment"
	@echo "  update     : Download and update custom configuration files"
	@echo "  clean      : Remove the virtual environment"
	@echo "  build_upload	: Build python package and upload it to the pypi repository"
	@echo "  help       : Display this help message"


.PHONY: all venv activate test clean pre-commit update help
