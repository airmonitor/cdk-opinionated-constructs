# Makefile for setting up and activating a Python virtual environment

# Set the desired Python interpreter (change if needed)
PYTHON := python3.11

# Virtual environment directory
VENV := .venv

STAGE?=ppe

# Default target
all: venv activate install

# Create the virtual environment
venv:
	@echo "Creating Python virtual environment..."
	$(PYTHON) -m venv $(VENV)

# Activate the virtual environment
activate:
	@echo "Activating Python virtual environment..."
	@echo "Run 'deactivate' to exit the virtual environment."
	@. $(VENV)/bin/activate

install:
	@echo "Installing dependencies from requirements files"
	pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pip install pre-commit pytest

pre-commit:
	@echo "Running pre-commit"
	pre-commit run --files cdk_opinionated_constructs/*.py
	pre-commit run --files cdk_opinionated_constructs/schemas/*.py
	pre-commit run --files cdk_opinionated_constructs/stacks/*.py
	pre-commit run --files cdk_opinionated_constructs/stages/*.py
	pre-commit run --files cdk_opinionated_constructs/tests/integration/*.py
	pre-commit run --files cdk_opinionated_constructs/utils/*.py

test:
	@echo "Running pytest for stage "
	STAGE=$(STAGE) pytest -v cdk/tests/infrastructure/

update:
	@echo "Updating used tools and scripts"
	pre-commit autoupdate

clean:
	@echo "Cleaning up..."
	rm -rf $(VENV)

build_upload:
	@echo "Building and uploading to PyPi"
	rm -rf dist/*
	python3 -m build
	twine upload dist/*
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
