.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help

PYTHON ?= python3

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := $(PYTHON) -c "$$BROWSER_PYSCRIPT"

help:
	@$(PYTHON) -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr target/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -fr {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

lint: ## check style with flake8 and fix with Black
	black text2ioc tests
	isort text2ioc tests
	flake8 text2ioc tests

test: ## run tests quickly with the default Python
	pytest tests/

test-all: ## run tests on every Python version with tox in docker
	docker run -v .:/app text2ioc-test:latest

build-test-image: ## build aow-sdk-test docker image
	docker build --tag text2ioc-test:latest .

coverage: ## check code coverage quickly with the default Python
	coverage run --source text2ioc -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

release: dist ## package and upload a release
	twine upload dist/*

dist: clean ## builds source and wheel package
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build .
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	$(PYTHON) -m pip install .
