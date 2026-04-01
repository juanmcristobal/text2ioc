#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.md') as history_file:
    history = history_file.read()

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup_requirements = ['pytest-runner', ]

test_requirements = ['pytest>=3', ]

setup(
    author="Juan Manuel Cristóbal Moreno",
    author_email='juanmcristobal@gmail.com',
    python_requires='>=3.10',
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    description="Python package for extracting Indicators of Compromise (IOCs) from unstructured text of any length, including articles, reports, logs, and threat intelligence documents.",
    install_requires=required,
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='text2ioc',
    name='text2ioc',
    packages=find_packages(include=['text2ioc', 'text2ioc.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/juanmcristobal/text2ioc',
    version='0.1.5',
    zip_safe=False,
)
