#!/usr/bin/env python
from setuptools import find_packages
from setuptools import setup
setup(
  name='kubestash',
  packages=['kubestash'],
  install_requires=[
    'kubernetes',
    'boto3',
    'credstash',
    'urllib3',
  ],
  version='2.0.2',
  description='Push your Credstash secrets to Kubernetes.',
  author='David Hargat',
  author_email='davidmhargat@gmail.com',
  url='https://github.com/af-inet/kubestash',
  license="MIT",
  # download_url='TODO',
  keywords=['k8s', 'kubernetes', 'credstash'],
  scripts=['bin/kubestash'])
