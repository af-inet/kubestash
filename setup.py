#!/usr/bin/env python
from distutils.core import setup
setup(
  name='kubestash',
  packages=['kubestash'],
  version='0.1',
  description='Push your Credstash secrets to Kubernetes.',
  author='David Hargat',
  author_email='davidmhargat@gmail.com',
  url='https://github.com/af-inet/kubestash',
  license="MIT",
  # download_url='TODO',
  keywords=['k8s', 'kubernetes', 'credstash'],
  classifiers=[],
  scripts=['bin/kubestash'])