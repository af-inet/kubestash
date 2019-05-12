#!/bin/bash
python setup.py sdist upload -r kubestash
VERSION=$(python setup.py --version)
docker build . -t "afinet/kubestash:${VERSION}"
docker push "afinet/kubestash:${VERSION}"
