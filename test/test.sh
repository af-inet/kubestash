#!/usr/bin/env bash
set -ex
cd "$(git rev-parse --show-toplevel)"

./test/test-setup.sh
./test/test-local.sh
./test/test-docker.sh
./test/test-kubernetes.sh
./test/test-teardown.sh

