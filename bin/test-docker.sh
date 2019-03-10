#!/usr/bin/env bash
set -e
cd "$(git rev-parse --show-toplevel)"
docker build . -t kubestash-test
docker run \
    -v "${HOME}/.kube:/root/.kube" \
    -v "${HOME}/.aws:/root/.aws" \
    -v "$(realpath ~/.minikube):$(realpath ~/.minikube)" \
    kubestash-test kubestash push -f kubestash kubestash
