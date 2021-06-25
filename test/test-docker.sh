#!/usr/bin/env bash
set -ex
cd "$(git rev-parse --show-toplevel)"

docker build . -t kubestash-test

# test with KUBECONFIG in docker
docker run \
    -v "${HOME}/.kube:/root/.kube" \
    -v "${HOME}/.aws:/root/.aws" \
    -v "$(realpath ~/.minikube):$(realpath ~/.minikube)" \
    kubestash-test kubestash push -f kubestash kubestash

