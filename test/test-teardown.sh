#!/usr/bin/env bash
set -ex
cd "$(git rev-parse --show-toplevel)"
minikube stop
aws dynamodb delete-table --table-name kubestash
