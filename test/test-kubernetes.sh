#!/usr/bin/env bash
set -ex
cd "$(git rev-parse --show-toplevel)"

# use the minikube docker daemon, so we can run images in kubernetes
eval $(minikube docker-env)

# needed a way to pass variables to kubernetes without mounting a file... hacky but whatever
AWS_ACCESS_KEY_ID=$(cat "${HOME}/.aws/credentials" | grep "aws_access_key_id" | sed -e 's/aws_access_key_id = //g')
AWS_SECRET_ACCESS_KEY=$(cat "${HOME}/.aws/credentials" | grep "aws_secret_access_key" | sed -e 's/aws_secret_access_key = //g')

# test with incluster-config in docker
kubectl run \
    --image-pull-policy=IfNotPresent \
    --restart=Never \
    --rm \
    -i \
    -t \
    --env "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}" \
    --env "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}" \
    --image kubestash-test \
    test \
    -- /bin/sh -c 'sleep 4; kubestash push -f kubestash kubestash'

echo "Success."

