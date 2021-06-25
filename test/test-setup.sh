#!/usr/bin/env bash
# this is my local testing script, probably won't work for everyone
#
set -ex

# (setup): make sure we're running this script from the root of the git directory
cd "$(git rev-parse --show-toplevel)"

# (sanity check): make sure these commands are installed
command -v credstash
command -v minikube
command -v aws

# (sanity check): make sure we're not logged in to an AWS organization.
aws organizations describe-organization && {
    echo "looks like we're logged into an AWS organization, exiting..."
    exit 1
}

# (setup): bring up a credstash table if necessary
credstash -t=kubestash setup
aws dynamodb wait table-exists --table-name kubestash

# (sanity check): make sure credstash is working
credstash -t=kubestash put TEST TEST -a
if [ "$(credstash -t=kubestash get TEST)" != "TEST" ]; then
    echo "looks like credstash isn't working, exiting..."
    exit 1
fi

# (setup): bring up minikube if necessary
minikube status || minikube start
# (sanity check): make sure kubectl is working
kubectl get pods

# make sure the docker context isn't set
unset DOCKER_HOST
unset DOCKER_API_VERSION
unset DOCKER_TLS_VERIFY
unset DOCKER_CERT_PATH

