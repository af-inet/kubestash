#!/usr/bin/env bash
set -e

python -m kubestash push -f kubestash kubestash

if [ "$(kubectl get secret kubestash -o=jsonpath='{.data.TEST}' | base64 -D)" != "TEST" ]; then
    echo "looks like kubestash isn't working, exiting..."
    exit 1
fi

echo "Success."

