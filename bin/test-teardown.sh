#!/usr/bin/env bash
minikube stop
aws dynamodb delete-table --table-name kubestash
