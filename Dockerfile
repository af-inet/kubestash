FROM jfloff/alpine-python:2.7
RUN apk update && apk add libffi-dev openssl-dev
RUN pip install kubestash