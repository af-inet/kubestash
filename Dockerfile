FROM python:2.7-alpine3.7
# See https://github.com/pyca/cryptography/blob/master/docs/installation.rst#alpine
RUN apk add --no-cache \
    gcc \
    libffi-dev \
    musl-dev \
    openssl-dev \
    python3-dev \
    yaml-dev \
    && mkdir /app
COPY . /app
WORKDIR /app
# force dateutil otherwise installation fails
RUN pip install requests python-dateutil==2.6.1 && python setup.py develop

ENTRYPOINT /usr/local/bin/kubestash