# kubestash

Push Credstash secrets to Kubernetes.

## installing

```
pip3 install kubestash
```

## installing - known issues

There's a known issue with the `kubernetes` library: https://github.com/kubernetes-incubator/client-python#sslerror-on-macos

which causes some people with older versions of python to get an ssl error:

```
SSLError(SSLError(1, u'[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:590)'),)
```

Kubernetes recommends you to run

```
brew install python
```

and then

```
python -c "import ssl; print ssl.OPENSSL_VERSION"
```

to make sure you have OpenSSL >= 1.0.0, however I did not find this to fix the problem.

If you run into any SSL issue, try updating SSL, and then updating python:

```
brew update
brew install openssl
brew link openssl --force
brew install python --with-brewed-openssl
```

if that still doesn't work, try running:

```
brew unlink openssl
```

## usage

```
usage: kubestash [-h] [-v] [-f] table secret

pulls secrets from Credstash and stores them in Kubernetes secret

positional arguments:
  table          credstash table you want to pull credentials from
  secret         name of the kubernetes secret you want to store secrets in

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose output
  -f, --force    replace a secret if it already exists
```
