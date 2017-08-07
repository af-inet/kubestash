# kubestash

Push Credstash secrets to Kubernetes.

## installing

```
pip3 install kubestash
```

## usage

```
usage: kubestash [-h] [-p PROXY] [-v] [--trace] [-f] {inject,push} ...

push a Credstash table to a Kubernetes secret

positional arguments:
  {inject,push}
    inject              inject env variables into a Kubernetes deployment
                        manifest, taken from a Kubernetes secret
    push                push values from a Credstash table to a Kubernetes
                        secret

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY, --proxy PROXY
                        hostname of a kubernetes apiserver to use, for
                        example: --proxy 127.0.0.1:8080
  -v, --verbose         verbose output
  --trace               show the full stack trace when an SSLError happens
  -f, --force           replace a secret if it already exists
```

## known issues

There's a known issue with the `kubernetes` library: https://github.com/kubernetes-incubator/client-python#sslerror-on-macos

which causes some people with older versions of python to get an ssl error:

```
SSLError(SSLError(1, u'[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:590)'),)
```

I recommend updating `openssl` and reinstalling `python3` to fix this:

```
brew update
brew install openssl
brew uninstall python3
brew install python3
```

you can also subvert the issue by using a proxy:

```
kubectl proxy -p 8080
kubestash --proxy 127.0.0.1:8080 table secret
```

