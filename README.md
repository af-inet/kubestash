# kubestash

Push Credstash secrets to Kubernetes.

## installing

```
pip3 install kubestash
```

## usage

```
usage: kubestash [-h] {inject,push} ...

push a Credstash table to a Kubernetes secret

positional arguments:
  {inject,push}
    inject       inject env variables into a Kubernetes deployment manifest,
                 taken from a Kubernetes secret
    push         push values from a Credstash table to a Kubernetes secret

optional arguments:
  -h, --help     show this help message and exit
```

## use case

`kubestash` is most useful when:

- You're using Credstash to store environment variables as secrets.

- You're using Kubernetes, and storing environment variables as secrets.

If the above is true for you, `kubestash` can help!

Just run:

`kubestash push TABLE SECRET`

and you'll have a Kubernetes SECRET which maps 1:1 with your Credstash TABLE.

Instead of writing a ton of yaml to inject your secrets into each container, simply run:

`kubestash inject SECRET DEPLOYMENT`

and each container in DEPLOYMENT will now have each key-value from SECRET.


## secret key constraints

Keys must consist of alphanumeric characters, ‘-‘, ‘_’ or ‘.’. [1]

So when you run `credstash -t=table put KEY VALUE`, you should take care that KEY meets this constraint.

In older versions of Kubernetes, secret keys had to conform to DNS_SUBDOMAIN. [2]

For this purpose, the `-l --lowercase` flag is present to help you convert your keys if necessary.

[1] https://kubernetes.io/docs/concepts/configuration/secret/

[2] https://github.com/kubernetes/community/blob/master/contributors/design-proposals/identifiers.md


## known issues

There's a known issue with the `kubernetes` library: https://github.com/kubernetes-incubator/client-python#sslerror-on-macos

which causes some people with older versions of python to get an ssl error:

```
SSLError(SSLError(1, u'[SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:590)'),)
```

We recommend updating `openssl` and reinstalling `python3` to fix this:

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