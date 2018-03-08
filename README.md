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

`kubestash` is only useful in certain use cases with Kubernetes + Credstash.

- You're using Credstash to store environment variables as secrets.

- You're using Kubernetes, and storing environment variables as secrets.

- You need to constantly synchronize your Credstash table to Kubernetes secrets.

If the above is true for you, `kubestash` can help!

Instead of manually synchronizing your Credstash table to a Kubernetes secret, you can just run

`kubestash push TABLE SECRET`

and you'll have a kubernetes SECRET which maps 1:1 (with some interpolation, see below) with your credstash TABLE.

Instead of writing a ton of yaml to inject your secrets into each container, simply run:

`kubestash inject SECRET DEPLOYMENT`

and each container in DEPLOYMENT will now have each key-value from SECRET.

## key interpolation between credstash and kubernetes.

Kubernetes will only let you store secrets if the key conforms to DNS_SUBDOMAIN. [1] [2]

So when we move your Credstash table to a Kubernetes secret, we do a simple conversion.

Imagine your Credstash table named `database` contains these key-values:

```
MY_DB_PASSWORD=databasezRcool
MY_DB_PORT=8080
```

Your resulting secret from pushing this with `kubestash push` would contain something like this:

```
my-db-password=databasezRcool
my-db-port=8080
```

and we do the reverse when you run `kubestash inject`, so your manifest ends up looking something like this

```
...
env:
- env:
  - name: MY_DB_PASSWORD
    valueFrom:
      secretKeyRef:
        key: my-db-password
        name: database
  - name: MY_DB_PORT
    valueFrom:
      secretKeyRef:
        key: my-db-port
        name: database
...
```


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

