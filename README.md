# kubestash

Push Credstash secrets to Kubernetes.

https://hub.docker.com/r/afinet/kubestash/

## installing

```
pip3 install kubestash
```

## usage

```
usage: kubestash push [-h] [-p PROXY] [-v] [--trace] [-f] [-n NAMESPACE]
                        [-l] [-c CONTEXT] [-r REGION]
                        table secret

positional arguments:
  table                 Credstash table you want to pull values from
  secret                Kubernetes secret you want to push values in

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY, --proxy PROXY
                        hostname of a kubernetes apiserver to use, for
                        example: --proxy 127.0.0.1:8080
  -v, --verbose         verbose output
  --trace               show the full stack trace when an SSLError happens
  -f, --force           replace a secret if it already exists
  -n NAMESPACE, --namespace NAMESPACE
                        kubernetes namespace
  -U, --uppercase       For lowercase keys in credstash, convert them
                        to UPPER_CASE environment variables
  -l, --lowercase       For SECRET keys, lowercase and convert "_" to "-"
                        (DNS_SUBDOMAIN). Useful for compatibility with older
                        Kubernetes versions. (deprecated).
  -c CONTEXT, --context CONTEXT
                        kubernetes context
  -r REGION, --region REGION
                        aws region

```

## adding envs to your deployment

add this to your container

```yaml
envFrom:
- secretRef:
    name: secret-name
```

See [test/example.deploy.yaml](test/example.deploy.yaml) for an example of this.

## use case

`kubestash` is most useful when:

- You're using Credstash to store environment variables as secrets.

- You're using Kubernetes, and storing environment variables as secrets.

If the above is true for you, `kubestash` can help!

Just run:

`kubestash push -v TABLE SECRET`

and you'll have a Kubernetes SECRET which maps 1:1 with your Credstash TABLE.

`kubestash daemon -v TABLE SECRET` will monitor DynamoDB for updates
(using [DynamoDB Streams](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html)),
and automatically trigger a push command when necessary.

This is useful if you don't want to manually run the `push` command every time you update credstash.

## secret key constraints

Keys must consist of alphanumeric characters, ‘-‘, ‘_’ or ‘.’. [1]

Environment variable names must consist solely of uppercase letters, digits, and the '_' (underscore). [2]

So when you run `credstash -t=table put KEY VALUE`, you should take care that KEY meets these constraints.

In older versions of Kubernetes, secret keys had to conform to DNS_SUBDOMAIN.

For this purpose, the `-l --lowercase` flag is present to help you convert your keys if necessary.

[1] https://kubernetes.io/docs/concepts/configuration/secret/

[2] http://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap08.html


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
