# kubestash

Push Credstash secrets to Kubernetes.

## installing

```
pip3 install kubestash
```

### install - SSL Issue

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
