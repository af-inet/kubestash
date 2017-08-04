import argparse
import base64
import json
import sys

import kubernetes
import credstash

DEFAULT_REGION = "us-east-1"
DEFAULT_NAMESPACE = "default"

# TODO: args.namespace
# TODO: args.profile, args.arn
# TODO: args.region
# TODO: args.context
# TODO: args.version

def parse_args():
    """ Parses command line arguments. """
    # https://docs.python.org/3/library/argparse.html
    help_text = "pulls secrets from Credstash and stores them in Kubernetes secret"
    parser = argparse.ArgumentParser(
            description=help_text)
    parser.add_argument('table',
            action='store',
            type=str,
            help="credstash table you want to pull credentials from")
    parser.add_argument('secret',
            action='store',
            type=str,
            help='name of the kubernetes secret you want to store secrets in')
    parser.add_argument('-v', '--verbose',
            dest='verbose',
            action='store_true',
            help='verbose output')
    parser.add_argument('-f', '--force',
            dest='force',
            action='store_true',
            help='replace a secret if it already exists')
    args = parser.parse_args()
    return args

def credstash_getall(args, session_params):
    """ Returns an object containing all your Credstash secrets from `args.table`. """
    # https://github.com/fugue/credstash/blob/master/credstash.py#L297
    secrets = credstash.getAllSecrets("",
        region=DEFAULT_REGION,
        table=args.table,
        context=None,
        **session_params)
    return secrets

def dns_subdomain(string):
    """Converts an ENV_VARIABLE style string to a secret-style string.
    This should be used to convert Credstash secret keys to Kubernetes secret keys.
    Explanation:
        Kubernetes will only let you store secrets if the key conforms to
        DNS_SUBDOMAIN. [1]
        rfc1035/rfc1123 subdomain (DNS_SUBDOMAIN): One or more lowercase
        rfc1035/rfc1123 labels separated by '.' with a maximum length of 253
        characters [2]
    [1] https://kubernetes.io/docs/concepts/configuration/secret/
    [2] https://github.com/kubernetes/community/blob/master/contributors/design-proposals/identifiers.md
    """
    return string.replace("_", "-").lower()

def kube_init_secret(name, data):
    """
    Initialize a Kubernetes secret object (only in memory).
    Data contains the secret data. Each key must consist of alphanumeric
    characters, '-', '_' or '.'. The serialized form of the secret data
    is a base64 encoded string, representing the arbitrary
    (possibly non-string) data value here.
    [1] https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/V1Secret.md
    """
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/V1Secret.md
    # api_version, data, kind, metadata, string_data, type
    converted_data = {
        dns_subdomain(key): base64.b64encode(data[key].encode('utf-8')).decode('utf-8')
        for key in data
    }
    metadata = kubernetes.client.V1ObjectMeta(name=name)
    return kubernetes.client.V1Secret(data=converted_data, type="generic", metadata=metadata)

def kube_create_secret(args, kube, data):
    """ Creates a Kubernetes secret. Returns the api response from Kubernetes."""
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#create_namespaced_secret
    body = kube_init_secret(args.secret, data)
    return kube.create_namespaced_secret(DEFAULT_NAMESPACE, body)

def kube_replace_secret(args, kube, data):
    """ Replaces a kubernetes secret. Returns the api response from Kubernetes. """
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#replace_namespaced_secret
    body = kube_init_secret(args.secret, data)
    return kube.replace_namespaced_secret(args.secret, DEFAULT_NAMESPACE, body)

def kube_secret_exists(args, kube):
    """ Returns True or False if a Kubernetes secret exists or not respectively. """
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#read_namespaced_secret
    try:
        # TODO: might be better to call list_namespaced_secrets here.
        response = kube.read_namespaced_secret(args.secret, DEFAULT_NAMESPACE)
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            return False # 404 means the secret did not exist, so we can return False
        else:
            raise e # don't catch errors you can't resolve.
    return True

def main():
    args = parse_args()

    kubernetes.config.load_kube_config()
    kube = kubernetes.client.CoreV1Api()
    session_params = credstash.get_session_params(None, None)
    
    if kube_secret_exists(args, kube):
        if not args.force:
            print("Secret: '{secret}' already exists, run with -f to replace it." \
                .format(secret=args.secret))
            sys.exit(1)
        else:
            data = credstash_getall(args, session_params)
            kube_replace_secret(args, kube, data)
            print("Replaced Secret: '{secret}' with Credstash table: '{table}'" \
                .format(secret=args.secret, table=args.table))
    else:
        data = credstash_getall(args, session_params)
        kube_create_secret(args, kube, data)
        print("Created Secret: '{secret}' with Credstash table: '{table}'" \
            .format(secret=args.secret, table=args.table))

    return None
