import argparse
import base64
import json
import sys
import urllib3
import ssl

import kubernetes
import credstash

DEFAULT_REGION = "us-east-1"
DEFAULT_NAMESPACE = "default"

# TODO: args.namespace
# TODO: args.profile, args.arn
# TODO: args.region
# TODO: args.context
# TODO: args.version

def base_parser():
    """ Parses arguments shared by every subcommand. """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-p', '--proxy',
        action='store',
        type=str,
        nargs=1,
        help='hostname of a kubernetes apiserver to use, for example: --proxy 127.0.0.1:8080')
    parser.add_argument('-v', '--verbose',
        dest='verbose',
        action='store_true',
        help='verbose output')
    parser.add_argument('--trace',
        dest='trace',
        action='store_true',
        help="show the full stack trace when an SSLError happens")
    parser.add_argument('-f', '--force',
        dest='force',
        action='store_true',
        help='replace a secret if it already exists')
    return parser

def add_parser_inject(parent):
    """ Parses arguments for the inject command. """
    parser = parent.add_parser('inject',
        parents = [base_parser()],
        help="inject env variables into a Kubernetes deployment manifest, taken from a Kubernetes secret")
    parser.add_argument('secret',
        action='store',
        type=str,
        help="Kubernetes secret you want to take values from")
    parser.add_argument('deployment',
        action='store',
        type=str,
        help="Kubernetes deployment to inject env values into")
    parser.add_argument('-c', '--container',
        action='append',
        default=[],
        type=str,
        help="specify one or more containers to insert env values into (default is all containers)")
    return parser

def add_parser_push(parent):
    """ Parses arguments for the push command. """
    parser = parent.add_parser('push',
        parents = [base_parser()],
        help="push values from a Credstash table to a Kubernetes secret")
    parser.add_argument('table',
        action='store',
        type=str,
        help="Credstash table you want to pull values from")
    parser.add_argument('secret',
        action='store',
        type=str,
        help='Kubernetes secret you want to push values in')
    return parser

def parse_args():
    """ Parses command line arguments. """
    # https://docs.python.org/3/library/argparse.html
    help_text = "push a Credstash table to a Kubernetes secret"

    parser = argparse.ArgumentParser(description=help_text, parents=[base_parser()])

    parsers = parser.add_subparsers(dest='cmd')
    parsers.required = True

    add_parser_inject(parsers)
    add_parser_push(parsers)

    args = parser.parse_args()
    return args

def credstash_getall(args):
    """ Returns an object containing all your Credstash secrets from `args.table`. """
    # https://github.com/fugue/credstash/blob/master/credstash.py#L297
    session_params = credstash.get_session_params(None, None)
    secrets = credstash.getAllSecrets("",
        region=DEFAULT_REGION,
        table=args.table,
        context=None,
        **session_params)
    return secrets

def dns_subdomain(string):
    """
    Converts an ENV_VARIABLE style string to a secret-style string.
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

def reverse_dns_subdomain(string):
    """ The opposite of dns_subdomain, convert secret-style strings to ENV_VARIABLE style strings. """
    return string.replace("-", "_").upper()

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

def kube_create_secret(args, data):
    """ Creates a Kubernetes secret. Returns the api response from Kubernetes."""
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#create_namespaced_secret
    kube = kubernetes.client.CoreV1Api()
    body = kube_init_secret(args.secret, data)
    return kube.create_namespaced_secret(DEFAULT_NAMESPACE, body)

def kube_replace_secret(args, data):
    """ Replaces a kubernetes secret. Returns the api response from Kubernetes. """
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#replace_namespaced_secret
    kube = kubernetes.client.CoreV1Api()
    body = kube_init_secret(args.secret, data)
    return kube.replace_namespaced_secret(args.secret, DEFAULT_NAMESPACE, body)

def kube_secret_exists(args):
    """ Returns True or False if a Kubernetes secret exists or not respectively. """
    # https://github.com/kubernetes-incubator/client-python/blob/master/kubernetes/docs/CoreV1Api.md#read_namespaced_secret
    kube = kubernetes.client.CoreV1Api()
    try:
        # TODO: might be better to call list_namespaced_secrets here.
        response = kube.read_namespaced_secret(args.secret, DEFAULT_NAMESPACE)
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            return False # 404 means the secret did not exist, so we can return False
        else:
            raise # don't catch errors you can't resolve.
    return True

def kube_read_secret(args):
    """ Returns the full contents of a Kubernetes secret. """
    kube = kubernetes.client.CoreV1Api()
    return kube.read_namespaced_secret(args.secret, DEFAULT_NAMESPACE)

def kube_read_deployment(args):
    """ Returns the full contents of Kubernetes deployment. """
    kube = kubernetes.client.AppsV1beta1Api()
    response = kube.read_namespaced_deployment(args.deployment, DEFAULT_NAMESPACE)
    return response

def kube_patch_deployment(args, deployment):
    """ Patches a Kubernetes deployment with data `deployment`. Returns the full contents of the patched deployment. """
    kube = kubernetes.client.AppsV1beta1Api()
    return kube.patch_namespaced_deployment(args.deployment, DEFAULT_NAMESPACE, deployment)

def inject_secret(data, containers, env_name, secret_name, secret_key):
    """
    Takes a Kubernetes service deployment structure `data` and adds a secretKeyRef
    environment to any `containers` it finds by name in the deployment.
    The secret is made up of:
    `env_name` - the name of the environment variable to add to the container
    `secret_name` - the name of the secret in kubernetes
    `secret_key` - the key for the secret in kubernetes
    """
    # see: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables
    # create a new env structure
    new_env = kubernetes.client.V1EnvVar(
        env_name,
        value_from = kubernetes.client.V1EnvVarSource(
            secret_key_ref = kubernetes.client.V1SecretKeySelector(
                name = secret_name,
                key = secret_key
            )
        )
    )
    for container in data.spec.template.spec.containers:
        # if no containers are passed in, we're inserting into all containers.
        if (len(containers)==0) or (container.name in containers):
            # filter out any ENV's that collide with our new secret.
            # (this means the new env will replace any old envs of the same name)
            container.env = [
                env
                for env in container.env
                    if env.name != new_env.name
            ]
            container.env.append(new_env)

def cmd_inject(args):
    """
    Pulls values from a Kubernetes secret and injects them into a deployment as environment variables.
    There may be multiple containers in a single deployment, so we inject into all of them.
    """
    # read the original deployment file
    deployment = kube_read_deployment(args)
    # print(deployment)
    # read the secrets
    secrets = kube_read_secret(args).data
    # inject each secert into the deployment file as an environment variable
    for key in secrets:
        inject_secret(deployment, args.container, reverse_dns_subdomain(key), args.secret, key)
    # TODO: implement a diff here so we can inform the use if they actually changed anything.
    kube_patch_deployment(args, {
        "spec": {
            "template": {
                "spec": {
                    "containers": deployment.spec.template.spec.containers
                }
            }
        }
    })
    print("Injected environment variables into deployment: '{deployment}' from secret: '{secret}'" \
        .format(deployment=args.deployment, secret=args.secret))

def cmd_push(args):
    """ Pulls values from a Credstash table and stores them in a Kubernetes secret. """
    if kube_secret_exists(args):
        if not args.force:
            print("Kubernetes Secret: '{secret}' already exists, run with -f to replace it." \
                .format(secret=args.secret))
            sys.exit(1)
        else:
            data = credstash_getall(args)
            kube_replace_secret(args, data)
            print("Replaced Kubernetes Secret: '{secret}' with Credstash table: '{table}'" \
                .format(secret=args.secret, table=args.table))
    else:
        data = credstash_getall(args)
        kube_create_secret(args, data)
        print("Created Kubernetes Secret: '{secret}' with Credstash table: '{table}'" \
            .format(secret=args.secret, table=args.table))

def main():
    args = parse_args()

    # load the users config file
    kubernetes.config.load_kube_config()

    # override the host if the user passes in a --proxy
    if args.proxy and (len(args.proxy) == 1):
        kubernetes.client.configuration.host = args.proxy[0]

    try:
        if args.cmd == "push":
            cmd_push(args)
        elif args.cmd == "inject":
            cmd_inject(args)
        else:
            pass
    except urllib3.exceptions.MaxRetryError as e:
        if (type(e.reason) is urllib3.exceptions.SSLError) and not (args.trace):
            # This will be a very common error since the python that ships with macOS
            # seems to be stuck on openssl v0.9.8, so lets show the users how to fix it.
            # Kubernetes seems to be aware of this issue: https://github.com/kubernetes-incubator/client-python#sslerror-on-macos
            #
            print(("\nSSLError: run with --trace to see the original exception which caused this error.\n\n"
                   "This version of python is compiled with '{ssl_version}' - while Kubernetes requires at least version 1.0.0!\n\n"
                   "You can fix this by running:\n\n"
                   "\tkubectl proxy -p 8080\n\n"
                   "\tkubestash --proxy 127.0.0.1:8080 {table} {secret}\n\n"
                   "Which will subvert the issue by connecting to Kubernetes through an http proxy.\n\n"
                   "Alternatively, you can upgrade your openssl and rebuild python3 with brew.\n\n"
                   "\tbrew update\n"
                   "\tbrew install openssl\n"
                   "\tbrew uninstall python3\n"
                   "\tbrew install python3 --with-brewed-openssl\n")
                .format(ssl_version=ssl.OPENSSL_VERSION, table=args.table, secret=args.secret))
            sys.exit(1)
        else:
            raise

    return None
