#!/usr/bin/env python3

# DNS-1123 validation regex https://stackoverflow.com/a/2063247
#
## kubestash secret format: namespace/secret-name/SECRET_KEY = SECRET_VALUE
## namespace & secret-name(passed as application name -a) are required args to this script
## SECRET_KEY & SECRET_VALUE are actual credstash secrets fetched from --source-table
#


import credstash
import argparse
import re
import sys

def parse_args():
    """ Parses command line arguments. """
    # https://docs.python.org/3/library/argparse.html
    help_text = 'Read credstash secrets and write kubestash formatted secrets #https://github.com/af-inet/kubestash/pull/8'

    parser = argparse.ArgumentParser(description=help_text)

    parser.add_argument('-s', '--source-table',
                        dest='src_table',
                        action='store',
                        type=str,
                        required=True,
                        help='Credstash table you want to pull values from')

    parser.add_argument('-t', '--target-table',
                        dest='tar_table',
                        action='store',
                        type=str,
                        required=True,
                        help='Credstash table you want to populate')

    parser.add_argument('-a', '--application',
                        dest='app',
                        action='store',
                        type=str,
                        required=True,
                        help='Application name that replaces secret-name in namespace/secret-name/SECRET_KEY')

    parser.add_argument('-r', '--region',
                        dest='region',
                        action='store',
                        type=str,
                        default='ap-south-1',
                        help='AWS region')

    parser.add_argument('-n', '--namespace',
                        dest='namespace',
                        action='store',
                        type=str,
                        required=True,
                        help='Kubernetes namespace that replaces namespace in namespace/secret-name/SECRET_KEY')

    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        help='Verbose output')

    parser.add_argument('-d', '--dryrun',
                        dest='dryrun',
                        action='store_true',
                        help='Do a dryrun')

    args = parser.parse_args()
    return args

def is_valid_dns_1123(args):
    regex = re.compile('^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$')
    if not regex.match(args.app):
        if args.verbose:
            print('Application name {app} does not conform with DNS-1123 spec.'.format(app=args.app))
        sys.exit(1)

def credstash_getall(args):
    if args.verbose:
        print('fetching your secrets from "{table}" '
              '(Credstash is slow, this may take a few minutes...)'.format(table=args.src_table))
    session_params = credstash.get_session_params(None, None)
    secrets = credstash.getAllSecrets('',
                                      region=args.region,
                                      table=args.src_table,
                                      **session_params)
    return secrets

def gen_kubestash_secrets(args):
    credstash_secrets = credstash_getall(args)
    kubestash_secrets = dict()
    for k, v in credstash_secrets.items():
        secret_key = args.namespace + '/' + args.app + '/' + k
        kubestash_secrets[secret_key] = v
    return kubestash_secrets

def main():
    args = parse_args()
    is_valid_dns_1123(args)
    kubestash_secrets = gen_kubestash_secrets(args)
    if args.dryrun:
        for k, v in kubestash_secrets.items():
            print('"{secret_key}": {secret_value}'.format(secret_key=k, secret_value=v))
    else:
        print('Push to tar_table')

if __name__ == '__main__':
    main()
