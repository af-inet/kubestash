#!/usr/bin/env python3

# DNS-1123 validation regex https://stackoverflow.com/a/2063247
#
## kubestash secret format: namespace/secret-name/SECRET_KEY = SECRET_VALUE
## namespace & secret-name(passed as application name -a) are required args to this script
## SECRET_KEY & SECRET_VALUE are actual credstash secrets fetched from --source-table
#

import traceback
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

    parser.add_argument('-k', '--key',
                        dest='kms_key_alias',
                        action='store',
                        type=str,
                        default='credstash',
                        help='KMS key alias used to populate secrets to target table')

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


# Fetch all secrets from args.src_table
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


# List all secrets from args.tar_table
def credstash_listall(args):
    if args.verbose:
        print('fetching your secrets from "{table}" '
              '(Credstash is slow, this may take a few minutes...)'.format(table=args.tar_table))
    session_params = credstash.get_session_params(None, None)
    secrets_list = credstash.listSecrets(region=args.region, table=args.tar_table, **session_params)
    return secrets_list

# Push a single secret to args.tar_table, supports versioning
def credstash_push(args, key, value, ver=0):
    if args.verbose:
        print('Pushing secret {secret} to "{table}"'.format(secret=key, table=args.tar_table))
    session_params = credstash.get_session_params(None, None)
    if ver == 0:
        pushed_secret = credstash.putSecret(key, value, region=args.region, table=args.tar_table, kms_key=args.kms_key_alias, **session_params)
    else:
        pushed_secret = credstash.putSecret(key, value, version=ver, region=args.region, table=args.tar_table, kms_key=args.kms_key_alias, **session_params)
    return pushed_secret


# Form kubestash formatted secrets dict from args.src_table
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
    args.kms_key_alias = 'alias/' + args.kms_key_alias
    if args.dryrun:
        print(' KMS key alias: {kmska}\n Source table: {srct}\n Target table: {tart}\n Namespace: {ns}\n Application name: {app}\n'.format(kmska=args.kms_key_alias, srct=args.src_table, tart=args.tar_table, ns=args.namespace, app=args.app))
        print(' Kubestash secrets:')
        for k, v in kubestash_secrets.items():
            print('  "{secret_key}": {secret_value}'.format(secret_key=k, secret_value=v))
    else:
        existing_target_secret_ver = credstash_listall(args)
        existing_target_secrets = [secret_list['name'].lower() for secret_list in existing_target_secret_ver]
        for k, v in kubestash_secrets.items():
            try:
                if k.lower() in existing_target_secrets:
                    # Bump up the version no. and push to args.tar_table
                    secret_version = -1
                    for secret in existing_target_secret_ver:
                        if secret['name'].lower() == k.lower():
                            secret_version = int(secret['version'])
                            if args.verbose:
                                print('Found secret {secret_name} with version no: {ver}'.format(secret_name=secret['name'], ver=secret_version))
                            break
                        else:
                            # Iterated complete secrets vers. list without a match, control sholud never reach here.
                            pass
                    if secret_version > -1:
                        secret_version += 1
                        if args.verbose:
                            print('Incrementing version for {secret_name} to: {ver}'.format(secret_name=k, ver=secret_version))
                        credstash_push(args, k, v, secret_version)
                    else:
                        # Iterated complete secrets vers. list without a match, control sholud never reach here.
                        pass
                else:
                    # Push to args.tar_table without passing ver.
                    credstash_push(args, k, v)
            except:
                if args.verbose:
                    traceback.print_exc()
                else:
                    pass


if __name__ == '__main__':
    main()
