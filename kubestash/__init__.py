import argparse

def parse_args():
    """ Parses command line arguments. """
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
    parser.add_argument('-c', '--command',
            dest='command',
            action='store_true',
            help='only output the Kubernetes command, instead of just running it')
    parser.add_argument('-v', '--verbose',
            dest='verbose',
            action='store_true',
            help='verbose output (print to stderr so you can easily pipe stdout)')
    parser.add_argument('-f', '--force',
            dest='force',
            action='store_true',
            help='replace a secret if it already exists (no prompt)')
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    pass
