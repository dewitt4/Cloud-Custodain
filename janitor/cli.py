
import argparse
import logging

from janitor import policy, commands


def _default_options(p):
    p.add_argument("-r", "--region", default="us-east-1",
                   help="AWS Region to target")
    p.add_argument("--profile", default=None,
                   help="AWS Account Config File Profile to utilize")
    p.add_argument("-c", "--config", required=True,
                   help="Policy Configuration File")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose Logging")
    p.add_argument("-s" "--s3-path", required=True,
                   help="S3 Bucket URL For Policy Output")
    p.add_argument("-f", "--cache", default="~/.cache/cloud-janitor.cache")
    p.add_argument("--cache-period", default=60, type=int,
                   help="Cache validity in seconds (Default 60)")

    
def _dryrun_option(p):
    p.add_argument(
        "-d", "--dryrun", action="store_true",
        help="Don't change infrastructure but verify access.")

    
def setup_parser():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()

    identify = subs.add_parser("identify")
    identify.set_defaults(command=commands.identify)
    _default_options(identify)

    run = subs.add_parser("run")
    run.set_defaults(command=commands.run)
    _default_options(run)
    _dryrun_option(run)
    return parser


def main():
    parser = setup_parser()
    options = parser.parse_args()

    level = options.verbose and logging.DEBUG or logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s: %(name)s:%(levelname)s %(message)s")
    logging.getLogger('botocore').setLevel(logging.ERROR)    
    
    config = policy.load(options, options.config)
    options.command(options, config)
    

if __name__ == '__main__':
    main()

    
