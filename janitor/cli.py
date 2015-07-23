
import argparse
import logging

from janitor import policy, commands


def _default_options(p):
    p.add_argument("-r", "--region", default="us-east-1",
                   help="AWS Region to the target")
    p.add_argument("-c", "--config", required=True,
                   help="Policy Configuration File")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose Logging")

    p.add_argument("-j", dest="or_operator", action="store_true",
                   help="Use 'OR' instead of 'AND' with filters.")    

    p.add_argument("-f", "--cache", default="~/.cache/cloud-janitor.cache")
    p.add_argument("-p", "--cache-period", default=5, type=int,
                   help="Cache validity in seconds (Default 5)")


    p.add_argument(
        "-o", "--output", dest="output_path", default="-",
        help="Save csv output to file")
    
    p.add_argument(
        "-s", "--format", choices=['json', 'csv'],
        help="Save csv output to file")    
    
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

    mark = subs.add_parser("mark")
    mark.set_defaults(command=commands.mark)
    _default_options(mark)
    _dryrun_option(mark)
    
    run = subs.add_parser("run")
    run.set_defaults(command=commands.run)
    _default_options(run)
    _dryrun_option(run)

    return parser


def main():
    parser = setup_parser()
    options = parser.parse_args()

    level = options.verbose and logging.DEBUG or logging.WARNING
    logging.basicConfig(level=level)
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    
    config = policy.load(options, options.config)
    options.command(options, config)
    

if __name__ == '__main__':
    main()

    
