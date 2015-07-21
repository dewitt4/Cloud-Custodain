
import argparse


from janitor import policy, commands


def _default_options(p):
    p.add_argument("-r", "--region", default="us-east-1",
                   help="AWS Region to the target")
    p.add_argument("-c", "--config", required=True,
                   help="Policy Configuration File")


    p.add_argument("-f", "--cache", default="~/.cache/cloud-janitor.cache")
    p.add_argument("-p", "--cache-period", default=5, type=int,
                   help="Cache validity in seconds (Default 5)")

    
def setup_parser():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()

    identify = subs.add_parser("identify")
    identify.set_defaults(command=commands.identify)
    _default_options(identify)
    identify.add_argument(
        "-o", "--output", dest="csv_file", required=True,
        help="Save csv output to file")
    identify.add_argument(
        "-s", "--format", choices=['json', 'csv'],
        help="Save csv output to file")    

    mark = subs.add_parser("mark")
    mark.set_defaults(command=commands.mark)
    _default_options(mark)
    
    run = subs.add_parser("run")
    run.set_defaults(command=commands.run)
    _default_options(run)
    run.add_argument(
        "-d", "--dryrun",
        help="Don't change infrastructure but verify access.")

    return parser

def main():
    parser = setup_parser()
    options = parser.parse_args()
    config = policy.load(options, options.config)
    options.command(options, config)
    

if __name__ == '__main__':
    main()

    
