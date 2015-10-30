import os
import sys


def identify(options, policy_collection):
    if options.output_path == "-":
        fh = sys.stdout
    else: # dangling fh on close
        fh = open(os.path.expanduser(options.output_path), 'w')

    for policy in policy_collection:
        manager = policy.resource_manager
        resources = manager.resources()
        print manager.format_json(resources, fh)

    
def run(options, policy_collection):
    for policy in policy_collection:
        policy()
        

