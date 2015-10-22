import os
import sys

def _serialize(options, manager):
    if options.output_path == "-":
        fh = sys.stdout
    else: # dangling fh on close
        fh = open(os.path.expanduser(options.output_path), 'w')

    if options.format == "json":
        manager.format_json(manager.resources(), fh)
    else:
        manager.format_csv(manager.resources(), fh)
    

def identify(options, policy_collection):
    for policy in policy_collection:
        manager = policy.resource_manager
        resources = manager.resources()
        print manager.format_json(resources)

    
def run(options, policy_collection):
    for policy in policy_collection:
        policy()
        

