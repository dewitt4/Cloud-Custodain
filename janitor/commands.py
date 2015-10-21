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
    

def identify(options, policy):
    manager = policy.resource_manager()
    _serialize(options, manager)

    
def run(options, policy):
    manager = policy.resource_manager()
    resources = manager.resources()
    for a in manager.actions:
        a.process(resources)
    _serialize(options, manager)

