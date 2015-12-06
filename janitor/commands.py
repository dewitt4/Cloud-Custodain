import sys


def identify(options, policy_collection):
    fh = sys.stdout
    for policy in policy_collection.policies(options.policies):
        manager = policy.resource_manager
        resources = manager.resources()
        manager.format_json(resources, fh)
    else:
        print("No policies matched %s" % options.policies)
        
    
def run(options, policy_collection):
    for policy in policy_collection.policies(options.policies):
        policy()
    else:
        print("No policies matched %s" % options.policies)        
        

