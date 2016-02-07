from datetime import timedelta, datetime

import logging
import sys

from janitor.report import report as do_report


log = logging.getLogger('maid.commands')


def identify(options, policy_collection):
    fh = sys.stdout
    for policy in policy_collection.policies(options.policies):
        manager = policy.resource_manager
        resources = manager.resources()
        manager.format_json(resources, fh)        

        
def run(options, policy_collection):
    for policy in policy_collection.policies(options.policies):
        try:
            policy()
        except Exception, e:
            if options.debug:
                raise
            # Output does an exception log
            log.warning("Error while executing policy %s, continuing" % (
                policy.name))
    
            
def report(options, policy_collection):
    log = logging.getLogger('maid.report')

    policies = policy_collection.policies(options.policies)
    assert len(policies) == 1, "Only one policy report at a time"
    policy = policies.pop()
    
    d = datetime.now()
    delta = timedelta(days=options.days)
    begin_date = d - delta
    do_report(
        policy, begin_date, sys.stdout,
        raw_output_fh=options.raw)


            
        
            

    
    
    
    

        
