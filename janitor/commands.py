from datetime import timedelta, datetime

import logging
import sys
import time
import yaml

from janitor.credentials import SessionFactory
from janitor.report import report as do_report
from janitor import mu


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
        except Exception as e:
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


def logs(options, policy_collection):
    policies = policy_collection.policies(options.policies)
    assert len(policies) == 1, "Only one policy log at a time"
    policy = policies.pop()
    
    if not policy.is_lambda:
        log.debug('lambda only atm')
        return

    session_factory = SessionFactory(
        options.region, options.profile, options.assume_role)
    manager = mu.LambdaManager(session_factory)
    for e in manager.logs(mu.PolicyLambda(policy)):
        print "%s: %s" % (
            time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(e['timestamp']/1000)),
            e['message'])
                
    
def resources(options, policy_collection):
    session_factory = SessionFactory(
        options.region, options.profile, options.assume_role)

    manager = mu.LambdaManager(session_factory)
    funcs = manager.list_functions('maid-')

    if options.all:
        print(yaml.dump(funcs, dumper=yaml.SafeDumper))


def resources_gc(options, policy_collection):
    pass

            

    
    
    
    

        
