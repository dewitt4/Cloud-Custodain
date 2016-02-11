import itertools
import logging

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry

from janitor.manager import ResourceManager, resources
from janitor.utils import local_session


log = logging.getLogger('maid.cfn')

filters = FilterRegistry('cfn.filters')
actions = ActionRegistry('cfn.actions')


@resources.register('cfn')
class CloudFormation(ResourceManager):

    def __init__(self, ctx, data):
        super(CloudFormation, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resources(self):
        c = self.session_factory().client('cloudformation')
        self.log.info("Querying cloudformation")
        p = c.get_paginator('describe_stacks')
        results = p.paginate()
        stacks = list(itertools.chain(*[rp['Stacks'] for rp in results]))
        return self.filter_resources(stacks)


@actions.register('delete')
class Delete(BaseAction):

    def process(self, stacks):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_stack, stacks))

    def process_stacks(self, stack):
        client = local_session(
            self.manager.session_factory).client('cloudformation')
        client.delete_stack(StackName=stack['StackName'])

