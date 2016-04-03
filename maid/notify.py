# Copyright 2016 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
Implementation Notes / not docs

Flexible notifications require quite a bit of implementation support
on pluggable transports, templates, address resolution, variable
extraction, batch periods, etc.

For expedience and flexibility then, we instead send the data to
an sqs queue, for processing. ie. actual communications is diy.

policies:
  - name: 
  
    actions:
      - type: notify
        # want fallback
        to: event-user | resource-creator | email@address | sns-topic
        # which template for the email should we use
        template: policy-template
        transport: 
           type: sqs
           region: us-east-1
           queue: xyz
"""
from maid.actions import BaseAction
from maid.mailer import send_data_message


class Notify(BaseAction):

    schema = {
        'type': 'object',
        'required': ['type', 'transport', 'template'],
        'properties': {
            'type': {'enum': ['notify']},
            'recipient': {'enum': ['event-user', 'resource-owner']},
            'template': {'type': 'string'},
            'transport': {
                'type': 'object',
                'required': ['type', 'queue'],
                'properties': {
                    'queue': {'type': 'string'},
                    'type': {'enum': ['sqs']}}
            }
        }
    }
        
    def process(self, resources, event=None):
        queue = self.data['transport']['queue']
        message = {'resources': resources,
                   'event': event,
                   'policy': self.manager.data}
        send_data_message(queue, message)
        
    def resolve_recipient_from_event(self, event):
        identity = event.get('details', {}).get('userIdentity', {})
        if identity is None:
            return None

        if identity['type'] == 'Root':
            return None
        
        if ':' in identity['principalId']:
            user_id = identity['principalId'].split(':', 1)[-1]
        else:
            user_id = identity['principalId']
        return user_id
            

