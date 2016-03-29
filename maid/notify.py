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
policies:
  - name: 
  
    actions:
      - type: notify
        to: event-user
        format: 
        transport: 
           type: sqs
           region: us-east-1
-           queue: xyz
"""
from maid.actions import BaseAction
from maid.mailer import send_data_message


class Notify(BaseAction):

    schema = {
        'type': 'object',
        'required': ['type', 'transport'],
        'properties': {
            'type': {'enum': ['notify']},
            'recipient': {'enum': ['event-owner', 'resource-owner']},
            'format': {'type': 'string'},
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
        recipient = self.data.get('recipient', 'event-owner')
        if recipient == 'event-owner':
            recipient = self.resolve_recipient_from_event(event)
        if not recipient:
            self.log.info("No recipient found")
            return

        # for sqs transport only        
        queue = self.data['transport']['queue']
        message = {'resources': resources,
                   'format': self.data['format'],
                   'policy': self.manager.data}
        send_data_message(queue, recipient, message)
        
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
            

