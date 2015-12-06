"""
SQS Email Relay
===============

Designed to work around ... corporate silliness. Rather than sending
email directly to users from maid via ses or other saas api, we
currently have to send via email relay.

Which prevents our lambda functions (separate magic vpc) from being
able to send email. Instead (and for other reasons not appropriate to
describe here) we send email via sqs for an email relay worker to
pickup and push out via smtp.

But as they say every problem is an opportunity, and this
gives us an opportunity to batch our emails within a given
time window to a given recipient.


From a connection perspective it looks like this


Maid (on instance) --
                     \
                      --- SQS Queue -- Relay Worker -> SMTP
                     /
Maid (lambda)  -----


Operationally we can work in either of two modes

 - Fetch Formatted Email Message off Queue and send via relay

 - Fetch Structured Message and batch for interval, before
   coalescing on address, and sending outbound email.


Usage
-----

 - policies:
    - name: ec2-tag-compliance
      resource: ec2
      filters:
        - "tag:required": absent
      actions:
        - type: notify
          target: owner
          owner-tags: OwnerContact, OwnerEmail
          delivery: ses


Data Message Structure
----------------------

  - resource_type: ec2
    resources: []
  

Todo
----

 - Bounce processing


"""
import boto3
import email
import smtplib
import time
import json
import gzip
import sqlite3

from janitor import utils
from janitor.sqsexec import MessageIterator


class MessageDB(object):

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.cursor = self.conn.cursor()
        self._init()
        
    def _init(self):
        self.cursor.execute('''
           create table if not exists messages(
              recipient text
              queue_id text
              message_id text
              message text
        )''')
        
    def add(self, recipient, message):
        self.cursor.execute(
            'insert into messages (recipient, message) values (?, ?)',
            recipient, message
            )

    def batches(self):
        results = self.cursor.execute(
            '''
            select recipient, message
            from messages
            order by recipient
            ''')
        return results
        
    def flush(self):
        self.cursor.execute('''delete from messages''')


class MessageType(object):

    Email = "Email"
    Lookup = "Lookup"
    Topic = "SNS"

    @staticmethod
    def address_resolver(contact):

        if contact.startswith('arn'):
            return MessageType.Topic
        elif '@' in contact:
            return MessageType.Email
        else:
            return MessageType.Lookup


class EmailFormatter(object):
    """
    Given a group of data messages for a given recipient
    construct a formatted email message.

    """
    def __init__(self, config):
        self.config = config
        
    def format(self, recipient, batch):
        """Format a batch of messages to a single recipient"""
        
    
class Worker(object):

    def __init__(self, config, session_factory):
        self.config = config
        self.session_factory = session_factory
        self.receive_queue = self.config.sqs_message_queue
        self.spool_db = MessageDB(self.config.spool_path)
        self.batch_period = self.config.batch_period
        
    def run(self):
        
        session = self.session_factory()
        
        while True:
            sqs = session.client('sqs')
            messages = MessageIterator(self.client)

            for m in messages:
                msg_kind = m['MessageAttributes'].get('ser')
                

def send_data_message(client, queue_url, message):
    client.send_message(
        QueueUrl=queue_url,
        MessageBody=utils.dumps(message),
        MessageAttributes={
            'ser': {
                'StringValue': 'json',
                'DataType': 'String'},
            })
    
def send_email_message():
    pass
