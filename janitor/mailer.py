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
    message: ""
    resources: [
      {'InstanceId': 'xyz'},
    ]

We'll receive those and queue them up. And then at batch
period we'll do outbound formatting and processing


Email Message Structure
-----------------------

We also want direct formatted emails, these are not batched
and are directly sent out as received in simple relay fashion.

  - {'recipient': 'subject':  'body': base64(gzip())'}
  

Todo
----

 - Bounce processing


"""
import argparse
import boto3
import email
import logging
import smtplib
import time
import json
import gzip
import sqlite3

from janitor import utils
from janitor.sqsexec import MessageIterator


DATA_MESSAGE = "datamsg/1.0"
EMAIL_MESSAGE = "email/1.0"


log = logging.getLogger('maid.mail')


class MessageDB(object):

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.cursor = self.conn.cursor()
        self._init()
        
    def _init(self):
        self.cursor.execute('''
           create table if not exists messages(
              recipient text,
              queue_id text,
              message_id text,
              message text
        )''')
        
    def add(self, recipient, message):
        self.cursor.execute(
            'insert into messages (recipient, message) values (?, ?)',
            (recipient, message)
            )

    def batches(self):
        results = self.cursor.execute(
            '''
            select recipient, message
            from messages
            group by recipient
            ''')
        return list(results.fetchall())
        
    def flush(self):
        self.cursor.execute('''delete from messages''')


class MessageAddress(object):

    Email = "Email"
    Lookup = "Lookup"
    Topic = "SNS"

    @staticmethod
    def address_resolver(contact):
        if contact.startswith('arn'):
            return MessageAddress.Topic
        elif '@' in contact:
            return MessageAddress.Email
        else:
            return MessageAddress.Lookup


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
        self.smtp = smtplib.SMTP(
            self.config.smtp_server,
            self.config.smtp_port)
        
    def run(self):
        session = self.session_factory()
        while True:
            sqs = session.client('sqs')
            messages = MessageIterator(self.client)
            messages.msg_attributes = ['mtype', 'recipient']
            for m in messages:
                msg_kind = m['MessageAttributes'].get('mtype')
                if msg_kind == DATA_MESSAGE:
                    self.spool_db.add(
                        m['MessageAttributes']['recipient'], m)
                elif msg_kind == EMAIL_MESSAGE:
                    result = self.smtp.sendmail(
                        self.config.from_addr,
                        [m['MessageAttributes']['recipient']],
                        )

                    if result:
                        log.warning("Couldn't send email %s" % (result,))
                    messages.ack(m)


def setup_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-s', '--smtp-host')
    parser.add_argument(
        '-p', '--smtp-port')
    parser.add_argument(
        '-q', '--queue-url')
    parser.add_argument(
        '-d', '--database-path')    
    parser.add_argument(
        '-f', '--from-addr', default="no-reply-cloud-maid@capitalone.com")    

    return parser

    
# FTesting

def send_data_message(queue_url, recipient, message):
    client = boto3.Session().client('sqs')
    client.send_message(
        QueueUrl=queue_url,
        MessageBody=utils.dumps(message),
        MessageAttributes={
            'mtype': {
                'DataType': 'String',
                'StringValue': DATA_MESSAGE},
            'recipient': {
                'StringValue': recipient,
                'DataType': 'String'}})

    
def send_email_message(client, queue_url, message):
    client.send_message(
        QueueUrl=queue_url,
        MessageBody=message,
        MessageAttributes={
            'op': {
                'DataType': 'String',
                'StringValue': 'email/1.0'},
            'ser': {
                'StringValue': 'json',
                'DataType': 'String'
                }})
