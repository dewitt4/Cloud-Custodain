Lambda Support
--------------

Lambda provides for powerful realtime event based code execution in
response to infrastructure and application behavior. A number of
different amazon services can be used as event sources.

Cloud Watch Events
##################

Cloud watchs events is a general event bus for aws infrastructure, atm
it covers several major sources of information, cloud trail api calls
over a poll period on cloud trail delivery, real time instance status
events, autoscale group notifications, and scheduled/periodic events.

Cloud trail provides a very rich data source over the entire range
of aws services exposed via the audit trail that allows maid to define
realtime policies effectively against any aws product.

Additionally for ec2 instances we can provide mandatory policy
compliance, that effectively means the non compliant resource never
became available.

Cloud Maid Integration
######################

Maid provides for policy level execution against any cwe event
stream. Each maid policy can be deployed as an independent lambda
function. The only difference between a maid policy that runs in
lambda a event/reactive push mode and one that runs directly from the
cli in poll mode is the specification of the events to subscribe to
in the mode config block of the policy.

Internally maid will reconstitue current state for all the resources
in the event and execute the policy against them, matching against the
policy filters, and applying the policy actions to matching resources.

Mu is the letter after lambda, lambda is a keyword in python.

Configuration
#############


Examples

.. code-block:: yaml

   policies:

     # Cloud Watch Events over CloudTrail api calls (1-15m trailing)
     - name: ec2-tag-compliance
       resource: ec2

       # The mode block is the only difference between a maid policy that
       # runs in reactive/push mode via lambda and one that runs in poll mode.
       mode: 
         type: cloudtrail
         events: 
          - RunInstances

         # Note because the total aws api surface area is so large
         # most cloud trail api event subscription needs two additional
         # fields.
         #
         # For cloud trail events we need to reference the source api call
         # sources: 
         #  - ec2.amazonaws.com
         #
         # To work transparently with existing resource policies, we also
         # need to specify how to extract the resource ids from the event
         # via jmespath so that the resources can be queried.
         # ids: "detail.responseElements.instancesSet.items[].instanceId"
         #
         # For very common api calls for policies, some shortchuts have
         # been defined to allow for easier policy writing as for the
         # RunInstances api call above.
         # 

       filters:
         - or:
           - tag:required1: absent
           - tag:required2: absent
       actions:
         - stop

     # On EC2 Instance state events (real time, seconds)
     - name: ec2-require-encrypted-volumes
       resource: ec2
       mode:
         type: ec2-instance-state
         events:
         - pending
       filters:
         - type: ebs
           key: Encrypted
           value: False
       actions:
         - mark
         # TODO delete instance volumes that
         # are not set to delete on terminate
         # currently we have a poll policy that
         # handles this.
         - terminate

     # Periodic Function
     # Syntax for scheduler per http://goo.gl/x3oMQ4
     # Supports both rate per unit time and cron expressions
     - name: s3-bucket-check
       resource: s3
       mode:
         type: periodic
         schedule: "rate(1 day)"

