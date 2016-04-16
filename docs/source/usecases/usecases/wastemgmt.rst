Waste management and identification based on resource consumption with additional information
=============================================================================================

.. code-block:: yaml
   
   - name: ec2-XL-instances-report
     resource: ec2
     comment: |
       Report all ec2 instances with size bigger than M running non-stop over 30 days
     query:
       - instance-state-name: running
     filters:
       - type: instance-age
         days: 1
       - or:
         - type: value
           key: "InstanceType"
           value: "t2.nano"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "t1.micro"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "t2.micro"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "t2.small"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "t2.medium"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "t2.large"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "m3.large"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "m3.medium"
           op: ne
       - or:
         - type: value
           key: "InstanceType"
           value: "m4.large"
           op: ne
   #    actions:
   #      - type: stop
   