Security policy wrt to resource rehydration (ec2 and ami/images) older than 60 days.
====================================================================================

.. code-block:: yaml

   - name: ec2-old-instances
     resource: ec2
     comment: |
       Report running instances older than 60 days which needs a refresh
     query:
       - instance-state-name: running
     filters:
       - type: instance-age
         days: 60
   
   
     # Use Case: Report all AMIs that are 120+ days or older
   
     - name: ancient-images-report
       resource: ami
       comment: |
         Report on all images older than 90 days which should
         be de-registered.
       filters:
         - type: image-age
           days: 120


- Instance Age Filter

The instance age filter allows for filtering the set of ec2 instances by
their LaunchTime, ie. all instances older than 60 or 90 days. The default
date value is 60 days if otherwise unspecified.

Filtering Examples
------------------

Configuring a specific value for instance-age to report all instances older
than 90 days.

.. code-block:: yaml

   policies:
     - name: old-instances
       resource: ec2
       filters:
         type: instance-age
         days: 90

Reporting all instances that are missing required tags

.. code-block:: yaml

   policies:
     - name: ec2-missing-tags
       resource: ec2
       filters:
         - "tag:CostCenter": absent
         - "tag:Owner": absent
         - "tag:Project": absent
