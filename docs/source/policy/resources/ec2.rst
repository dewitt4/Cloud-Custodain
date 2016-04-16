.. _ec2:

Elastic Cloud Compute (EC2)
===========================


Filters
-------

- Standard Value Filter (see :ref:`filters`)


Actions
-------

- *Mark*

  Tag instances with mark instances matching filters with a 'c7n_status' tag by
  default and configurable value. Here's an example of renaming an extant tag:
  
  .. code-block:: yaml
  
     policies:
       - name: ec2-tag-instances
         resource: ec2
         filters:
           - "tag:CostCenter": foobar
         actions:
           - type: mark
             tag: CostCenter
             msg: barrum

- *Start*

  Start a set of instances (presumably) already stopped, the start action will automatically
  filter instances to those that are already in the correct state.
  
  This example will restart all stopped instances.
  
  .. code-block:: yaml
  
     policies:
       - name: ec2-start
         resources: ec2
         actions:
           - start

- *Stop*

  Will stop the instances. Stopped instances do not incur ec2 instance costs.

- *Terminate*

  Will terminate the instances. Use with caution!
