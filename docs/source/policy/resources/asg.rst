.. _asg:

Auto Scaling Groups (ASG)
=========================

Filters
-------

- Standard Value Filter (see :ref:`filters`)

Actions
-------

``remove-tag`` or ``untag`` or ``unmark``
  Removes tag from ASG

``tag`` or ``mark``
  Create or update tag on ASG

``propagate-tags``
  Propagate tags to an asg instances. In AWS changing an asg tag does not propagate to instances. This action exists to do that, and can also trim older tags not present on the asg anymore that are present on instances.

``rename-tag``
  Rename a tag on an AutoScaleGroup.

``mark-for-op``
  Tag ASG for an operation

``suspend``
  Multistep process to stop an ASG. Suspend processes, note load balancer in tag, detach load balancer, and then stop instances.

``resume``
  Multi-step process to resume an ASG. Start any stopped ec2 instances, reattach ELB, and resume ASG processes.

``delete``
  Delete ASG

``offhour`` or ``OffHour``
  Turn resources off based on a schedule.
  :py:class:``c7n.offhours``

``onhour`` or ``onhour``
  Turn resources on based on a schedule.
  :py:class:``c7n.offhours``
