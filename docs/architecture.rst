Architecture
============

Terms
-----

- *Policy*

  Defined in yaml, specifies a set of filters and actions to take
  on a given aws resource type.

- *Resource Manager*

  Provides for retrieval of a resources of a given type (typically via aws api) and defines the vocabulary of filters and actions that can be used on those resource. Example resource types are autoscalegroups, s3 buckets, ec2 instances, elbs, etc).

- *Filter*

  Given a set of resources, how do we filter to the subset that we're interested in operating on. The filtering language has some default behaviors across resource types like value filtering with jmespath expressions against the json representation of a resource, as well specific filters for particular resources types (instance age, tag count, etc).

- *Action*

  A verb to use on a given resource, ie. stop, start, suspend
  delete, encrypt, etc.

Policy Execution
----------------

TODO, document diagram, to show generic output management
and sequencing.

Model Definition
----------------

- Validation

- Imports

- Formats

  - yaml

- Serialization and Exchange Formats

- For record serialization, we preferentially use bson over json for its
  datetime support.


Operations Design Goals
-----------------------

- Configuration either S3 or Git Config

- Stateless by design (this simplifies scaling)

  - Dev can run with a local cache file.
  - Considering optional cache / Redis / S3 State File (kv) / MongoDB  

- IAM Policy Generation

- Policy level Outputs
  - Data S3 at Element Level
  - Metrics at Element Level
    - Execution Time
    - Resource Counts
	- Modified
  - Alerts (SNS)
    - Error
    - Completion
  - SNS Notifications
  - Worker
  - Output channels

- Cron / Lambda Execution

Not yet
-------

- Distributed
- Autoscaling
