Capabilities
------------

Currently provides for policy definition around the following
resources:
* Amazon Machine Images (AMI)
* Auto Scaling Groups (ASG)
* CloudFormation Stacks (CFT)
* Elastic Block Stores (EBS)
* Elasic Cloud Compute (EC2)
* Elastic Load Balancers (ELB)
* Key Management Service (KMS)
* Simple Storage Service (S3)

Provides a flexible query language for filtering resources to a
particular subset that allows for compound querying. Ie. Instances
with ebs volumes that are not set to delete on instance
termination. This filtering can take into account external data
sources.

And provides for resource specific actions around deletion, stopping,
starting, encryption, tagging, etc.

Each account will define it own policy, CM will run the policy and
push structured record output and logs to s3 and metrics to cloudwatch
in that account. Additional app specific control is done via resource
tagging (ie. Offhours).


Easy to extend to as needed for internal (CMDB, LDAP) and external
(CloudHealth) integrations or other clouds (GCE, Azure) as the need
arises.

Reports and generates metrics for all policies executes. 

Stateless design greatly simplifies feature development and operations
and provides flexibility around execution environment (local cli,
server, lambda).

OpenSource so LoBs can enhance and contribute to new features and
capabilities, currently on track for external opensource project
targeting late january.