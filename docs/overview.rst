Overview
========

Summary: A stateless rules engine for policy definition and
enforcement with metrics and detailed reporting across the dozens of
enterprise and lob specific policies capitalone has for aws. The goal
was rather than having dozens of tools and scripts in place with
highly variable operational controls that a unified tool and language
with consistent reporting, metrics, and operations would provide
superior control and visibility. Policies are specified for a given
resource type and constructed from a vocabulary of filters and actions
specific to a resource type.

Use Cases
---------
 
- Offhours support for ec2 instances and autoscale groups
- Tag compliance across resources (ec2, asg, elb, s3, etc)
- Security compliance around encrypted ebs volumes
- Security compliance around s3 buckets (bucket policies, lambda functions, and full scan remediation).
- Security compliance around elb cipher policies
- Security alerting wrt to kms grant exhaustion for ebs encryption
- Security policy wrt to resource rehydration (ec2 and ami/images) older than 60 days.
- Waste management and identification based on resource consumption with additional information 

Capabilities
------------

Currently provides for policy definition around the following
resources ASG, EBS, S3, ELB, EC2, KMS, AMI, CFT

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
(cloudhealth) integrations or other clouds (gce, azure) as the need
arises.

Reports and generates metrics for all policies executes. 

Stateless design greatly simplifies feature development and operations
and provides flexibility around execution environment (local cli,
server, lambda).

OpenSource so LoBs can enhance and contribute to new features and
capabilities, currently on track for external opensource project
targeting late january.


