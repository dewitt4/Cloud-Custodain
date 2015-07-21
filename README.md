
# AWS Janitor



Identifies ec2 instances that are not conformant to an org tag policy
and then take one of several configurable actions.

# Usage

First a policy file needs to be created in yaml format, as an example:

```yaml

filters:
  - filter: tag-key
    value: CMDBEnvironment
    type: ec2  
    state: absent

  - filter: tag-key
    type: ec2
    value: ASV

  - filter: instance-state-name
    type: ec2  
    value: running

  - filter: relative-instance-age
    value:
	days: 2
    type: janitor

actions:
  - operation: notify-owner
  - operation: stop
  - operation: terminate
  - operation:
	- type: mark
	- msg: "Doesn't match policy" 
     

```

Given that you can run the janitor via::

  $ janitor run -c policy.yml
  
Janitor supports a few other useful modes.

One is to just query

  $ janitor run -c policy.yml --dry-run

You can also use run directly in dryrun mode, in which case it will verify api
access.

# Operations

## Mark

Will mark instances matching with a 'Janitor' tag

# Credentials

All credentials are sourced from environment variables, either IAM Role

# Filters

Ec2 Filters are per filter list at
http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html

Note state: absent filters are done via post processing instances in memory.

    

  




