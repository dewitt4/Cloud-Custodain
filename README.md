# Cloud Maid

Cloud maid is a rules engine that provides for querying, filtering,
and applying actions to AWS resources.

Goals for the project are to help organizations manage their cloud
spend rates by for example turning instances off at evening and
starting them in the morning or terminating instances that aren't
conformant with the organizations tag or security group policy.


# Links

- [Architecture](docs/architecture.md)
- [Developer Install](docs/developer.md)
- Resource Guides
  - [EC2](docs/ec2.md)
  - [S3](docs/s3.md)
 

# Usage

First a policy file needs to be created in yaml format, as an example:


```yaml

policies:
 - name: remediate-extant-keys
   resources: s3
   actions:
     - encrypt-keys

- name: old-instances
   resource: ec2
   query:
     - instance-state-name: running
   filters:
     - type: instance-age

- name: tag-compliance
   resources: ec2
   query:
     - instance-state-name: running
   filters:
     - "tag:CMDBEnvironment": absent
     - "tag:ASV": absent
     - or:
       - "tag:OwnerContact": absent
   	   - "tag:OwnerEID": absent
   actions:
     - type: mark-for-op
       op: stop
       days: 4

```

Given that, you can run the janitor via

```
  $ cloud-maid run -c policy.yml
```
By default any run of the maid will output csv of the instances operated on.


Maid supports a few other useful subcommands and options.

One is to just query for instances matching and export them as csv or json with
the *identify* subcommand. Default output is to stdout, controlled with the
'-o' option.

```
  $ janitor identify -c policy.yml -o instances.json --format=json
```

You can also use run directly in dryrun mode, in which case it will verify api
access to perform the requested actions.

```
  $ janitor run -c policy.yml --dryrun
```

For email notification to owner, we'll need the following.

- [ ] Access to CloudTrail bucket for account
- [ ] Email Relay (PonyEx) 
- [ ] Mapping of EID to email address.

For ASV and CMDBEnvironment verification we'll need access to an API over hp service manager.


# Credentials

All credentials are sourced from environment variables or IAM Role

# Querying

Ec2 query capabilities are per filter list at
http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html

# Filtering

Note state: absent filters are done via post processing instances in
memory. The -j option allows switching from the filter operator from
or to and.




  




