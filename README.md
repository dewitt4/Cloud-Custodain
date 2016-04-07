# Cloud Maid

Cloud maid is a rules engine that provides for querying, filtering,
and applying actions to AWS resources.

Goals for the project are to help organizations manage their cloud
infrastructures by ensuring compliance to security policies, tag
policies, garbage collection of unused resources, and cost management
via offhours resource management. 

# Links

- [Docs https://github.kdc.capitalone.com/pages/cloud-maid/cloud-maid/ ]
- [Architecture](docs/architecture.rst)
- [Developer Install](docs/developer.rst)

- Resource Guides
  - [EC2](docs/ec2.rst)
  - [S3](docs/s3.rst)
 

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

Given that, you can run cloud-maid via

```
  $ cloud-maid run -c policy.yml
```
By default any run of the maid will output csv of the instances operated on.


Maid supports a few other useful subcommands and options.

One is to just query for instances matching and export them as csv or json with
the *identify* subcommand.

```
  $ cloud-maid identify -c policy.yml > instances.json
```

For additional information please look at the individual
resource guides and the filtering docs linked above.





  




