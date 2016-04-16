[![Build Status](http://maid-dev-ci.cloud.capitalone.com/api/badges/cloud-maid/cloud-maid/status.svg)](http://maid-dev-ci.cloud.capitalone.com/cloud-maid/cloud-maid)

# Cloud Custodian

Cloud Custodian is a stateless rules engine for policy definition and enforcement, with metrics and detailed reporting for AWS. It consolidates many of the enterprise and departmental specific cloud controls organizations have into one tool. Organizations can use Custodian to manage their AWS environments by ensuring compliance to security policies, tag policies, garbage collection of unused resources, and cost management via off-hours resource management, all from one tool. Custodian policies are written in simple YAML configuration files that specify given resource types and are constructed from a vocabulary of filters and actions. Custodian was created to unify the dozens of tools and scripts most organizations use for managing their AWS accounts into one open source tool.

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
