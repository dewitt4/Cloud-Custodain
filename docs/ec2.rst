# EC2 Policy Definition



## Filters

- Standard Value Filter (see [Value Filters](filter-values.md))

- Instance Age Filter

The instance age filter allows for filtering the set of ec2 instances by
their LaunchTime, ie. all instances older than 60 or 90 days. The default
date value is 60 days if otherwise unspecified.

## Filtering Examples

Configuring a specific value for instance-age to report all instances older
than 90 days.

```yaml
policies:
  - name: old-instances
    resource: ec2
    filters:
      type: instance-age
      days: 90      
```

Reporting all instances that are missing required tags

```yaml
policies:
  - name: ec2-missing-tags
    resource: ec2
    filters:
      - "tag:ASV": absent
      - "tag:CMDBEnvironment": absent
      - "tag:OwnerContact": absent
```

## Actions


### Mark

Tag instances with mark instances matching filters with a 'maid_status' tag by
default and configurable value.

Here's an example of renaming an extant tag

```yaml
policies:
  - name: ec2-tag-instances
    resource: ec2
    filters:
      - "tag:ASV": foobar
    actions:
      - type: mark
        tag: ASV
        msg: barrum
```

### Start

Start a set of instances (presumably) already stopped, the start action will automatically
filter instances to those that are already in the correct state.

This example will restart all stopped instances.

```yaml
policies:
  - name: ec2-start
    resources: ec2
    actions:
      - start
```

### Stop

Will stop the instances. Stopped instances do not incur ec2 instance costs.

### Terminate

Will terminate the instances. Use with caution!
