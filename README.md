
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

actions:
  - notify-owner
  - stop
  - terminate
  - type: mark
    msg: "Doesn't match policy" 
     

```

Given that, you can run the janitor via

```
  $ janitor run -c policy.yml
```
By default any run of the janitor will output csv of the instances operated on.


Janitor supports a few other useful subcommands and options.

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

# Operations

## Mark

Will mark instances matching filters with a 'Janitor' tag and configurable message


## Stop

Will stop the instance. Stopped instances do not incur ec2 instance costs.

## Terminate

Will terminate the instance. Use with caution!

## Notify

Not implemented, todo list

- [x] Access to CloudTrail bucket for acct
- [x] Email Relay (PonyEx)


# Credentials

All credentials are sourced from environment variables or IAM Role

# Filters

Ec2 Filters are per filter list at
http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html

Note state: absent filters are done via post processing instances in
memory. The -j option allows switching from the filter operator from
or to and.

    

  




