
# AWS Janitor

Identifies ec2 instances that match a set of query filters
and then take actions on them.

Goals for the project are to help organizations manage their cloud
spend rates by for example turning instances off at evening and
starting them in the morning or terminating instances that aren't
conformant with the organizations tag or security group policy.



# Usage

First a policy file needs to be created in yaml format, as an example:

```yaml

ec2:
  filters:
    - filter: tag-key
      value: CMDBEnvironment
      state: absent

    - filter: tag-key
      value: ASV

    - filter: instance-state-name
      value: running
  actions:
    - stop
    - type: mark
      msg: "Instance doesn't match tagging policy" 
     

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


## Start

Start a set of instances (presumably) already stopped.

## Stop

Will stop the instance. Stopped instances do not incur ec2 instance costs.

## Terminate

Will terminate the instance. Use with caution!

# Todo List

For email notification to owner, we'll need the following.

- [ ] Access to CloudTrail bucket for account
- [ ] Email Relay (PonyEx) 
- [ ] Mapping of EID to email address.

For ASV and CMDBEnvironment verification we'll need access to an API over hp service manager.


# Credentials

All credentials are sourced from environment variables or IAM Role

# Filters

Ec2 Filters are per filter list at
http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html

Note state: absent filters are done via post processing instances in
memory. The -j option allows switching from the filter operator from
or to and.



# Install

You'll need python-dev and python-virtualenv packages installed already on linux, on
OSX the default install comes with the nesc requirements.

First clone the repository:

$ git clone https://github.kdc.capitalone.com/ylv522/cloud-janitor.git

Also recommended is to use a virtualenv to sandbox this install from your system packages:

$ virtualenv cloud-janitor
$ source cloud-janitor/bin/activate

And then install the dependencies

$ pip install -f requirements.txt

And then the janitor itself

$ python setup.py develop

You should have the cloud-janitor command available now.

$ cloud-janitor -h




  




