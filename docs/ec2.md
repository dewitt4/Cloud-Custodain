# EC2 Policies


## Use Cases


- Verify that instances are conformant to tag policies


## Queries



## Filters


### Value Filters

Cloud maid uses [jmespath](http://www.jmespath.org) for matching on instance attributes

### Instance Age


## Actions


### Mark

Will mark instances matching filters with a 'Maid' tag and configurable message


### Start

Start a set of instances (presumably) already stopped.

### Stop

Will stop the instance. Stopped instances do not incur ec2 instance costs.

### Terminate

Will terminate the instance. Use with caution!

