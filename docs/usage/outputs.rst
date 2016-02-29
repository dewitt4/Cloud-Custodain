
Outputs
=======

Cloud maid generates a consistent set of outputs for any given
policy. 

Maid automatically generates per policy outputs with resources metrics
and archived serialization for all resources that match against a policy's
filters.


Metrics
#######

By default cloud-maid on any policy generates cloudwatch metrics for
the number of resources that matched the set of filters, as well as
the time to retrieve and filter the resources as well as the time to
execute actions.

In practice this number of matching resources allow us to generate
enough metrics to put together useful dashboards over policies
in cloud watch custom dashboards.

Additionally some filters and actions, may generate their own metrics.

To enable metrics output, when running cloud maid the boolean metrics
flag needs to be specified::

  $ cloud-maid run -c config.yml --metrics


CloudWatch Logs
###############

Maid can optionally upload its logs in realtime to cloudwatch logs, if
a log group is specified. Each policy's log output is generated as a
separate stream.


Usage example::

  $ cloud-maid run -c config.yml --log-group=/cloud-maid/dev-account/us-east-1


If enabled, its recommended to set a log subscription on the group to
be informed of an operations issues.

If s3 output is also enabled, then its also recommended to set a log group
archival policy, as use the s3 logs as permanenent/audit archive.


S3 Logs & Records
#################

Maid will output its logs and structured resource records in json format to s3, along
with its log files for archival purposes.

The s3 bucket and prefix can be specified via parameters::

  $ cloud-maid run -c config.yml --output-dir s3://my-bucket/my/prefix
  



