__notes__ = """
Architecture implementation notes

We need to load policies for lambda functions a bit differently so that
they can create the resources needed.


For full lifecycle management we need to be able to determine

 - all resources associated to a given policy
 - all resources created by maid
 - diff of current resources to goal state of resources
 - remove previous policy lambdas and their event sources
   - we need either the previous config file or we need
     to assume only one maid running lambdas in a given
     account.

 
Sample interactions

  $ cloud-maid resources -c config.yml

   lambda:
     - function: name
       sources:
        - source info


Given an event that comes in from one of a number of sources,
per event source we need to be able to extract the rseource
identities and then query state for them and before processing
filters and actions.
Lambda Developer Notes
----------------------

AWS Cloud Config
################

One event source is using AWS Cloud Config, which provides versioned
json representation of objects into s3 with rules execution against
them.  Config Rules allow for lambda execution against these resource
states to determine compliance along with a nice dashboard targeted
towards visualizing compliance information over time. At the moment
config rules execute after the resource is already active, based on the
underlying resource poll and config snapshot delivery. 

Underlying the hood aws config and config rules, appear to be just
productizing a poll of some resources into json files in s3 with
lambda and versioned metrics reports. At the moment config rules
only support items managed under the ec2 api (ec2, ebs, network) which
means they have significant coverage gap when looking at the totality
of aws services since they only cover a single api. As a result atm,
they are best suited to orgs that are using a small subset of aws that
requires audit (ie. just ec2) and prefer a pre-configured dashboard on
that subset. Of course overtime the config service will evolve.

However for capabilities and reporting around compliance Netflix
security monkey would be a better choice atm imo. Maid distinguishes
in its configurable policy engine, as opposed to hard coded, ability
to run serverless, better integration with current best aws practices
and provides remediation and enforcement capabilities.

Open question on config rules, Its unclear if rules execute against
only on a delta to a resource or against each config snapshot..

For a wider range of coverage and functionality we turn to


TODO:

- Resource Manager Abstraction for all policies (or just policy
  collection).

- Lambda Manager Update Func Configuration

-  Cli tools for listing maid provisioned resources

# S3 Uploads

 - Zip Files idempotency is a bit hard to define, we can't currently
   tag the lambda with git revisions, and zip files track mod times.
 - We're actually uploading policy specific lambda functions, as we 
   bake the policy into the function code. So we need to track two
   separate versions, the policy version and the maid code version.
 - With s3 for the function code, we can track this information better
   both via metadata and/or versioning.

Todo
----

Maid additionally could use lambda execution for resource intensive policy
actions, using dynamodb for results aggregation, and a periodic result checker,
alternatively sqs with periodic aggregator, or when lambda is vpc accessible
elasticache.

