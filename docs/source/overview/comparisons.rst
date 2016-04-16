Comparisons
------------

Janitor Monkey
^^^^^^^^^^^^^^

Netflix's Janitor Monkey provides for a statically defined set of
rules in code, many of which are overly specific to Netflix's use
cases. It also utilizes legacy technology for state management in the
form SimpleDB. Custodian in comparison allows for user definition of policy
and rules to enforce within a yaml configuration file, and since it
runs stateless can be deployed on a laptop, server, or lambda.

Security Monkey
^^^^^^^^^^^^^^^

Netflix's Security Monkey is a more interesting tool, that provides for some
basic audit capabilities. Its worth investigating, but its not clear that
there's much overlap between Cloud Custodian and Security Monkey, their targeted
to different use cases.
