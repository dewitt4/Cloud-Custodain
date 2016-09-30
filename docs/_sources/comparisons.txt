Comparisons
===========

Janitor Monkey
--------------

Netflix's janitor monkey provides for a statically defined set of
rules in code, many of which are overly specific to netflix's use
cases. It also utilizes legacy technology for state management in the
form simpledb. Maid in comparison allows for user definition of poilcy
and rules to enforce within a yaml configuration file, and since it
runs stateless can be deployed on a laptop, server, or lambda.

Security Monkey
---------------

Netflix's security monkey is a more interesting tool, that provides for some
basic audit capabilities. Its worth investigating, but its not clear that
there's much overlap between cloud-maid and security monkey, their targetted
to different use cases.
