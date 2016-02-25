Value Filters
=============

Cloud maid provides for a flexible query language on any resource by
allowing for rich queries on json objects via jmespath, and allows for
mixing and combininng those with a boolean conditional operators that
are nestable. Comparision between values is configurable supporting
scalar operators, absent, not-null, equal (eq), not-equal (ne),
greater-than (gt|gte), less-than (lt|lte), and a few collection
operators in, not-in (ni), against user supplied lists.
