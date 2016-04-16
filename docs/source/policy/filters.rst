.. _filters:

Value Filters
-------------

Cloud Custodian provides for a flexible query language on any resource by
allowing for rich queries on JSON objects via JMESPath, and allows for
mixing and combining those with a boolean conditional operators that
are nest-able. Comparison between values is configurable supporting
scalar operators:

- ``absent``
- ``not-null``
- ``equal`` or ``eq``
- ``not-equal`` or ``ne``
- ``greater-than`` or ``gt`` or ``gte``
- ``less-than`` or ``lt`` or ``lte``
- collection operators against user supplied lists:
    - ``in``
    - ``not-in`` or ``ni``
