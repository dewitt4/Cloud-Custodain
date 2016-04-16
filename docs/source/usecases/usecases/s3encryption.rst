Security compliance around s3 buckets (bucket policies, lambda functions, and full scan remediation)
====================================================================================================

- Ensure all objects in s3 are encrypted
- Audit and report on buckets with global access
- Apply bucket policies to an instance

Actions
-------

Encrypt Extant Keys
~~~~~~~~~~~~~~~~~~~

Will scan all keys in the bucket for unencrypted keys and by default
remediate them such that they are encrypted.

Example
.. code-block:: yaml

   policies:
     - name: s3-key-encryption
       resource: s3
       actions: encrypt-keys
         - type: encrypt-keys


  Options

  - `crypto` for determining the crypto mechanism, this can either be `AWS:KMS` or `AES256` (default)
  - `report-only` generate reports of unencrypted keys in a bucket, but do not remediate them.


  Encryption Bucket Policy
  ~~~~~~~~~~~~~~~~~~~~~~~~

  Adds a encryption required bucket policy, merging with extant policy
  statements.

  Example
  .. code-block:: yaml

    policies:
      - name: s3-encryption-policy
        action: encryption-policy
        resource: s3

  Global Grants
  -------------

  Scan buckets that allow for global (ie non capitalone) access in their
  acls and report them and the acl permissions granted.

  Example
  .. code-block:: yaml

    policies:
      - name: s3-insecure-grants
        action: global-grants
        resource: s3
