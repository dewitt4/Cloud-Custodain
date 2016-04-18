S3 - Encryption Bucket Policy
=============================

Adds a encryption required bucket policy, merging with extant policy
statements.

.. code-block:: yaml

   policies:
     - name: s3-encryption-policy
       action: encryption-policy
       resource: s3