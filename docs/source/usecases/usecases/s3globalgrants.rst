S3 - Global Grants
==================

Scan buckets that allow for global access in their
acls and report them and the acl permissions granted.


.. code-block:: yaml

   policies:
   
     - name: s3-insecure-grants
       action: global-grants
       resource: s3
