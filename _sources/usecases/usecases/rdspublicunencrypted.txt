RDS - Terminate Unencrypted Public Instances
============================================

.. code-block:: yaml

   - name: terminate-unencrypted-public-rds
     description: |
       Terminate all unencrypted or publicly available RDS on create
     resource: rds
     mode:
       type: cloudtrail
       events:
         - CreateDBInstance
     filters:
       - or:
           - StorageEncrypted: false
           - PubliclyAccessible: true
           # matches true if rds in default vpc
           - type: default-vpc
     actions:
       - type: delete
         skip-snapshot: true
   
         - name: terminate-unencrypted-ebs
           description: |
             Terminate all unencrypted EBS volumes on create
           resource: ebs
           mode:
             type: cloudtrail
             events:
               - CreateVolume
           filters:
             - Encrypted: false
           actions:
             - delete
   