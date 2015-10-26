import json
import boto3

s3 = boto3.resource('s3')

CRYPTO_METHOD = "AES256"


def handle_new_object(record):
    bucket = record['s3']['bucket']['name']
    key = record['s3']['object']['key']
    try:
        obj =  s3.Object(bucket, key)
        if not obj.server_side_encryption:
            print("bucket:%s key:%s adding crypt: %s" % CRYPTO_METHOD)
            obj.copy_from(CopySource="%s/%s" % (bucket, key),
                          ServerSideEncryption=CRYPTO_METHOD)
    except Exception as e:
        print(e)        
        print(('Error getting object {} from bucket {}. '
               'Make sure they exist and your bucket is '
               'in the same region as this function').format(key, bucket))
        raise e

    
def lambda_handler(event, context):
    map(handle_new_object, event['Records'])
