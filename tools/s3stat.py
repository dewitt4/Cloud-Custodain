from datetime import datetime, timedelta

import boto3
import json
import pprint
import logging
import os


def bucket_info(c, bucket):
   result = {'Bucket': bucket}
   
   response = c.get_metric_statistics(
          Namespace='AWS/S3',
          MetricName='NumberOfObjects',
          Dimensions=[
             {'Name': 'BucketName',
              'Value': bucket},
             {'Name': 'StorageType',
              'Value': 'AllStorageTypes'}
             ],
      StartTime=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(1),
      EndTime=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0),
      Period=60*24*24,
      Statistics=['Average'])

   if not response['Datapoints']:
      result['ObjectCount'] = 0
   else:
      result['ObjectCount'] = response['Datapoints'][0]['Average']
   
   response = c.get_metric_statistics(
          Namespace='AWS/S3',
          MetricName='BucketSizeBytes',
          Dimensions=[
             {'Name': 'BucketName',
              'Value': bucket},
             {'Name': 'StorageType',
              'Value': 'StandardStorage'},
             ],
      StartTime=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(10),
      EndTime=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0),
      Period=60*24*24,
      Statistics=['Average'])

   if not response['Datapoints']:
      result['Size'] = 0
      result['SizeGB'] = 0
   else:
      result['Size'] = response['Datapoints'][0]['Average']
      result['SizeGB'] = result['Size'] / (1024.0 * 1024 * 1024)
   return result

def main():

   logging.basicConfig(level=logging.INFO)
   
   bucket = os.environ.get('BUCKET')
   s = boto3.Session()
   cw = s.client('cloudwatch')
   s3 = s.client('s3')
   buckets = s3.list_buckets()['Buckets'] 

   results = {'buckets':[]}
   size_count = obj_count = 0.0

   for b in buckets:
      i = bucket_info(cw, b['Name'])
      results['buckets'].append(i)
      obj_count += i['ObjectCount']
      size_count += i['SizeGB']
 
   results['TotalObjects'] = obj_count
   results['TotalSizeGB'] = size_count

   print json.dumps(results, indent=2)


   
if __name__ == '__main__':
   main()

