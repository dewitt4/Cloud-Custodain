import json, boto3

ec2Client = boto3.client('ec2')
kmsClient = boto3.client('kms')

def collectKey():
	kmsKeyId = kmsClient.describe_key(KeyId='alias/cof/ebs/encrypted')
	return kmsKeyId

def createSnapshotUnc(volumeId):
	snapDesc = "cloud_maid.snapshotUnc"
    snapshot = ec2Client.create_snapshot(DryRun=False, VolumeId=volumeId, Description=snapDesc)
	snapshotId = snapshot['SnapshotId']
	return snapshotId
	
def copySnapshotEnc(snapshotId):
	kmsKeyId = collectKey()
	snapDesc = "cloud_maid.snapshotEnc"
	encSnapshot = ec2Client.copy_snapshot(DryRun=False, SourceSnapshotId=snapshotId, Description=snapDesc, Encrypted=True, KmsKeyId=kmsKeyId)
	encSnapshotId = encSnapshot['SnapShotId']
	
	# delete the unencrypted snapshot
	ec2Client.delete_snapshot(DryRun=False, SnapshotId=snapshotId)
	
	return encSnapshotId
	
def createVolume(snapshotId, availabilityZone):
	volume = ec2Client.create_volume(DryRun=False, SnapShotId=snapshotId, AvailabilityZone=availabilityZone)
	volumeId = volume['VolumeId']
	return volumeId