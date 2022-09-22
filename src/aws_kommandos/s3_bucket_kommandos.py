#!/usr/bin/env python3
import os

class S3BucketKommands:
    def __init__(self, s3_client,
                 s3_bucket_name: str,
                 home_folder: str):
        self.s3_client = s3_client
        self.s3_bucket_name = s3_bucket_name
        self.home_folder = home_folder

    ## S3 BUCKETS
    ### GETTING ALL BUCKETS
    def get_all_buckets(self):
        return self.s3_client.list_buckets()['Buckets']

    ### GETTING BUCKET BY NAME
    def get_bucket(self, bucket_name: str):
        buckets = self.get_all_buckets()
        for bucket in buckets:
            for k, v in bucket.items():
                if 'Name' == k and bucket_name == v:
                    return bucket

    ### CREATING A BUCKET
    def create_bucket(self, bucket_name: str):
        print(f"Creating a new private S3 bucket with name '{bucket_name}'")
        try:
            self.s3_client.create_bucket(
                ACL='private',
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    'LocationConstraint': self.s3_client.meta.region_name
                }
            )
        except Exception as e:
            if "you already own it" in f"{e}":
                print(f"The S3 bucket '{bucket_name}' already exists")
            else:
                print(f"Failed to create a S3 bucket: {e}")

    ### DELETING A BUCKET
    def delete_bucket(self, bucket_name: str):
        print(f"Deleting the S3 bucket: '{bucket_name}'")
        try:
            self.s3_client.delete_bucket(
                Bucket=bucket_name
            )
        except Exception as e:
            if "The specified bucket does not exist" in f"{e}":
                print(f"The S3 bucket '{bucket_name}' doesn't exist")
            else:
                print(f"Failed to delete the S3 bucket: {e}")

    ### GETTING A FILE FROM S3
    def download_file_from_bucket(self, bucket_name, remote_file_name, local_file_name):
        print(f"Downloading '{remote_file_name}' from s3://{bucket_name} to '{local_file_name}'")
        try:
            self.s3_client.download_file(
                Bucket=bucket_name,
                Key=remote_file_name,
                Filename=local_file_name
            )
            if os.path.exists(local_file_name):
                print(f"{remote_file_name} has been downloaded")
                return True
        except Exception as e:
            if "Not Found" in f"{e}":
                print(f"The file '{remote_file_name}' has not been found on '{bucket_name}' bucket")
            else:
                print(f"Failed to download the file from the S3 bucket: {e}")

    ### UPLOADING A FILE TO S3
    def upload_file_to_bucket(self, bucket_name, local_file_name):
        print(f"Uploading '{local_file_name}' to s3://{bucket_name}")
        try:
            self.s3_client.upload_file(
                Bucket=bucket_name,
                Filename=local_file_name,
                Key=os.path.basename(local_file_name)
            )
        except Exception as e:
            print(f"Failed to upload a file from to the S3 bucket: {e}")

    ### DELETING A FILE FROM S3
    def delete_file_from_bucket(self, bucket_name, remote_file_name):
        print(f"Deleting '{remote_file_name}' from s3://{bucket_name}")
        try:
            self.s3_client.delete_object(
                Bucket=self.s3_bucket_name,
                Key=remote_file_name
            )
        except Exception as e:
            print(f"Failed to upload a file from to the S3 bucket: {e}")
