#!/usr/bin/env python3
import os
from pprint import pprint

import pandas
from termcolor import colored


class SSHKeyPairsKommandos:
    def __init__(self, ec2_client, bucket_kommandos):
        self.ec2_client = ec2_client
        self.bucket_kommandos = bucket_kommandos

    ## SSH KEY PAIRS
    ### GETTING KEY PAIRS
    def get_key_pairs(self):
        key_pairs = []
        response = self.ec2_client.describe_key_pairs()
        if response and 'KeyPairs' in response:
            for key_pair in response['KeyPairs']:
                key_pairs.append(key_pair)
        return key_pairs

    def download_key_pair_from_s3(self, key_pair_name: str):
        key_path = f"{self.bucket_kommandos.home_folder}/{key_pair_name}.pem"
        self.bucket_kommandos.download_file_from_bucket(
            bucket_name=self.bucket_kommandos.s3_bucket_name,
            remote_file_name=f"{key_pair_name}.pem",
            local_file_name=key_path
        )
        os.chmod(f"{self.bucket_kommandos.home_folder}/{key_pair_name}.pem", 0o400)

    def print_key_pairs(self, verbose: bool = False):
        key_pairs = self.get_key_pairs()
        if key_pairs:
            print()
            print('> SSH key pairs are:')
            data = []
            for kp in key_pairs:
                key_name = kp['KeyName']
                key = {
                    'KeyPairId': kp['KeyPairId'],
                    'KeyName': key_name
                }
                if verbose:
                    key['KeyFingerprint'] = kp['KeyFingerprint']
                    if 'Tags' in kp and kp['Tags']:
                        key['Tags'] = kp['Tags']
                if os.path.exists(f"{self.bucket_kommandos.home_folder}/{key_name}.pem"):
                    key_local_path = f"{self.bucket_kommandos.home_folder}/{key_name}.pem"
                else:
                    key_local_path = '-'
                key['KeyLocalPath'] = key_local_path
                data.append(key)
            print(pandas.DataFrame(data))
        else:
            print('There are no SSH key pairs')

    ### CREATING A KEY PAIR
    def create_key_pair(self, key_name: str):
        print(f"Creating a new SSH key pair: {key_name}")
        response = self.ec2_client.create_key_pair(KeyName=key_name)
        if response and 'KeyMaterial' in response:
            private_key = response['KeyMaterial']
            file_name = f"{key_name}.pem"
            key_path = f"{self.bucket_kommandos.home_folder}/{file_name}"

            print(colored(f'Saving the private key to {key_path}', 'green'))
            with open(key_path, 'w') as f:
                f.write(private_key)
            # 0x400 -r--------
            os.chmod(key_path, 0o400)

            self.bucket_kommandos.upload_file_to_bucket(bucket_name=self.bucket_kommandos.s3_bucket_name,
                                                        local_file_name=key_path)

    ### DELETE A KEY PAIR
    def delete_key_pair(self, key_name: str):
        print(colored(f"Deleting the SSH key pair: {key_name}", 'yellow'))
        self.ec2_client.delete_key_pair(KeyName=key_name)

        file_name = f"{key_name}.pem"
        key_path = f"{self.bucket_kommandos.home_folder}/{file_name}"
        if os.path.exists(key_path):
            os.chmod(key_path, 0o600)
            os.remove(key_path)

        self.bucket_kommandos.delete_file_from_bucket(self.bucket_kommandos.s3_bucket_name, file_name)
