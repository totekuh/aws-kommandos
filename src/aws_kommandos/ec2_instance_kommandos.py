#!/usr/bin/env python3
import os
import subprocess
from pprint import pprint
import pandas

import botocore.client
from termcolor import colored

from ami_kommandos import AMIKommandos


class EC2InstanceKommandos:
    def __init__(self, ec2, ec2_client,
                 home_folder: str,
                 ami_kommandos: AMIKommandos):
        self.ec2 = ec2
        self.ec2_client = ec2_client
        self.home_folder = home_folder
        self.ami_kommandos = ami_kommandos

    ## EC2 INSTANCES
    def find_instance(self, instance_name: str):
        filters = [{
            'Name': 'tag:Name',
            'Values': [instance_name]
        }]
        return self.ec2_client.describe_instances(Filters=filters)

    def poll_ssh_status(self, instance_id: str):
        instance = self.get_instance(instance_id)
        # try until connected
        cmd = f"""
        until nc -w 1 -z {instance.public_ip_address} 22; do
             sleep 5
        done
        """
        try:
            os.system(cmd)
        except Exception as e:
            print(f'Polling session with {instance.public_ip_address} has been interrupted: {type(e)} - {e}')

    ### LISTING RUNNING INSTANCES
    def get_running_instances(self):
        # create filter for instances in running state
        filters = [
            {
                'Name': 'instance-state-name',
                'Values': ['running']
            }
        ]

        # filter the instances based on filters() above
        instances = []
        for instance in self.ec2.instances.filter(Filters=filters):
            instances.append(instance)
        return instances

    def get_instance(self, instance_id: str):
        return self.ec2.Instance(instance_id)

    def print_running_instances(self, verbose: bool = False):
        instances = self.get_running_instances()
        if instances:
            print()
            print('> Running instances are:')
            data = []
            for instance in instances:
                name = ''
                if hasattr(instance, 'tags') and instance.tags:
                    for tag in instance.tags:
                        if 'Key' in tag and tag['Key'] == 'Name':
                            name = tag['Value']
                inst = {
                    'InstanceId': instance.id,
                    'PublicIpAddress': instance.public_ip_address,
                    'SecurityGroups': [group['GroupId'] for group in instance.security_groups]
                }
                if name:
                    inst['Name'] = name

                if instance.key_pair:
                    inst['KeyPairName'] = instance.key_pair.key_name

                if verbose:
                    inst['ImageId'] = instance.image_id

                data.append(inst)
            print(pandas.DataFrame(data))
        else:
            print('There are no running instances')

    ### TERMINATING INSTANCES
    def terminate_instance(self, instance_id: str):
        print(colored(f'Terminating {instance_id}', 'magenta'))
        try:
            self.ec2_client.terminate_instances(InstanceIds=[
                instance_id
            ])
        except botocore.client.ClientError as e:
            if 'may not be terminated' in f"{e}":
                print(colored(f"The {instance_id} instance has API termination disabled", 'red'))

    def terminate_all_running_instances(self):
        print(colored('Terminating all running instances', 'magenta'))
        instances = self.get_running_instances()
        if instances:
            for instance in instances:
                self.terminate_instance(instance.id)
        else:
            print('Nothing to terminate')

    ### STARTING INSTANCES
    def run_instance(self,
                     image_id: str,
                     key_pair_name: str,
                     security_group_id: str,
                     instance_type: str,
                     instance_name: str,
                     volume_size: int,
                     block_device_name: str,
                     disable_api_termination: bool = False):
        print(f'Starting a new instance: '
              f'{image_id} {key_pair_name} {security_group_id} {instance_type} {instance_name}')
        print(f"EBS volume size is {volume_size} GB")
        if disable_api_termination:
            print(colored('API termination for that instance has been disabled', 'yellow'))
        response = self.ec2_client.run_instances(InstanceType=instance_type,
                                                 ImageId=image_id,
                                                 KeyName=key_pair_name,
                                                 SecurityGroupIds=[security_group_id],
                                                 BlockDeviceMappings=[{
                                                     'DeviceName': block_device_name,
                                                     'Ebs': {
                                                         'DeleteOnTermination': True,
                                                         'VolumeSize': volume_size,
                                                         'VolumeType': 'standard'
                                                     }
                                                 }],
                                                 TagSpecifications=[
                                                     {
                                                         'ResourceType': 'instance',
                                                         'Tags': [
                                                             {
                                                                 'Key': 'Name',
                                                                 'Value': instance_name
                                                             },
                                                         ]
                                                     },
                                                 ],
                                                 DisableApiTermination=disable_api_termination,
                                                 # The maximum number of instances to launch.
                                                 MaxCount=1,
                                                 MinCount=1
                                                 )
        new_instance = response['Instances'][0]
        if new_instance:
            print(colored('The instance has been created', 'green'))
            print('Waiting for the server boot...')
            instance = self.get_instance(new_instance['InstanceId'])
            instance.wait_until_running()
            print(f'The server is up and running at {colored(instance.public_ip_address, "green")}')
            return instance

    def invoke_script(self, instance_id: str,
                      file_name: str,
                      parameters: list = None,
                      key_pair_path: str = None):
        instance = self.get_instance(instance_id=instance_id)
        ip_address = instance.public_ip_address
        username = self.ami_kommandos.get_default_ami_user_name(image_id=instance.image_id)
        print(colored(f"Invoking the {file_name} script on the instance hosted at {ip_address}", 'yellow'))

        if not key_pair_path:
            key_pair_path = f"{self.home_folder}/{instance.key_pair.name}.pem"

        if not os.path.exists(key_pair_path):
            raise Exception(f"The RSA private key '{key_pair_path}' has not been found at the given path")

        if parameters:
            print(colored(f"Script parameters are: {parameters}", 'yellow'))
            script_name = f"{file_name}-kommandos-temp"

            content = ''
            with open(file_name, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    for param in parameters:
                        param_name = param.split('=')[0]
                        if line.startswith(param_name):
                            line = param
                    content += line
                    content += os.linesep
            with open(script_name, 'w') as f:
                f.write(content)
        else:
            script_name = file_name

        remote_script_folder = "/tmp"
        if '/' in script_name:
            remote_script_name = f"{remote_script_folder}/{script_name.split('/')[-1]}"
        else:
            remote_script_name = f"{remote_script_folder}/{script_name}"

        subprocess.call(['scp', '-o', 'StrictHostKeyChecking=accept-new',
                         '-i', key_pair_path,
                         script_name, f"{username}@{ip_address}:{remote_script_name}"])
        subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=accept-new',
                         '-i', key_pair_path,
                         f"{username}@{ip_address}",
                         "/bin/bash", remote_script_name])
        print(colored(f"The '{file_name}' script has been invoked as {username}@{ip_address}", 'yellow'))

        if script_name.endswith('-kommandos-temp'):
            os.remove(script_name)
