#!/usr/bin/env python3
import os
import sys
from pprint import pprint

import boto3
import pandas as pd
from termcolor import colored

from ami_kommandos import AMIKommandos
from command_line import DEFAULT_SECURITY_GROUP_NAME
from command_line import get_arguments
from dns_kommandos import DnsKommandos
from ec2_instance_kommandos import EC2InstanceKommandos
from firewall_rule_request import FirewallRuleRequest
from s3_bucket_kommandos import S3BucketKommands
from security_groups_kommandos import SecurityGroupsKommandos
from ssh_key_pairs_kommandos import SSHKeyPairsKommandos

if 'win' in sys.platform:
    print("Windows ain't supported")
    exit()
pd.options.styler.render.max_columns = None # show all cols
pd.options.display.max_colwidth = None # show full width of showing cols
pd.options.display.expand_frame_repr = False # print cols side by side as it's supposed to be
pd.options.display.max_rows = 300

class AwsManager:
    def __init__(self,
                 home_folder: str,
                 s3_bucket_name: str,
                 aws_access_key_id: str = None,
                 aws_access_key_secret: str = None,
                 region_name: str = None, ):
        self.home_folder = home_folder
        self.s3_bucket_name = s3_bucket_name
        try:
            self.ec2_client = boto3.client('ec2', aws_access_key_id=aws_access_key_id,
                                           aws_secret_access_key=aws_access_key_secret,
                                           region_name=region_name)
            self.ec2 = boto3.resource('ec2', aws_access_key_id=aws_access_key_id,
                                      aws_secret_access_key=aws_access_key_secret,
                                      region_name=region_name)
            self.dns_kommandos = DnsKommandos(
                route53_client=boto3.client('route53', aws_access_key_id=aws_access_key_id,
                                            aws_secret_access_key=aws_access_key_secret,
                                            region_name=region_name))
            self.bucket_kommandos = S3BucketKommands(
                s3_client=boto3.client('s3', aws_access_key_id=aws_access_key_id,
                                       aws_secret_access_key=aws_access_key_secret,
                                       region_name=region_name),
                s3_bucket_name=s3_bucket_name,
                home_folder=home_folder)
            self.ssh_key_pairs_kommandos = SSHKeyPairsKommandos(
                ec2_client=self.ec2_client,
                bucket_kommandos=self.bucket_kommandos
            )
            self.security_groups_kommandos = SecurityGroupsKommandos(
                ec2=self.ec2,
                ec2_client=self.ec2_client)
            self.ami_kommandos = AMIKommandos(
                ec2_client=self.ec2_client
            )
            self.ec2_instance_kommandos = EC2InstanceKommandos(
                ec2=self.ec2,
                ec2_client=self.ec2_client,
                home_folder=self.home_folder,
                ami_kommandos=self.ami_kommandos
            )
            if not os.path.exists(self.home_folder):
                os.makedirs(self.home_folder)
                print(f"The Kommandos's home folder has been created at '{self.home_folder}'. "
                      f"The SSH private keys to be created by Kommandos will be stored there.")

            if not self.bucket_kommandos.get_bucket(self.s3_bucket_name):
                print("Creating a new Kommandos S3 bucket, as it doesn't seem to exist yet")
                self.bucket_kommandos.create_bucket(bucket_name=self.s3_bucket_name)

        except Exception as e:
            print(f"Kommandos initialization failed: {e}")
            exit(1)


def main():
    options = get_arguments()

    # find credentials
    if options.access_key_id and options.access_key_secret and options.region_name:
        access_key_id = options.access_key_id
        access_key_secret = options.access_key_secret
        region_name = options.region_name
    elif 'AWS_ACCESS_KEY_ID' in os.environ \
            and 'AWS_ACCESS_KEY_SECRET' in os.environ \
            and 'AWS_REGION' in os.environ:
        access_key_id = os.environ['AWS_ACCESS_KEY_ID']
        access_key_secret = os.environ['AWS_ACCESS_KEY_SECRET']
        region_name = os.environ['AWS_REGION']
    else:
        # assume the AWS client's been already configured
        access_key_id = None
        access_key_secret = None
        region_name = None

    # override the region if only --region-name has been supplied
    if options.region_name:
        region_name = options.region_name

    key_pair_name = options.key_pair_name
    image_id = options.image_id

    instance_name = options.instance_name

    domain_name = options.fqdn
    poll_ssh = options.poll_ssh

    aws_manager = AwsManager(home_folder=options.home_folder,
                             s3_bucket_name=options.s3_bucket_name,
                             aws_access_key_id=access_key_id,
                             aws_access_key_secret=access_key_secret,
                             region_name=region_name)
    security_group_id = options.security_group_id

    if not security_group_id:
        # fetch the default one or create it if it doesn't exist yet
        security_group = \
            aws_manager.security_groups_kommandos.get_security_group_by_name(
                security_group_name=DEFAULT_SECURITY_GROUP_NAME)
        if not security_group:
            print(f"There's no default security group, creating one now")
            security_group = \
                aws_manager.security_groups_kommandos.create_security_group(
                    group_name=DEFAULT_SECURITY_GROUP_NAME,
                    description='Kommandos default security group')
            security_group_id = security_group.group_id

    if options.get_ami:
        image = aws_manager.ami_kommandos.get_ami_image(image_id=image_id)
        pprint(image)
        aws_manager.ami_kommandos.get_default_ami_user_name(image_id=image_id)

    if options.delete_key_pair:
        aws_manager.ssh_key_pairs_kommandos.delete_key_pair(key_name=key_pair_name)

    if options.terminate:
        aws_manager.ec2_instance_kommandos.terminate_instance(instance_id=options.terminate)
    elif options.terminate_all:
        aws_manager.ec2_instance_kommandos.terminate_all_running_instances()

    if options.add_record:
        aws_manager.dns_kommandos.create_dns_record(hosted_zone_name=domain_name,
                                                    record_type=options.record_type,
                                                    record_value=options.record_value,
                                                    ttl=options.ttl)
    if options.delete_record:
        aws_manager.dns_kommandos.delete_dns_record(hosted_zone_name=domain_name,
                                                    record_type=options.record_type,
                                                    record_value=options.record_value,
                                                    ttl=options.ttl)

    if options.create_security_group:
        group_name = options.create_security_group
        if ':' in group_name:
            chunks = group_name.split(':', maxsplit=1)
            name = chunks[0]
            description = chunks[1]
        else:
            name = group_name
            description = f"{name}-generated-by-kommandos"
        aws_manager.security_groups_kommandos.create_security_group(group_name=name,
                                                                    description=description)

    if options.delete_security_group:
        aws_manager.security_groups_kommandos.delete_security_group(security_group_id=security_group_id)

    if options.allow_inbound:
        for rule in options.allow_inbound:
            aws_manager.security_groups_kommandos.add_ingress_rule(firewall_rule_request=FirewallRuleRequest(rule),
                                                                   security_group_id=security_group_id)
    if options.allow_outbound:
        for rule in options.allow_outbound:
            aws_manager.security_groups_kommandos.add_egress_rule(firewall_rule_request=FirewallRuleRequest(rule),
                                                                  security_group_id=security_group_id)
    if options.delete_inbound:
        for rule in options.delete_inbound:
            aws_manager.security_groups_kommandos.delete_ingress_rule(firewall_rule_request=FirewallRuleRequest(rule),
                                                                      security_group_id=security_group_id)
    if options.delete_outbound:
        for rule in options.delete_outbound:
            aws_manager.security_groups_kommandos.delete_egress_rule(firewall_rule_request=FirewallRuleRequest(rule),
                                                                     security_group_id=security_group_id)

    if options.stats:
        aws_manager.ec2_instance_kommandos.print_running_instances(verbose=options.verbose)
        aws_manager.ssh_key_pairs_kommandos.print_key_pairs(verbose=options.verbose)
        aws_manager.security_groups_kommandos.print_security_groups(verbose=options.verbose)
        aws_manager.dns_kommandos.print_hosted_zones(verbose=options.verbose)
    elif options.search_ami:
        images = aws_manager.ami_kommandos.search_ami_images(query=options.search_ami)
        if images:
            for image in images:
                img = {
                    'CreationDate': image['CreationDate'],
                    'ImageId': image['ImageId'],
                    'State': image['State']
                }
                if 'Name' in image:
                    img['Name'] = image['Name']
                if 'ImageLocation' in image:
                    img['ImageLocation'] = image['ImageLocation']
                if 'Description' in image:
                    img['Description'] = image['Description']
                if 'ImageOwnerAlias' in image:
                    img['ImageOwnerAlias'] = image['ImageOwnerAlias']
                pprint(img, sort_dicts=False)
            print(f"{len(images)} AMI images found")
        else:
            print('No images found')
    elif options.connect:
        instance_id = options.connect
        instance = aws_manager.ec2_instance_kommandos.get_instance(instance_id=instance_id)

        public_ip = instance.public_ip_address
        print(f"Connecting to {public_ip}")

        if hasattr(instance, 'key_name') and instance.key_name:
            if not key_pair_name:
                key_pair_name = instance.key_name

            key_path = f"{aws_manager.home_folder}/{key_pair_name}.pem"
            if not os.path.exists(key_path):
                aws_manager.ssh_key_pairs_kommandos.download_key_pair_from_s3(key_pair_name)

            if options.user:
                user_name = options.user
            else:
                user_name = aws_manager.ami_kommandos.get_default_ami_user_name(instance.image_id)
            key_path = f"{aws_manager.home_folder}/{key_pair_name}.pem"
            if options.ssh_append:
                append = options.ssh_append
            else:
                append = ''
            ssh_cmd = f"ssh -oStrictHostKeyChecking=no {user_name}@{public_ip} -i {key_path} {append}"
            print(colored(f"Using the following command: {ssh_cmd}", 'green'))
            os.system(ssh_cmd)
        else:
            print(colored("The instance doesn't seem to have an SSH key pair attached", 'red'))

    elif options.start:
        instances = aws_manager.ec2_instance_kommandos.find_instance(instance_name=instance_name)
        if instances['Reservations']:
            print(colored(f"An instance with the name '{instance_name}' already exists, "
                          f"use --instance-name to override", 'red'))
            exit(1)

        if not key_pair_name:
            key_pair_name = instance_name

        if options.force_recreate_key:
            aws_manager.ssh_key_pairs_kommandos.delete_key_pair(key_name=key_pair_name)
        try:
            aws_manager.ssh_key_pairs_kommandos.create_key_pair(key_name=key_pair_name)
        except Exception as e:
            if 'InvalidKeyPair.Duplicate' in f"{e}":
                print(colored(f"The SSH key pair with the name '{key_pair_name}' already exists", 'yellow'))
            else:
                print(f"{type(e)} {e}")
                exit(1)

        disable_termination = options.disable_api_termination
        new_instance = aws_manager.ec2_instance_kommandos.run_instance(image_id=image_id,
                                                                       key_pair_name=key_pair_name,
                                                                       security_group_id=security_group_id,
                                                                       instance_type=options.instance_type,
                                                                       instance_name=instance_name,
                                                                       volume_size=options.volume_size,
                                                                       block_device_name=options.block_device_name,
                                                                       disable_api_termination=disable_termination)
        if options.link_fqdn:
            ttl = options.ttl
            aws_manager.dns_kommandos.create_dns_record(hosted_zone_name=domain_name,
                                                        record_type='A',
                                                        record_value=new_instance.public_ip_address,
                                                        ttl=ttl)
            aws_manager.dns_kommandos.create_dns_record(hosted_zone_name=domain_name,
                                                        record_type='MX',
                                                        record_value=f"1 {new_instance.public_ip_address}",
                                                        ttl=ttl)
        if options.invoke_script:
            if poll_ssh:
                print('Waiting until the SSH service is available...')
                aws_manager.ec2_instance_kommandos.poll_ssh_status(new_instance.id)

            aws_manager.ec2_instance_kommandos.invoke_script(instance_id=new_instance.instance_id,
                                                             file_name=options.invoke_script,
                                                             parameters=options.invoke_script_argument)
        if poll_ssh:
            print('Waiting until the SSH service becomes available...')
            aws_manager.ec2_instance_kommandos.poll_ssh_status(new_instance.id)
            print("Connecting to the newly created instance")

            key_path = f"{aws_manager.home_folder}/{key_pair_name}.pem"
            if os.path.exists(key_path):
                print("The private key already exists on the file system, use --force-recreate-key to overwrite")
            else:
                aws_manager.ssh_key_pairs_kommandos.download_key_pair_from_s3(key_pair_name)

            identified_user_name = aws_manager.ami_kommandos.get_default_ami_user_name(new_instance.image_id)
            key_path = f"{aws_manager.home_folder}/{key_pair_name}.pem"
            os.system(
                f"ssh -oStrictHostKeyChecking=no {identified_user_name}@{new_instance.public_ip_address} -i {key_path}")
    else:
        print(f"Nothing to do. Specify specify a command. Use --help for more info.")


if __name__ == '__main__':
    main()
