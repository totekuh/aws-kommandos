#!/usr/bin/env python3
import os
import sys
from pprint import pprint

import boto3

# ubuntu server 20.04
DEFAULT_IMAGE_ID = 'ami-0746eb3cb5c684ae6'
DEFAULT_INSTANCE_TYPE = 't2.micro'
DEFAULT_INSTANCE_NAME = 'proxy-instance'
DEFAULT_KEY_NAME = 'proxy-key'

if 'win' in sys.platform:
    print("Windows ain't supported")
    exit()


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description='AWS Kommandos Script')

    # COMMANDS
    starting_commands = parser.add_argument_group('Starting Instances')
    starting_commands.add_argument("--start",
                                   dest="start",
                                   action='store_true',
                                   required=False,
                                   help="Start a new EC2 instance")
    starting_commands.add_argument('--invoke-script',
                                   dest='invoke_script',
                                   required=False,
                                   type=str,
                                   help="Specify a filename of a script to execute on remote. "
                                        "You can grab a predefined one from the instance-scripts folder "
                                        "or supply your own.")
    starting_commands.add_argument("--instance-type",
                                   dest="instance_type",
                                   required=False,
                                   default=DEFAULT_INSTANCE_TYPE,
                                   type=str,
                                   help="Specify the instance type to use. "
                                        f"Default is {DEFAULT_INSTANCE_TYPE}")
    starting_commands.add_argument("--instance-name",
                                   dest="instance_name",
                                   required=False,
                                   default=DEFAULT_INSTANCE_NAME,
                                   type=str,
                                   help="Specify the instance name. "
                                        f"Default is {DEFAULT_INSTANCE_NAME}")

    stats = parser.add_argument_group('Getting AWS Overview')
    stats.add_argument("--stats",
                       dest="stats",
                       action='store_true',
                       required=False,
                       help="Print the current stats to the console")

    termination = parser.add_argument_group('Terminating Instances')
    termination.add_argument('--terminate',
                             dest='terminate',
                             required=False,
                             type=str,
                             help="Terminate an instance with the given instance id")
    termination.add_argument("--terminate-all",
                             dest="terminate_all",
                             action='store_true',
                             required=False,
                             help="Terminate all running EC2 instances")

    ami = parser.add_argument_group('Working with AMI')
    ami.add_argument('--search-ami',
                     dest='search_ami',
                     required=False,
                     type=str,
                     help="Search for the matching AMI images")
    ami.add_argument('--get-ami',
                     dest='get_ami',
                     action='store_true',
                     required=False,
                     help="Print information about the given AMI. "
                          "Goes together with --image-id when omitted always gets data about the default image.")
    ami.add_argument("--image-id",
                     dest="image_id",
                     required=False,
                     default=DEFAULT_IMAGE_ID,
                     type=str,
                     help="Specify the image id to use while creating an instance. "
                          f"Default is {DEFAULT_IMAGE_ID} (Ubuntu 20.04).")

    firewall = parser.add_argument_group('Managing AWS Firewall')
    firewall.add_argument('--allow-inbound',
                          dest='allow_inbound',
                          required=False,
                          type=str,
                          help="Specify an inbound firewall rule to be applied for the given security group and "
                               "eventually for created instances. "
                               "Should be in the following format: --allow-inbound 443/tcp:10.10.10.10/32:HTTPS-rule")
    firewall.add_argument('--allow-outbound',
                          dest='allow_outbound',
                          required=False,
                          type=str,
                          help="Specify an outbound firewall rule to be applied for the given security group and "
                               "eventually for created instances. "
                               "Should be in the following format: --allow-outbound 443/tcp:10.10.10.10/32:HTTPS-rule")
    firewall.add_argument('--delete-inbound',
                          dest='delete_inbound',
                          required=False,
                          type=str,
                          help="Specify an inbound firewall rule to be deleted from the given security group and "
                               "eventually from linked instances. "
                               "Should be in the following format: --delete-inbound 443/tcp:10.10.10.10/32:HTTPS-rule")
    firewall.add_argument('--delete-outbound',
                          dest='delete_outbound',
                          required=False,
                          type=str,
                          help="Specify an outbound firewall rule to be deleted from the given security group and "
                               "eventually from linked instances. "
                               "Should be in the following format: --delete-outbound 443/tcp:10.10.10.10/32:HTTPS-rule")
    firewall.add_argument("--security-group-id",
                          dest="security_group_id",
                          required=False,
                          type=str,
                          help="Specify the security group ID to use for a newly created instance "
                               "or for changing firewall rules")

    ssh_keys = parser.add_argument_group('Managing SSH Keys')
    ssh_keys.add_argument("--key-pair-name",
                          dest="key_pair_name",
                          required=False,
                          default=DEFAULT_KEY_NAME,
                          type=str,
                          help="Specify the key pair name to use alongside the created instance. "
                               f"Default is '{DEFAULT_KEY_NAME}'.")
    ssh_keys.add_argument("--force-recreate-key",
                          dest="force_recreate_key",
                          action='store_true',
                          required=False,
                          help="Recreate the SSH key pair if already exists")

    options = parser.parse_args()
    if options.start:
        if not options.security_group_id:
            parser.error('The --security-group-id arg cannot be blank when requesting a new instance. '
                         'Use --help for more info.')
        if options.invoke_script and not os.path.exists(options.invoke_script):
            parser.error("The script file you're providing with --invoke-script doesn't seem to exist")
    else:
        if options.invoke_script:
            parser.error("Invoking scripts on remote is only supported while creating new instances (at least yet)")
    if options.terminate and options.terminate_all:
        parser.error("You must use either --terminate <instance-id> or --terminate-all. Because I said so."
                     "Use --help for more info.")
    if (options.allow_inbound or options.allow_outbound or options.delete_inbound or options.delete_outbound) \
            and not options.security_group_id:
        parser.error('The --security-group-id argument must be provided whenever you wanna change the firewall rules. '
                     'Use --help for more info.')
    return options


class FirewallRuleRequest:
    def __init__(self, rule_from_command_line):
        if ':' not in rule_from_command_line:
            raise Exception('Invalid format of the firewall rule. Use --help to see an example.')
        chunks = rule_from_command_line.split(':')
        if len(chunks) != 3:
            raise Exception('Invalid number of chunks in the rule. Use --help to see an example.')
        if '/' not in chunks[0]:
            raise Exception('Invalid port specification format. Use --help to see an example.')
        port_specification = chunks[0].split('/')
        try:
            self.port = int(port_specification[0])
        except Exception as ex:
            ex.args = ('Port must be a number. Use --help for more info.',)
            raise
        self.protocol = port_specification[1]
        self.ipv4_address = chunks[1]
        self.description = chunks[2]


class AwsManager:
    def __init__(self):
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')

    ## SSH KEY PAIRS
    ### GETTING KEY PAIRS
    def get_key_pairs(self):
        key_pairs = []
        response = self.client.describe_key_pairs()
        if response and 'KeyPairs' in response:
            for key_pair in response['KeyPairs']:
                key_pairs.append(key_pair)
        return key_pairs

    def print_key_pairs(self):
        key_pairs = self.get_key_pairs()
        if key_pairs:
            print('The SSH key pairs are:')
            for kp in key_pairs:
                pprint(kp, sort_dicts=False)
        else:
            print('There are no SSH key pairs')

    ### CREATING A KEY PAIR
    def create_key_pair(self, key_name: str):
        print(f"Creating a new SSH key pair: {key_name}")
        response = self.client.create_key_pair(KeyName=key_name)
        if response and 'KeyMaterial' in response:
            private_key = response['KeyMaterial']
            file_name = f"{key_name}.pem"

            print(f'Saving the private key to {file_name}')
            with open(file_name, 'w') as f:
                f.write(private_key)
            # 0x400 -r--------
            os.chmod(file_name, 0o400)

    ### DELETE A KEY PAIR
    def delete_key_pair(self, key_name: str):
        print(f"Deleting the SSH key pair: {key_name}")
        self.client.delete_key_pair(KeyName=key_name)

        file_name = f"{key_name}.pem"
        if os.path.exists(file_name):
            os.chmod(file_name, 0o600)
            os.remove(file_name)

    ## SECURITY GROUPS
    ### GET SECURITY GROUPS
    def get_all_security_groups(self):
        security_groups = []
        response = self.client.describe_security_groups()
        if response and 'SecurityGroups' in response:
            for sg in response['SecurityGroups']:
                security_groups.append(sg)
        return security_groups

    def print_security_groups(self):
        def security_rule_to_string(rule: dict):
            if rule['IpProtocol'] == '-1':
                return f"{';'.join([ip['CidrIp'] for ip in rule['IpRanges']])} -> All Traffic"
            else:
                return f"{';'.join([ip['CidrIp'] for ip in rule['IpRanges']])} " \
                       f"-> {rule['FromPort']}/{rule['IpProtocol']}"

        security_groups = self.get_all_security_groups()
        if security_groups:
            print('Security groups are:')
            for sg in security_groups:
                group_id = sg['GroupId']
                description = sg['Description']
                ip_permissions = []
                for rule in sg['IpPermissions']:
                    ip_permissions.append(security_rule_to_string(rule))

                ip_permissions_egress = []
                for rule in sg['IpPermissionsEgress']:
                    ip_permissions_egress.append(security_rule_to_string(rule))

                group = {
                    'GroupId': group_id,
                    'Description': description,
                    'IpPermissionsIngress': ip_permissions,
                    'IpPermissionsEgress': ip_permissions_egress
                }
                pprint(group, sort_dicts=False)

    ### CREATE A NEW SECURITY GROUP
    def create_security_group(self):
        raise Exception('Not implemented yet')

    def add_ingress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
        raise Exception('Not implemented yet')

    def add_egress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
        raise Exception('Not implemented yet')

    def delete_ingress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
        raise Exception('Not implemented yet')

    def delete_egress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
        raise Exception('Not implemented yet')

    ## AMI IMAGES
    def get_ami_image(self, image_id: str):
        return self.client.describe_images(
            ImageIds=[
                image_id
            ]
        )

    def search_ami_images(self, query: str):
        images = []
        resp = self.client.describe_images(
            Filters=[
                {
                    'Name': 'name',
                    'Values': [f"*{query}*"]
                }
            ]
        )
        if 'Images' not in resp or len(resp['Images']) == 0:
            return images
        else:
            for image in resp['Images']:
                images.append(image)
            return images

    def get_default_ami_user_name(self, image_id: str):
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connection-prereqs.html
        user_mapping = {
            'amazon-linux': 'ec2-user',
            'centos': 'centos',
            'debian': 'admin',
            'fedora': 'fedora',
            'rhel': 'ec2-user',
            'suse': 'ec2-user',
            'ubuntu': 'ubuntu'
        }
        resp = self.get_ami_image(image_id=image_id)
        if resp and 'Images' in resp:
            if len(resp['Images']) != 1:
                raise Exception(f"More than 1 result has been returned by the given AMI image id: {image_id}")
            else:
                image = resp['Images'][0]

                identified_user_name = ''
                for os, user in user_mapping.items():
                    if 'Name' in image and os in image['Name'].lower():
                        identified_user_name = user
                        break
                    elif 'ImageLocation' in image and os in image['ImageLocation'].lower():
                        identified_user_name = user
                        break
                    elif 'Description' in image and os in image['Description'].lower():
                        identified_user_name = user
                        break
                if not identified_user_name:
                    # resort to the default one
                    identified_user_name = 'ec2-user'
                print(f"The default user of the AMI '{image_id}' has been identified as '{identified_user_name}'")
                return identified_user_name

    ## EC2 INSTANCES
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

    def print_running_instances(self):
        instances = self.get_running_instances()
        if instances:
            print('Running instances are:')
            for instance in instances:
                instance_id = instance.id
                key_pair_name = instance.key_pair.key_name
                public_ip_address = instance.public_ip_address
                image_id = instance.image_id
                name = ''
                for tag in instance.tags:
                    if 'Key' in tag and tag['Key'] == 'Name':
                        name = tag['Value']
                inst = {
                    'InstanceId': instance_id,
                    'KeyPairName': key_pair_name,
                    'PublicIpAddress': public_ip_address,
                    'ImageId': image_id,
                }
                if name:
                    inst['Name'] = name

                pprint(inst, sort_dicts=False)
        else:
            print('There are no running instances')

    ### TERMINATING INSTANCES
    def terminate_instance(self, instance_id: str):
        print(f'Terminating {instance_id}')
        self.client.terminate_instances(InstanceIds=[
            instance_id
        ])

    def terminate_all_running_instances(self):
        print('Terminating all running instances')
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
                     instance_name: str):
        print(f'Starting a new instance: '
              f'{image_id} {key_pair_name} {security_group_id} {instance_type} {instance_name}')
        response = self.client.run_instances(InstanceType=instance_type,
                                             ImageId=image_id,
                                             KeyName=key_pair_name,
                                             SecurityGroupIds=[security_group_id],
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
                                             # The maximum number of instances to launch.
                                             # If you specify more instances than Amazon EC2 can launch
                                             # in the target Availability Zone,
                                             # Amazon EC2 launches the largest possible number of instances above MinCount.
                                             MaxCount=1,
                                             MinCount=1
                                             )
        new_instance = response['Instances'][0]
        if new_instance:
            print('The instance has been created')
            print('Waiting for the server boot...')
            instance = aws_manager.get_instance(new_instance['InstanceId'])
            instance.wait_until_running()
            print(f'The server is up and running at {instance.public_ip_address}')
            print('Waiting until the SSH service is available...')
            aws_manager.poll_ssh_status(instance.id)
            identified_user_name = self.get_default_ami_user_name(instance.image_id)
            print("Use the following command for connecting to the instance: " +
                  f"ssh {identified_user_name}@{instance.public_ip_address} -i {key_pair_name}.pem")
            return instance

    def invoke_script(self, instance_id: str, file_name: str, key_pair_name: str):
        instance = self.get_instance(instance_id=instance_id)
        ip_address = instance.public_ip_address
        username = self.get_default_ami_user_name(image_id=instance.image_id)
        print(f"Invoking the {file_name} script on the instance hosted at {ip_address}")

        # did you even know you could pipe commands like this?
        os.system(f"cat {file_name} | "
                  f'ssh -o "StrictHostKeyChecking=accept-new" {username}@{ip_address} -i {key_pair_name}.pem')


if __name__ == '__main__':
    options = get_arguments()

    key_pair_name = options.key_pair_name
    image_id = options.image_id
    security_group_id = options.security_group_id
    instance_type = options.instance_type
    instance_name = options.instance_name

    aws_manager = AwsManager()

    if options.get_ami:
        image = aws_manager.get_ami_image(image_id=image_id)
        pprint(image)
        default_ami_user = aws_manager.get_default_ami_user_name(image_id=image_id)

    if options.terminate:
        aws_manager.terminate_instance(instance_id=options.terminate)
    elif options.terminate_all:
        aws_manager.terminate_all_running_instances()

    if options.allow_inbound:
        aws_manager.add_ingress_rule(firewall_rule_request=FirewallRuleRequest(options.allow_inbound),
                                     security_group_id=options.security_group_id)
    if options.allow_outbound:
        aws_manager.add_egress_rule(firewall_rule_request=FirewallRuleRequest(options.allow_outbound),
                                    security_group_id=options.security_group_id)
    if options.delete_inbound:
        aws_manager.delete_ingress_rule(firewall_rule_request=FirewallRuleRequest(options.delete_inbound),
                                        security_group_id=options.security_group_id)
    if options.delete_outbound:
        aws_manager.delete_egress_rule(firewall_rule_request=FirewallRuleRequest(options.delete_outbound),
                                       security_group_id=options.security_group_id)

    if options.stats:
        aws_manager.print_running_instances()
        print('*' * 70)
        aws_manager.print_key_pairs()
        print('*' * 70)
        aws_manager.print_security_groups()
    elif options.search_ami:
        images = aws_manager.search_ami_images(query=options.search_ami)
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
    elif options.start:
        if options.force_recreate_key:
            aws_manager.delete_key_pair(key_name=key_pair_name)
        try:
            aws_manager.create_key_pair(key_name=key_pair_name)
        except Exception as e:
            if 'InvalidKeyPair.Duplicate' in f"{e}":
                print(f"The SSH key pair with the name '{key_pair_name}' already exists")
            else:
                print(f"{type(e)} {e}")
                exit(1)

        new_instance = aws_manager.run_instance(image_id=image_id,
                                                key_pair_name=key_pair_name,
                                                security_group_id=security_group_id,
                                                instance_type=options.instance_type,
                                                instance_name=instance_name)
        if options.invoke_script:
            aws_manager.invoke_script(instance_id=new_instance.instance_id,
                                      file_name=options.invoke_script,
                                      key_pair_name=key_pair_name)
