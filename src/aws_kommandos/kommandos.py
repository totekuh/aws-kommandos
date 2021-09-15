#!/usr/bin/env python3
import os
import subprocess
import sys
from pprint import pprint

import boto3
import botocore.client
from termcolor import colored

# ubuntu server 18.04
DEFAULT_IMAGE_ID = 'ami-0b1deee75235aa4bb'
DEFAULT_INSTANCE_TYPE = 't2.micro'
DEFAULT_INSTANCE_NAME = 'kommandos-instance'
DEFAULT_KEY_NAME = 'kommandos-key'

DEFAULT_DNS_TTL = 86400

if 'win' in sys.platform:
    print("Windows ain't supported")
    exit()


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description='AWS Kommandos Script')

    # EC2 Starting Instances
    starting_commands = parser.add_argument_group('Starting Instances')
    starting_commands.add_argument("--start",
                                   dest="start",
                                   action='store_true',
                                   required=False,
                                   help="Start a new EC2 instance")
    starting_commands.add_argument('-dat',
                                   '--disable-api-termination',
                                   dest='disable_api_termination',
                                   action='store_true',
                                   required=False,
                                   help="Provide this flag to disable API termination of the new instance. "
                                        "You would need to manually login to the AWS console "
                                        "for disabling the instance. "
                                        "Useful if you wanna ensure you won't accidentally terminate "
                                        "the required instance.")
    starting_commands.add_argument('--link-fqdn',
                                   action='store_true',
                                   dest='link_fqdn',
                                   required=False,
                                   help="Instruct the Kommandos script to automatically "
                                        "create A and MX records pointing "
                                        "to the IP address of the newly created instance "
                                        "for the domain specified with the --fqdn flag. "
                                        "You must own the domain name and have the hosted zone for doing that.")
    starting_commands.add_argument('-is',
                                   '--invoke-script',
                                   dest='invoke_script',
                                   required=False,
                                   type=str,
                                   help="Specify a filename of a script to execute on remote. "
                                        "You can either grab one from the ./instance-scripts/ folder "
                                        "or supply your own.")
    starting_commands.add_argument('-is-arg',
                                   '--invoke-script-argument',
                                   dest='invoke_script_argument',
                                   action='append',
                                   required=False,
                                   type=str,
                                   help="Provide an argument for the specified --invoke-script script. "
                                        "This options can be passed multiple times. "
                                        "The parameters being passed to the script must be specified "
                                        "in the script itself. "
                                        "Every parameter definition must start from the new line. "
                                        "Must be used in the following format: "
                                        "-is-arg MICROSOCKS_IP=127.0.0.1 or "
                                        "-is-arg MICROSOCKS_PORT=42024 or "
                                        "--invoke-script-argument MICROSOCKS_IP=127.0.0.1")
    starting_commands.add_argument("--instance-type",
                                   dest="instance_type",
                                   required=False,
                                   default=DEFAULT_INSTANCE_TYPE,
                                   type=str,
                                   help="Specify the instance type to use. "
                                        f"Default is '{DEFAULT_INSTANCE_TYPE}'.")
    starting_commands.add_argument("--instance-name",
                                   dest="instance_name",
                                   required=False,
                                   default=DEFAULT_INSTANCE_NAME,
                                   type=str,
                                   help="Specify the instance name. "
                                        f"Default is '{DEFAULT_INSTANCE_NAME}'.")

    # Route53 Managing Domains
    route53 = parser.add_argument_group('Route53 Domain Management')
    route53.add_argument('--add-record',
                         dest='add_record',
                         action='store_true',
                         required=False,
                         help='Specify if a new record set with specified '
                              '--record-type '
                              'and --record-value '
                              'for --fqdn must be inserted.')
    route53.add_argument('--delete-record',
                         dest='delete_record',
                         action='store_true',
                         required=False,
                         help='Specify if the record set with specified '
                              '--record-type '
                              'and --record-value '
                              'for --fqdn must be deleted.')
    route53.add_argument('--record-type',
                         dest='record_type',
                         required=False,
                         choices=['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SOA', 'NS', 'SRV', 'PTR'],
                         type=str,
                         help='Specify the record type to use with --add-record or --delete-record')
    route53.add_argument('--record-value',
                         dest='record_value',
                         required=False,
                         type=str,
                         help="Specify the record value to use with --add-record or --delete-record")
    route53.add_argument('--ttl',
                         dest='ttl',
                         required=False,
                         default=DEFAULT_DNS_TTL,
                         type=int,
                         help='Specify the TTL value to use while creating DNS record sets. '
                              f"Default is '{DEFAULT_DNS_TTL}'.")
    route53.add_argument('--fqdn',
                         dest='fqdn',
                         required=False,
                         type=str,
                         help="Specify the domain name (FQDN) to use with --add-record or --delete-record "
                              "or with the --link-fqdn flag for linking it to a new EC2 instance")

    stats = parser.add_argument_group('Getting AWS Overview')
    stats.add_argument("--stats",
                       dest="stats",
                       action='store_true',
                       required=False,
                       help="Print the current stats to the console")
    stats.add_argument('-v',
                       '--verbose',
                       dest='verbose',
                       action='store_true',
                       required=False,
                       help="Be verbose. Print detailed stats.")

    termination = parser.add_argument_group('Terminating Instances')
    termination.add_argument('--terminate',
                             dest='terminate',
                             required=False,
                             type=str,
                             help="Terminate an instance with the given instance id")
    termination.add_argument('-ta',
                             "--terminate-all",
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
    firewall.add_argument('--create-security-group',
                          dest='create_security_group',
                          required=False,
                          type=str,
                          help='Create a new security group with the specified name. '
                               '--create-security-group "KommandosGroup" '
                               'or --create-security-group "KommandosGroup: My security group"')
    firewall.add_argument('--delete-security-group',
                          dest='delete_security_group',
                          action='store_true',
                          required=False,
                          help="Delete the security group with the given --security-group-id")
    firewall.add_argument('--allow-inbound',
                          dest='allow_inbound',
                          action='append',
                          required=False,
                          type=str,
                          help="Specify an inbound firewall rule to be applied for the given security group and "
                               "eventually for created instances. Can be passed multiple times. "
                               "Should be in the following format: --allow-inbound 443/tcp:10.10.10.10/32:HTTPS-rule "
                               "or --allow-inbound 443/tcp:10.10.10.10/32")
    firewall.add_argument('--allow-outbound',
                          dest='allow_outbound',
                          action='append',
                          required=False,
                          type=str,
                          help="Specify an outbound firewall rule to be applied for the given security group and "
                               "eventually for created instances. Can be passed multiple times. "
                               "Should be in the following format: --allow-outbound 443/tcp:10.10.10.10/32:HTTPS-rule "
                               "or --allow-outbound 443/tcp:10.10.10.10/32")
    firewall.add_argument('--delete-inbound',
                          dest='delete_inbound',
                          action='append',
                          required=False,
                          type=str,
                          help="Specify an inbound firewall rule to be deleted from the given security group and "
                               "eventually from linked instances. Can be passed multiple times. "
                               "Should be in the following format: --delete-inbound 443/tcp:10.10.10.10/32:HTTPS-rule "
                               "or --delete-outbound 443/tcp:10.10.10.10/32")
    firewall.add_argument('--delete-outbound',
                          dest='delete_outbound',
                          action='append',
                          required=False,
                          type=str,
                          help="Specify an outbound firewall rule to be deleted from the given security group and "
                               "eventually from linked instances. Can be passed multiple times. "
                               "Should be in the following format: --delete-outbound 443/tcp:10.10.10.10/32:HTTPS-rule "
                               "or --delete-outbound 443/tcp:10.10.10.10/32")
    firewall.add_argument('-sg',
                          "--security-group-id",
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
    ssh_keys.add_argument('--delete-key-pair',
                          dest='delete_key_pair',
                          action='store_true',
                          required=False,
                          help="Specify if the key pair must be deleted. "
                               "Takes the value from the --key-pair-name parameter.")

    options = parser.parse_args()
    if options.invoke_script_argument:
        if not options.invoke_script:
            parser.error(f"--invoke-script-argument has been passed "
                         f"w/o the invocation script (--invoke-script) being provided. "
                         f"Use --help for more info.")
        else:
            with open(options.invoke_script, 'r') as f:
                invoke_script_content = f.read()
            invocation_arguments = options.invoke_script_argument
            # check the format first
            for param in invocation_arguments:
                if '=' not in param:
                    parser.error(f"The '{param}' invocation script parameter "
                                 f"doesn't fit the schema, as you must specify a parameter "
                                 f"and its value separated by '='. "
                                 f"Use --help for more info.")
                chunks = param.split('=')
                param_name = chunks[0]
                if not param_name:
                    parser.error(f"The '{param}' invocation script parameter "
                                 f"doesn't fit the schema, as the parameter's name can't be empty. "
                                 f"Use --help for more info.")
                if param_name not in invoke_script_content:
                    parser.error(f"The '{param_name}' parameter has not been found in the invocation script's content. "
                                 f"Consider putting the parameter into the script. "
                                 f"Use --help for more info.")
                if not chunks[1]:
                    parser.error(f"The '{param}' invocation script parameter "
                                 f"doesn't fit the schema, as the parameter's value can't be empty. "
                                 f"Use --help for more info.")

    if options.start:
        if not options.security_group_id:
            parser.error('The --security-group-id arg cannot be blank when requesting a new instance. '
                         'Use --help for more info.')
        if options.invoke_script and not os.path.exists(options.invoke_script):
            parser.error("The script file you're providing with --invoke-script doesn't seem to exist")
    else:
        if options.invoke_script:
            parser.error("Invoking scripts on remote is only supported while creating new instances (at least yet)")
    if options.delete_security_group and not options.security_group_id:
        parser.error('The --security-group-id argument is required for deleting a security group. '
                     'Use --help for more info')
    if options.terminate and options.terminate_all:
        parser.error("You must use either --terminate <instance-id> or --terminate-all. Because I said so."
                     "Use --help for more info.")
    if (options.allow_inbound or options.allow_outbound or options.delete_inbound or options.delete_outbound) \
            and not options.security_group_id:
        parser.error('The --security-group-id argument must be provided whenever you wanna change the firewall rules. '
                     'Use --help for more info.')

    if options.add_record or options.delete_record:
        if not options.record_type:
            parser.error('--record-type is required for adding new DNS records. Use --help for more info.')
        if not options.record_value:
            parser.error('--record-value is required for adding new DNS records. Use --help for more info.')
        if not options.fqdn:
            parser.error('--fqdn is required for adding new DNS records. Use --help for more info.')
    if options.link_fqdn and not options.fqdn:
        parser.error('A domain name with the --fqdn flag must be supplied for auto-creating the A and MX record sets. '
                     'Use --help for more info.')
    return options


class kommandos:
    def __init__(self, rule_from_command_line):
        if ':' not in rule_from_command_line:
            raise Exception('Invalid format of the firewall rule. Use --help to see an example.')
        chunks = rule_from_command_line.split(':')
        if len(chunks) != 2 and len(chunks) != 3:
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
        if len(chunks) == 3:
            self.description = chunks[2]
        else:
            self.description = ''

    def __repr__(self):
        return f"[{self.port}/{self.protocol} -> {self.ipv4_address}] - {self.description}"


class AwsManager:
    def __init__(self):
        self.ec2 = boto3.resource('ec2')
        self.route53_client = boto3.client('route53')
        self.ec2_client = boto3.client('ec2')

    ## DNS
    ### GETTING ALL HOSTING ZONES
    def get_all_hosted_zones(self):
        return self.route53_client.list_hosted_zones_by_name()['HostedZones']

    ### GETTING A HOSTING ZONE
    def get_hosted_zone(self, hosted_zone_name: str):
        return self.route53_client.list_hosted_zones_by_name(DNSName=hosted_zone_name)['HostedZones'][0]

    ### CREATING DNS RECORDS
    def create_dns_record(self, hosted_zone_name: str,
                          record_type: str,
                          record_value: str,
                          ttl: int):
        hosted_zone = self.get_hosted_zone(hosted_zone_name=hosted_zone_name)
        self.route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone['Id'],
            ChangeBatch={
                'Changes': [
                    {
                        'Action': "UPSERT",
                        'ResourceRecordSet': {
                            'Name': hosted_zone_name,
                            'Type': record_type,
                            'TTL': ttl,
                            'ResourceRecords': [{'Value': record_value}]
                        }
                    }]
            }
        )
        print(colored(f"A new record set {hosted_zone['Name']} {record_type} {record_value} has been created", 'green'))

    ### DELETING DNS RECORDS
    def delete_dns_record(self, hosted_zone_name: str,
                          record_type: str,
                          record_value: str,
                          ttl: int):
        hosted_zone = self.get_hosted_zone(hosted_zone_name=hosted_zone_name)
        try:
            self.route53_client.change_resource_record_sets(
                HostedZoneId=hosted_zone['Id'],
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': "DELETE",
                            'ResourceRecordSet': {
                                'Name': hosted_zone_name,
                                'Type': record_type,
                                'TTL': ttl,
                                'ResourceRecords': [{'Value': record_value}]
                            }
                        }]
                }
            )
            print(colored(f"The record set {hosted_zone['Name']} {record_type} {record_value} has been deleted",
                          'yellow'))
        except Exception as e:
            if "but it was not found" in f"{e}":
                print(colored(f"The record set {record_type} {record_value} for fqdn {hosted_zone_name} "
                              f"has not been found", 'red'))
            else:
                print(f"{type(e)} - {e}")

    ### GETTING RECORD SETS
    def get_record_sets(self, hosted_zone_id: str):
        return self.route53_client.list_resource_record_sets(
            HostedZoneId=hosted_zone_id
        )['ResourceRecordSets']

    ### PRINTING DNS STATS
    def print_hosted_zones(self, verbose: bool = False):
        hosted_zones = self.get_all_hosted_zones()

        if hosted_zones:
            print("Hosting zones are:")
            for zone in hosted_zones:
                hosted_zone_id = zone['Id']
                hz = {
                    'Name': zone['Name'],
                    'HostedZoneId': hosted_zone_id,
                }
                if verbose:
                    hz['ResourceRecordSets'] = self.get_record_sets(hosted_zone_id=hosted_zone_id)
                    pprint(hz, sort_dicts=False)
                else:
                    print(hz)
        else:
            print('No hosting zones found')

    ## SSH KEY PAIRS
    ### GETTING KEY PAIRS
    def get_key_pairs(self):
        key_pairs = []
        response = self.ec2_client.describe_key_pairs()
        if response and 'KeyPairs' in response:
            for key_pair in response['KeyPairs']:
                key_pairs.append(key_pair)
        return key_pairs

    def print_key_pairs(self, verbose: bool = False):
        key_pairs = self.get_key_pairs()
        if key_pairs:
            print('The SSH key pairs are:')
            for kp in key_pairs:
                key = {
                    'KeyPairId': kp['KeyPairId'],
                    'KeyName': kp['KeyName']
                }
                if verbose:
                    key['KeyFingerprint'] = kp['KeyFingerprint']
                    if 'Tags' in kp and kp['Tags']:
                        key['Tags'] = kp['Tags']
                pprint(key, sort_dicts=False)
        else:
            print('There are no SSH key pairs')

    ### CREATING A KEY PAIR
    def create_key_pair(self, key_name: str):
        print(f"Creating a new SSH key pair: {key_name}")
        response = self.ec2_client.create_key_pair(KeyName=key_name)
        if response and 'KeyMaterial' in response:
            private_key = response['KeyMaterial']
            file_name = f"{key_name}.pem"

            print(colored(f'Saving the private key to {file_name}', 'green'))
            with open(file_name, 'w') as f:
                f.write(private_key)
            # 0x400 -r--------
            os.chmod(file_name, 0o400)

    ### DELETE A KEY PAIR
    def delete_key_pair(self, key_name: str):
        print(colored(f"Deleting the SSH key pair: {key_name}", 'yellow'))
        self.ec2_client.delete_key_pair(KeyName=key_name)

        file_name = f"{key_name}.pem"
        if os.path.exists(file_name):
            os.chmod(file_name, 0o600)
            os.remove(file_name)

    ## SECURITY GROUPS
    ### GET SECURITY GROUPS
    def get_all_security_groups(self):
        security_groups = []
        response = self.ec2_client.describe_security_groups()
        if response and 'SecurityGroups' in response:
            for sg in response['SecurityGroups']:
                security_groups.append(sg)
        return security_groups

    def get_security_group(self, security_group_id: str):
        return self.ec2_client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        security_group_id,
                    ]
                },
            ]
        )['SecurityGroups']

    def print_security_groups(self, verbose: bool = False):
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
                ip_permissions = []
                for rule in sg['IpPermissions']:
                    ip_permissions.append(security_rule_to_string(rule))

                ip_permissions_egress = []
                for rule in sg['IpPermissionsEgress']:
                    ip_permissions_egress.append(security_rule_to_string(rule))

                group = {'GroupId': sg['GroupId'],
                         'GroupName': sg['GroupName'],
                         'Description': sg['Description'],
                         'IpPermissionsIngress': ip_permissions,
                         'IpPermissionsEgress': ip_permissions_egress}

                if verbose:
                    group['OwnerId'] = sg['OwnerId']
                    group['VpcId'] = sg['VpcId']

                pprint(group, sort_dicts=False)

    ### CREATE A NEW SECURITY GROUP
    def create_security_group(self, group_name: str, description: str):
        try:
            self.ec2.create_security_group(GroupName=group_name,
                                           Description=description)
            print(colored(f"A new security group with the name '{group_name}' has been created", 'green'))
        except botocore.client.ClientError as e:
            if 'already exists' in f"{e}":
                print(colored(f'The security group with name {group_name} already exists', 'yellow'))
            else:
                print(f"{type(e)} - {e}")

    ### DELETE A SECURITY GROUP
    def delete_security_group(self, security_group_id: str):
        try:
            self.ec2_client.delete_security_group(GroupId=security_group_id)
            print(colored(f"The security group with id '{security_group_id}' has been deleted", 'green'))
        except botocore.client.ClientError as e:
            if 'does not exist' in f"{e}":
                print(colored(f"The specified security group with id '{security_group_id}' does not exist", 'red'))
            else:
                print(colored(f"{type(e)} - {e}", 'red'))

    ### CONFIGURING DA FIREWALL
    def add_ingress_rule(self, firewall_rule_request: kommandos, security_group_id: str):
        print(f"Authorizing ingress '{firewall_rule_request}' on '{security_group_id}'")
        if not firewall_rule_request.description:
            description = f"{firewall_rule_request.port}-{firewall_rule_request.protocol}-custom"
        else:
            description = firewall_rule_request.description

        try:
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'FromPort': firewall_rule_request.port,
                        'ToPort': firewall_rule_request.port,
                        'IpProtocol': firewall_rule_request.protocol,
                        'IpRanges': [
                            {
                                'CidrIp': firewall_rule_request.ipv4_address,
                                'Description': description
                            },
                        ]
                    }
                ]
            )
            if response:
                if 'Return' in response:
                    if response['Return']:
                        print(f"Operation performed successfully")
                    else:
                        print('Operating failed')
                else:
                    print('Unknown response format')
                    print(response)
        except botocore.client.ClientError as e:
            if 'already exists' in f"{e}":
                print(f"The requested ingress rule '{firewall_rule_request}' already exists")
            else:
                print(f"{type(e)} - {e}")

    def add_egress_rule(self, firewall_rule_request: kommandos, security_group_id: str):
        print(f"Authorizing egress '{firewall_rule_request}' on '{security_group_id}'")
        if not firewall_rule_request.description:
            description = f"{firewall_rule_request.port}-{firewall_rule_request.protocol}-custom"
        else:
            description = firewall_rule_request.description

        try:
            response = self.ec2_client.authorize_security_group_egress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'FromPort': firewall_rule_request.port,
                        'ToPort': firewall_rule_request.port,
                        'IpProtocol': firewall_rule_request.protocol,
                        'IpRanges': [
                            {
                                'CidrIp': firewall_rule_request.ipv4_address,
                                'Description': description
                            },
                        ]
                    }
                ]
            )
            if response:
                if 'Return' in response:
                    if response['Return']:
                        print(f"Operation performed successfully")
                    else:
                        print('Operating failed')
                else:
                    print('Unknown response format')
                    print(response)
        except botocore.client.ClientError as e:
            if 'already exists' in f"{e}":
                print(f"The requested egress rule '{firewall_rule_request}' already exists")
            else:
                print(f"{type(e)} - {e}")

    def delete_ingress_rule(self, firewall_rule_request: kommandos, security_group_id: str):
        print(f"Revoking ingress '{firewall_rule_request}' on '{security_group_id}'")

        # find the description if the one wasn't supplied
        description = ''
        if not firewall_rule_request.description:
            sg = self.get_security_group(security_group_id=security_group_id)
            if sg and len(sg) == 1:
                ip_permissions = sg[0]['IpPermissions']
                for rule in ip_permissions:
                    if (rule['FromPort'] == rule['ToPort']) and firewall_rule_request.port == rule['FromPort']:
                        ip_ranges = rule['IpRanges']
                        for range in ip_ranges:
                            if range['CidrIp'] == firewall_rule_request.ipv4_address:
                                description = range['Description']
            else:
                raise Exception(f"{len(sg)} security groups have been found by the given id '{security_group_id}'")
        else:
            description = firewall_rule_request.description

        try:
            response = self.ec2_client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'FromPort': firewall_rule_request.port,
                        'ToPort': firewall_rule_request.port,
                        'IpProtocol': firewall_rule_request.protocol,
                        'IpRanges': [
                            {
                                'CidrIp': firewall_rule_request.ipv4_address,
                                'Description': description
                            },
                        ]
                    }
                ]
            )
            if response:
                if 'Return' in response:
                    if response['Return']:
                        print(f"Operation performed successfully")
                    else:
                        print('Operating failed')
                else:
                    print('Unknown response format')
                    print(response)
        except botocore.client.ClientError as e:
            print(f"{type(e)} - {e}")

    def delete_egress_rule(self, firewall_rule_request: kommandos, security_group_id: str):
        print(f"Revoking egress '{firewall_rule_request}' on '{security_group_id}'")

        # find the description if the one wasn't supplied
        description = ''
        if not firewall_rule_request.description:
            sg = self.get_security_group(security_group_id=security_group_id)
            if sg and len(sg) == 1:
                ip_permissions = sg[0]['IpPermissionsEgress']
                for rule in ip_permissions:
                    if 'FromPort' in rule and 'ToPort' in rule:
                        if (rule['FromPort'] == rule['ToPort']) and firewall_rule_request.port == rule['FromPort']:
                            ip_ranges = rule['IpRanges']
                            for range in ip_ranges:
                                if range['CidrIp'] == firewall_rule_request.ipv4_address:
                                    description = range['Description']
            else:
                raise Exception(f"{len(sg)} security groups have been found by the given id '{security_group_id}'")
        else:
            description = firewall_rule_request.description

        try:
            response = self.ec2_client.revoke_security_group_egress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'FromPort': firewall_rule_request.port,
                        'ToPort': firewall_rule_request.port,
                        'IpProtocol': firewall_rule_request.protocol,
                        'IpRanges': [
                            {
                                'CidrIp': firewall_rule_request.ipv4_address,
                                'Description': description
                            },
                        ]
                    }
                ]
            )
            if response:
                if 'Return' in response:
                    if response['Return']:
                        print(f"Operation performed successfully")
                    else:
                        print('Operating failed')
                else:
                    print('Unknown response format')
                    print(response)
        except botocore.client.ClientError as e:
            print(f"{type(e)} - {e}")

    ## AMI IMAGES
    def get_ami_image(self, image_id: str):
        return self.ec2_client.describe_images(
            ImageIds=[
                image_id
            ]
        )

    def search_ami_images(self, query: str):
        images = []
        resp = self.ec2_client.describe_images(
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
                print(f"The default user of the AMI '{colored(image_id, 'green')}' "
                      f"has been identified as '{colored(identified_user_name, 'green')}'")
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

    def print_running_instances(self, verbose: bool = False):
        instances = self.get_running_instances()
        if instances:
            print('Running instances are:')
            for instance in instances:
                name = ''
                if hasattr(instance, 'tags') and instance.tags:
                    for tag in instance.tags:
                        if 'Key' in tag and tag['Key'] == 'Name':
                            name = tag['Value']
                inst = {
                    'InstanceId': instance.id,
                    'PublicIpAddress': instance.public_ip_address,
                    'KeyPairName': instance.key_pair.key_name,
                    'SecurityGroups': instance.security_groups
                }
                if name:
                    inst['Name'] = name

                if verbose:
                    inst['ImageId'] = instance.image_id

                pprint(inst, sort_dicts=False)
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
                     disable_api_termination: bool = False):
        print(f'Starting a new instance: '
              f'{image_id} {key_pair_name} {security_group_id} {instance_type} {instance_name}')
        if disable_api_termination:
            print(colored('API termination for that instance has been disabled', 'yellow'))
        response = self.ec2_client.run_instances(InstanceType=instance_type,
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
                                                 DisableApiTermination=disable_api_termination,
                                                 # The maximum number of instances to launch.
                                                 # If you specify more instances than Amazon EC2 can launch
                                                 # in the target Availability Zone,
                                                 # Amazon EC2 launches the largest possible number of instances above MinCount.
                                                 MaxCount=1,
                                                 MinCount=1
                                                 )
        new_instance = response['Instances'][0]
        if new_instance:
            print(colored('The instance has been created', 'green'))
            print('Waiting for the server boot...')
            instance = aws_manager.get_instance(new_instance['InstanceId'])
            instance.wait_until_running()
            print(f'The server is up and running at {colored(instance.public_ip_address, "green")}')
            print('Waiting until the SSH service is available...')
            aws_manager.poll_ssh_status(instance.id)
            identified_user_name = self.get_default_ami_user_name(instance.image_id)
            print("Use the following command for connecting to the instance: " +
                  colored(f"ssh {identified_user_name}@{instance.public_ip_address} -i {key_pair_name}.pem", 'green'))
            return instance

    def invoke_script(self, instance_id: str,
                      file_name: str,
                      parameters: list = None,
                      key_pair_name: str = None):
        instance = self.get_instance(instance_id=instance_id)
        ip_address = instance.public_ip_address
        username = self.get_default_ami_user_name(image_id=instance.image_id)
        print(colored(f"Invoking the {file_name} script on the instance hosted at {ip_address}", 'yellow'))

        if not key_pair_name:
            key_pair_name = f"{instance.key_pair.name}.pem"

        if not os.path.exists(key_pair_name):
            raise Exception(f"The RSA private key '{key_pair_name}' has not been found at the given path")

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
                         '-i', key_pair_name,
                         script_name, f"{username}@{ip_address}:{remote_script_name}"])
        subprocess.call(['ssh', '-o', 'StrictHostKeyChecking=accept-new',
                         '-i', key_pair_name,
                         f"{username}@{ip_address}",
                         "/bin/bash", remote_script_name])
        print(colored(f"The '{file_name}' script has been invoked as {username}@{ip_address}", 'yellow'))

        if script_name.endswith('-kommandos-temp'):
            os.remove(script_name)

def main():
    options = get_arguments()

    key_pair_name = options.key_pair_name
    image_id = options.image_id
    security_group_id = options.security_group_id
    instance_name = options.instance_name

    domain_name = options.fqdn

    aws_manager = AwsManager()

    if options.get_ami:
        image = aws_manager.get_ami_image(image_id=image_id)
        pprint(image)
        aws_manager.get_default_ami_user_name(image_id=image_id)

    if options.delete_key_pair:
        aws_manager.delete_key_pair(key_name=key_pair_name)

    if options.terminate:
        aws_manager.terminate_instance(instance_id=options.terminate)
    elif options.terminate_all:
        aws_manager.terminate_all_running_instances()

    if options.add_record:
        aws_manager.create_dns_record(hosted_zone_name=domain_name,
                                      record_type=options.record_type,
                                      record_value=options.record_value,
                                      ttl=options.ttl)
    if options.delete_record:
        aws_manager.delete_dns_record(hosted_zone_name=domain_name,
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
        aws_manager.create_security_group(group_name=name,
                                          description=description)
    if options.delete_security_group:
        aws_manager.delete_security_group(security_group_id=security_group_id)

    if options.allow_inbound:
        for rule in options.allow_inbound:
            aws_manager.add_ingress_rule(firewall_rule_request=kommandos(rule),
                                         security_group_id=security_group_id)
    if options.allow_outbound:
        for rule in options.allow_outbound:
            aws_manager.add_egress_rule(firewall_rule_request=kommandos(rule),
                                        security_group_id=security_group_id)
    if options.delete_inbound:
        for rule in options.delete_inbound:
            aws_manager.delete_ingress_rule(firewall_rule_request=kommandos(rule),
                                            security_group_id=security_group_id)
    if options.delete_outbound:
        for rule in options.delete_outbound:
            aws_manager.delete_egress_rule(firewall_rule_request=kommandos(rule),
                                           security_group_id=security_group_id)

    if options.stats:
        aws_manager.print_running_instances(verbose=options.verbose)
        print('*' * 70)
        aws_manager.print_key_pairs(verbose=options.verbose)
        print('*' * 70)
        aws_manager.print_security_groups(verbose=options.verbose)
        print('*' * 70)
        aws_manager.print_hosted_zones(verbose=options.verbose)
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
                print(colored(f"The SSH key pair with the name '{key_pair_name}' already exists", 'yellow'))
            else:
                print(f"{type(e)} {e}")
                exit(1)

        new_instance = aws_manager.run_instance(image_id=image_id,
                                                key_pair_name=key_pair_name,
                                                security_group_id=security_group_id,
                                                instance_type=options.instance_type,
                                                instance_name=instance_name,
                                                disable_api_termination=options.disable_api_termination)
        if options.link_fqdn:
            ttl = options.ttl
            aws_manager.create_dns_record(hosted_zone_name=domain_name,
                                          record_type='A',
                                          record_value=new_instance.public_ip_address,
                                          ttl=ttl)
            aws_manager.create_dns_record(hosted_zone_name=domain_name,
                                          record_type='MX',
                                          record_value=f"1 {new_instance.public_ip_address}",
                                          ttl=ttl)
        if options.invoke_script:
            aws_manager.invoke_script(instance_id=new_instance.instance_id,
                                      file_name=options.invoke_script,
                                      parameters=options.invoke_script_argument)

if __name__ == '__main__':
    main()
