#!/usr/bin/env python3
from pprint import pprint

import botocore.client
from termcolor import colored

from firewall_rule_request import FirewallRuleRequest


class SecurityGroupsKommandos:
    def __init__(self, ec2_client):
        self.ec2_client = ec2_client

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
        def security_rule_to_string(sec_rule: dict):
            if sec_rule['IpProtocol'] == '-1':
                return f"{';'.join([ip['CidrIp'] for ip in sec_rule['IpRanges']])} -> All Traffic"
            else:
                return f"{';'.join([ip['CidrIp'] for ip in sec_rule['IpRanges']])} " \
                       f"-> {sec_rule['FromPort']}/{sec_rule['IpProtocol']}"

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
    def add_ingress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
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

    def add_egress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
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

    def delete_ingress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
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
                        for ip_range in ip_ranges:
                            if ip_range['CidrIp'] == firewall_rule_request.ipv4_address:
                                description = ip_range['Description']
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

    def delete_egress_rule(self, firewall_rule_request: FirewallRuleRequest, security_group_id: str):
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
                            for ip_range in ip_ranges:
                                if ip_range['CidrIp'] == firewall_rule_request.ipv4_address:
                                    description = ip_range['Description']
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
