#!/usr/bin/env python3
from termcolor import colored


class AMIKommandos:
    def __init__(self, ec2_client):
        self.ec2_client = ec2_client

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
                for system, user in user_mapping.items():
                    # the kali image - a special case
                    if image['ImageId'] == 'ami-0899c3c82cdfd00f1':
                        identified_user_name = 'kali'
                        break

                    if 'Name' in image and system in image['Name'].lower():
                        identified_user_name = user
                        break
                    elif 'ImageLocation' in image and system in image['ImageLocation'].lower():
                        identified_user_name = user
                        break
                    elif 'Description' in image and system in image['Description'].lower():
                        identified_user_name = user
                        break
                if not identified_user_name:
                    # resort to the default one
                    identified_user_name = 'ec2-user'
                print(f"The default user of the AMI '{colored(image_id, 'green')}' "
                      f"has been identified as '{colored(identified_user_name, 'green')}'")
                return identified_user_name
