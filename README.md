# aws-kommandos

Advisory Infrastructure Setup Scripts

## About

Have you ever been bothered with setting up your C2 infrastructure on AWS prior to/during a red team engagement? Having
to deal with logging in, configuring security groups, going through the process of creating DNS record sets and such?

If you hate doing this time after time and just wanna have a script that does everything for you - you've come to the
right place.

AWS Kommandos automates the process of creating cloud instances for various purposes - as C2 servers, for example. It
also helps you to manage your AWS console - from changing firewall rules and managing your SSH access keys to adjusting
the DNS record sets. All in one damn script.

You're only expected to create an AWS account and configure the access keys for running Kommandos locally.

See the Usage section for getting an idea how to use it.

Kommandos automatically creates its directory under the ~/.aws-kommandos path to store SSH private keys it creates.

## Installation

### Install the toolset

```bash
apt install python3 python3-pip
pip3 install aws-kommandos
```

### Configure the AWS credentials

The first option is to use the *awscli* client to configure your AWS credentials used by Kommandos.
`aws configure`

The second options is to export the AWS credentials as environment variables
```bash
export AWS_ACCESS_KEY_ID=key_id
export AWS_ACCESS_KEY_SECRET=secret
export AWS_REGION=region
```

The third option is to use the command-line arguments to pass credentials to Kommandos
`aws-kommandos --access-key-id <key_id> --access-key-secret <secret> --region-name <region>`

## Usage

### Print Kommandos options

`aws-kommandos --help`

`aws-kommandos -h`

### Print AWS stats (instances, security groups, ssh keys, DNS hosted zones)

`aws-kommandos --stats`

### Print detailed AWS stats

`aws-kommandos --stats --verbose`

`aws-kommandos --stats -v`

### Terminate all running EC2 instances

```text
╰$ aws-kommandos --terminate-all
Terminating all running instances
Terminating i-0df15af122876dd62
```

### Search AMI images

```text
╰$ aws-kommandos --search-ami "ubuntu*server*20.04*"
{'CreationDate': '2021-07-27T16:45:08.000Z',
 'ImageId': 'ami-06e715bf46b6caf71',
 'State': 'available',
 'Name': 'ubuntu-pro-server/images/hvm-ssd/ubuntu-focal-20.04-amd64-pro-serve-ae7ed378-8838-4fcf-842d-d1d09b34f116-ami-005f184e361f78579.4',
 'ImageLocation': 'aws-marketplace/ubuntu-pro-server/images/hvm-ssd/ubuntu-focal-20.04-amd64-pro-serve-ae7ed378-8838-4fcf-842d-d1d09b34f116-ami-005f184e361f78579.4',
 'Description': 'Canonical, Ubuntu Server Pro, 20.04 LTS, amd64 focal image '
                'build on 2021-07-20',
 'ImageOwnerAlias': 'aws-marketplace'}
1 AMI images found
```

### Start a new instance (minimal configuration)

```text
╰$ aws-kommandos --security-group sg-66666666661488666 --start
Creating a new SSH key pair: proxy-key
The SSH key pair with the name 'proxy-key' already exists
Starting a new instance: ami-0746eb3cb5c684ae6 proxy-key sg-030abb524637009f3 t2.micro proxy-instance
The instance has been created
Waiting for the server boot...
The server is up and running at 18.197.229.100
Waiting until the SSH service is available...
The default user of the AMI 'ami-0746eb3cb5c684ae6' has been identified as 'ubuntu'
Use the following command for connecting to the instance: ssh ubuntu@18.197.229.100 -i proxy-key.pem
```

Oh, and did I mention that if you don't have an SSH access key the script automatically creates one for you?
Use *--force-recreate-key* to force the script into creating a new key even if one with the same name exists.

### Start a new instance and invoke a bash script on remote

```text
╰$ aws-kommandos --security-group sg-66666666661488666 --start --invoke-script instance-scripts/proxy/invoke-fresh-install.sh 
Creating a new SSH key pair: proxy-key
The SSH key pair with the name 'proxy-key' already exists
Starting a new instance: ami-0746eb3cb5c684ae6 proxy-key sg-030abb524637009f3 t2.micro proxy-instance
The instance has been created
Waiting for the server boot...
The server is up and running at 18.184.160.55
Waiting until the SSH service is available...
The default user of the AMI 'ami-0746eb3cb5c684ae6' has been identified as 'ubuntu'
Use the following command for connecting to the instance: ssh ubuntu@18.184.160.55 -i proxy-key.pem
The default user of the AMI 'ami-0746eb3cb5c684ae6' has been identified as 'ubuntu'
Invoking the instance-scripts/proxy/invoke-fresh-install.sh script on the instance hosted at 18.184.160.55
...truncated - script output...
Setting microsocks as a system service
Created symlink /etc/systemd/system/multi-user.target.wants/microsocks.service → /lib/systemd/system/microsocks.service.
All done
The 'instance-scripts/proxy/invoke-fresh-install.sh' script has been invoked as ubuntu@18.184.160.55
```

### Start a new instance and autoconfigure the DNS record sets
This command starts a new instance and uses the domain name supplied with the *--fqdn* argument 
to create A and MX record sets pointing to the IP address of the newly created EC2 instance.
```text
╰$ aws-kommandos --security-group sg-66666666661488666 --start --link-fqdn --fqdn virtualsquad.ninja
Creating a new SSH key pair: proxy-key
The SSH key pair with the name 'proxy-key' already exists
Starting a new instance: ami-0746eb3cb5c684ae6 proxy-key sg-030abb524637009f3 t2.micro proxy-instance
The instance has been created
Waiting for the server boot...
The server is up and running at 18.184.218.238
Waiting until the SSH service is available...
The default user of the AMI 'ami-0746eb3cb5c684ae6' has been identified as 'ubuntu'
Use the following command for connecting to the instance: ssh ubuntu@18.184.218.238 -i proxy-key.pem
A new record set virtualsquad.ninja. A 18.184.218.238 has been created
A new record set virtualsquad.ninja. MX 1 18.184.218.238 has been created
```

### Create an inbound firewall rule
```text
╰$ aws-kommandos --security-group sg-66666666661488666 --allow-inbound 443/tcp:0.0.0.0/0         
Authorizing ingress '[443/tcp -> 0.0.0.0/0] - ' on 'sg-66666666661488666'
Operation performed successfully
```

### Revoke an inbound firewall rule
```text
╰$ aws-kommandos --security-group sg-66666666661488666 --delete-inbound 443/tcp:0.0.0.0/0
Revoking ingress '[443/tcp -> 0.0.0.0/0] - ' on 'sg-66666666661488666'
Operation performed successfully
```

### Create an outbound firewall rule
```text
╰$ aws-kommandos --security-group sg-66666666661488666 --allow-outbound 443/tcp:0.0.0.0/0         
Authorizing egress '[443/tcp -> 0.0.0.0/0] - ' on 'sg-66666666661488666'
Operation performed successfully
```

### Revoke an outbound firewall rule
```text
╰$ aws-kommandos --security-group sg-66666666661488666 --delete-outbound 443/tcp:0.0.0.0/0
Revoking egress '[443/tcp -> 0.0.0.0/0] - ' on 'sg-66666666661488666'
Operation performed successfully
```

### Create a security group w/o description
```text
╰$ aws-kommandos --create-security-group NinjaGroup                                         
A new security group with the name 'NinjaGroup' has been created
```

### Create a security group w description
```text
╰$ aws-kommandos --create-security-group "NinjaGroup: My Awesome Security Group"
A new security group with the name 'NinjaGroup' has been created
```

### Delete a security group
```text
╰$ aws-kommandos --delete-security-group --security-group-id sg-0b2d1b55354c531bd
The security group with id 'sg-0b2d1b55354c531bd' has been deleted
```

### Create a new A record set for domain
```text
╰$ aws-kommandos --fqdn virtualsquad.ninja --add-record --record-type A --record-value 55.55.55.55
A new record set virtualsquad.ninja. A 55.55.55.55 has been created
```

### Delete a record set from domain
```text
╰$ aws-kommandos --fqdn virtualsquad.ninja --delete-record --record-type A --record-value 55.55.55.55
The record set virtualsquad.ninja. A 55.55.55.55 has been deleted
```

And many more! Please use --help to see what else you could do with Kommandos.