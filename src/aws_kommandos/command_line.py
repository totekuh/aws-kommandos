#!/usr/bin/env python3
import os

# ubuntu server 18.04
DEFAULT_IMAGE_ID = 'ami-0b1deee75235aa4bb'
DEFAULT_INSTANCE_TYPE = 't2.micro'
DEFAULT_INSTANCE_NAME = 'kommandos-instance'

DEFAULT_DNS_TTL = 86400

DEFAULT_BLOCK_DEVICE_NAME = "/dev/sda1"
DEFAULT_VOLUME_SIZE = 10

S3_BUCKET_NAME = "kommandos-bucket"
KOMMANDOS_HOME_FOLDER = f'{os.path.expanduser("~")}/.aws-kommandos'

DEFAULT_SECURITY_GROUP_NAME = "kommandos-security-group"


def get_arguments():
    from argparse import ArgumentParser
    parser = ArgumentParser(description='AWS Kommandos Script')

    general_settings = parser.add_argument_group('General Settings')
    general_settings.add_argument('-hf',
                                  '--home-folder',
                                  dest='home_folder',
                                  default=KOMMANDOS_HOME_FOLDER,
                                  type=str,
                                  help='Specify the path '
                                       'where kommandos should store the private keys of instances it will create. '
                                       f"Default is '{KOMMANDOS_HOME_FOLDER}'.")
    general_settings.add_argument('-sbn',
                                  '--s3-bucket-name',
                                  dest='s3_bucket_name',
                                  default=S3_BUCKET_NAME,
                                  type=str,
                                  help='Specify the S3 bucket name '
                                       'where kommandos will store your private keys of instances it will create. '
                                       'It is used for sharing the keys across other devices. '
                                       f"Default is '{S3_BUCKET_NAME}'.")

    credentials = parser.add_argument_group('AWS Credentials')
    credentials.add_argument('--access-key-id',
                             dest='access_key_id',
                             required=False,
                             type=str,
                             help="Specify the AWS access key ID to use. "
                                  "If omitted, the script grabs the key ID "
                                  "from the AWS_ACCESS_KEY_ID env variable. "
                                  "If that variable does not present, the script takes default credentials "
                                  "located in the ~/.aws/credentials file.")
    credentials.add_argument('--access-key-secret',
                             dest='access_key_secret',
                             required=False,
                             type=str,
                             help="Specify the AWS access key secret to use. "
                                  "If omitted, the script grabs the key secret "
                                  "from the AWS_ACCESS_KEY_SECRET env variable. "
                                  "If that variable does not present, the script takes default credentials "
                                  "located in the ~/.aws/credentials file.")
    credentials.add_argument('--region-name',
                             dest='region_name',
                             required=False,
                             type=str,
                             help="Specify the AWS region to use. "
                                  "If omitted, the script grabs the key secret from the AWS_REGION env variable. "
                                  "If that variable does not present, the script takes default credentials "
                                  "located in the ~/.aws/config file.")

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
                                        "for shutting down the instance. "
                                        "Useful if you wanna ensure you won't accidentally terminate "
                                        "something you may need in the future.")
    starting_commands.add_argument('--poll-ssh',
                                   dest='poll_ssh',
                                   action='store_true',
                                   required=False,
                                   help="Specify this flag if you want to poll the SSH service on remote "
                                        "after the server boot. "
                                        "The netcat tool needs to be installed on the system to use that. "
                                        "Keep in mind that you should provide this flag in case you want to "
                                        "enable script invocation on remote, "
                                        "since Kommandos needs to know when the service is available for invoking it. "
                                        "Also make sure an inbound rule in the corresponding security group "
                                        "for connecting to the 22/tcp port.")
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

    connect = parser.add_argument_group("EC2 Connection Commands")
    connect.add_argument('--connect',
                         dest='connect',
                         required=False,
                         type=str,
                         help='Specify an instance-id to connect to. '
                              'The SSH port (22/tcp) should be reachable for doing that. '
                              "The private key is taken from the argument --key-pair-name and "
                              "is fetched from the Kommandos S3 bucket if doesn't exist locally.")
    connect.add_argument('--user',
                         dest='user',
                         required=False,
                         type=str,
                         help='Specify a username to use while connecting to the instance via SSH. '
                              'If omitted, the default user name of the AMI image is used.')
    connect.add_argument("--ssh-append",
                         dest="ssh_append",
                         required=False,
                         type=str,
                         help="Specify a string to append to the command used for establishing the SSH connection. "
                              "If may be something like '-L 127.0.0.1:8080:127.0.0.1:8080' "
                              "if you want to additionally forward the ports, for example.")

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
                               "or for changing firewall rules. "
                               f"If there's no security group given, kommandos will create one for you with the name "
                               f"'{DEFAULT_SECURITY_GROUP_NAME}'.")

    ssh_keys = parser.add_argument_group('Managing SSH Keys')
    ssh_keys.add_argument("--key-pair-name",
                          dest="key_pair_name",
                          required=False,
                          type=str,
                          help="Specify the key pair name to use alongside the created instance. "
                               f"Default value is taken from --instance-name. "
                               f"The keys managed by Kommandos "
                               f"are stored under the '{KOMMANDOS_HOME_FOLDER}' directory "
                               f"and are uploaded to the Kommandos managed S3 bucket.")
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

    ebs_group = parser.add_argument_group('EBS')
    ebs_group.add_argument('-bdn',
                           '--block-device-name',
                           dest='block_device_name',
                           required=False,
                           type=str,
                           default=DEFAULT_BLOCK_DEVICE_NAME,
                           help='Specify the block device name of the disk that will be attached to the instance. '
                                f'Default is {DEFAULT_BLOCK_DEVICE_NAME} GB.')
    ebs_group.add_argument('-vs',
                           '--volume-size',
                           dest='volume_size',
                           required=False,
                           type=int,
                           default=DEFAULT_VOLUME_SIZE,
                           help='Specify the volume size in GB of the disk that will be attached to the instance. '
                                'Note, this disk will be deleted once its instance gets terminated. '
                                f'Default is {DEFAULT_VOLUME_SIZE} GB.')

    options = parser.parse_args()
    if options.access_key_id and not options.access_key_secret:
        parser.error(f"The --access-key-id argument must go together with --access-key-secret argument. "
                     f"Use --help for more info.")
    if not options.access_key_id and options.access_key_secret:
        parser.error(f"The --access-key-secret argument must go together with --access-key-id argument. "
                     f"Use --help for more info.")
    if (options.access_key_id and options.access_key_secret) and not options.region_name:
        parser.error("The region name must be supplied with the --region-name argument when credentials"
                     " are passed via command line."
                     "Use --help for more info.")
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
        if options.invoke_script:
            if not os.path.exists(options.invoke_script):
                parser.error("The script file you're providing with --invoke-script doesn't seem to exist")
            if not options.poll_ssh:
                parser.error('The --poll-ssh argument must be given if you require remote script invocation. '
                             'Use --help for more info.')
    else:
        if options.invoke_script:
            parser.error("Invoking scripts on remote is only supported while creating new instances (at least yet)")
    if options.delete_security_group and not options.security_group_id:
        parser.error('The --security-group-id argument is required for deleting a security group. '
                     'Use --help for more info')
    if options.terminate and options.terminate_all:
        parser.error("You must use either --terminate <instance-id> or --terminate-all. "
                     "Use --help for more info.")

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
