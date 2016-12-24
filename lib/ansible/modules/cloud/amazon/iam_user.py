#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: iam_user
short_description: Manage AWS IAM users
description:
  - Manage AWS IAM roles
version_added: "2.3"
author: Rob White, @wimnat
options:
  group:
    description:
      - A list of IAM group names that the user is a member of. To remove all existing groups, use an empty list item.
    required: false
  path:
    description:
      - The path to the user. For more information about paths, see U(http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html).
    required: false
    default: "/"
  name:
    description:
      - The name of the user.
    required: true
  password:
    description:
      - The password of the user. If this parameter is provided but left blank, the user's password will be deleted.
    required: false
  password_reset_required:
    description:
      - Allows the password to be used only once by requiring the specified IAM user to set a new password on next sign-in. You must set password_update_policy to 'always' to apply this option to an existing password.
    required: false
    default: no
    choices: [ 'yes', 'no' ]
  password_update_policy:
    description:
      - Whether to always update the user password, or only when the user is created for the first time. If set to always, the module will always report changed.
    required: false
    default: on_create
    choices: [ 'always', 'on_create' ]
  ssh_public_key:
    description:
      - The SSH public key. The public key must be encoded in ssh-rsa format or PEM format. It is used for authenticating a user to AWS CodeCommit.
    required: false
  ssh_public_key_encoding:
    description:
      - The public key encoding format.
    required: false
    default: ssh-rsa
    choices: [ 'ssh-rsa', 'pem' ]
  managed_policy:
    description:
      - A list of managed policy ARNs (can't use friendly names due to AWS API limitation) to attach to the user. To embed an inline policy, use M(iam_policy). To remove all existing policies, use an empty list item.
    required: false
  state:
    description:
      - Create or remove the IAM user.
    required: true
    choices: [ 'present', 'absent' ]
requirements: [ botocore, boto3 ]
extends_documentation_fragment:
  - aws
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Create a user and add to a pre-existing group "Devs"
- iam_user:
    name: joe.blogs
    state: present
    group:
      - Devs

# Create a user with a password and set the flag to ask the user to set a new password on first login
- iam_user:
    name: joe.bloggs
    state: present
    password: anotverysecretpassword
    password_reset_required: yes

# Create a user and attach a managed policy called "ReadOnlyAccess"
- iam_user:
    name: joe.blogs
    state: present
    managed_policy:
      - "arn:aws:iam::aws:policy/ReadOnlyAccess"

# Keep the user created above but remove all managed policies
- iam_user:
    name: joe.blogs
    state: present
    managed_policy:
      -

# Set the flag for a password change on next login for an existing user
- iam_user:
    name: some.existing.user
    state: present
    password_reset_required: yes
    password_update_policy: always

# Delete the user
- iam_user:
    name: joe.blogs
    state: absent

'''
RETURN = '''
activeServicesCount:
    description: how many services are active in this cluster
    returned: 0 if a new cluster
    type: int
clusterArn:
    description: the ARN of the cluster just created
    type: string (ARN)
    sample: arn:aws:ecs:us-west-2:172139249013:cluster/test-cluster-mfshcdok
clusterName:
    description: name of the cluster just created (should match the input argument)
    type: string
    sample: test-cluster-mfshcdok
pendingTasksCount:
    description: how many tasks are waiting to run in this cluster
    returned: 0 if a new cluster
    type: int
registeredContainerInstancesCount:
    description: how many container instances are available in this cluster
    returned: 0 if a new cluster
    type: int
runningTasksCount:
    description: how many tasks are running in this cluster
    returned: 0 if a new cluster
    type: int
status:
    description: the status of the new cluster
    returned: ACTIVE
    type: string
'''

try:
    import boto3
    from botocore.exceptions import ClientError, ParamValidationError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def get_attached_policy_arn_list(dict_of_policies):

    policy_arn_list = []
    for policy in dict_of_policies:
        policy_arn_list.append(policy['PolicyArn'])

    return policy_arn_list


def compare_attached_user_policies(current_attached_policies, new_attached_policies):

    attached_policy_arn_list = get_attached_policy_arn_list(current_attached_policies)
    if set(attached_policy_arn_list) == set(new_attached_policies):
        return True
    else:
        # If a blank single list item is passed that means we're aiming for 0 attached policies so return True if so
        if len(new_attached_policies) == 1 and new_attached_policies[0] == "" and len(attached_policy_arn_list) == 0:
            return True
        else:
            return False


def get_group_membership_list(dict_of_groups):

    group_list = []
    for group in dict_of_groups:
        group_list.append(group['GroupName'])

    return group_list


def compare_group_membership(current_group_membership, new_groups):

    group_membership_list = get_group_membership_list(current_group_membership)

    if set(group_membership_list) == set(new_groups):
        return True
    else:
        # If a blank single list item is passed that means we're aiming for 0 attached policies so return True if so
        if len(new_groups) == 1 and new_groups[0] == "" and len(group_membership_list) == 0:
            return True
        else:
            return False


def create_or_update_user_ssh_public_key(connection, module, changed):

    ssh_public_key = module.params.get('ssh_public_key')
    name = module.params.get('name')
    changed = changed

    get_ssh_public_key_list_of_dicts(connection, module, name)


def create_or_update_user_password(connection, module, user_existed, changed):

    name = module.params.get('name')
    password = module.params.get('password')
    password_reset_required = module.params.get('password_reset_required')
    password_update_policy = module.params.get('password_update_policy')
    changed = changed

    if user_existed and password_update_policy != 'always':
        pass
    else:
        if password == "":
            try:
                connection.delete_login_profile(UserName=name)
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
        else:
            try:
                if password is not None and password_reset_required is not None:
                    connection.update_login_profile(UserName=name, Password=password, PasswordResetRequired=password_reset_required)
                    changed = True
                elif password is not None and password_reset_required is None:
                    connection.update_login_profile(UserName=name, Password=password)
                    changed = True
                elif password is None and password_reset_required is not None:
                    connection.update_login_profile(UserName=name, PasswordResetRequired=password_reset_required)
                    changed = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    # If we don't have a password at this point we can not proceed to create a new profile
                    if password is not None:
                        try:
                            connection.create_login_profile(UserName=name, Password=password, PasswordResetRequired=password_reset_required)
                            changed = True
                        except ClientError as e:
                            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
                else:
                    module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    return changed


def create_or_update_user(connection, module):

    params = dict()
    params['Path'] = module.params.get('path')
    params['UserName'] = module.params.get('name')
    managed_policies = module.params.get('managed_policy')
    groups = module.params.get('group')
    changed = False
    user_existed = False

    # Get user
    user = get_user(connection, params['UserName'], module)

    # If user is None, create it
    if user is None:
        if params['Path'] is None:
            del(params['Path'])

        try:
            user = connection.create_user(**params)
            changed = True
        except (ClientError, ParamValidationError) as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
    else:
        user_existed = True
        # Check attached managed policies
        current_attached_policies = get_attached_policy_dict(connection, params['UserName'], module)
        if not compare_attached_user_policies(current_attached_policies, managed_policies):

            # Detach managed policies not present
            for policy_arn in list(set(get_attached_policy_arn_list(current_attached_policies)) - set(managed_policies)):
                try:
                    connection.detach_user_policy(UserName=params['UserName'], PolicyArn=policy_arn)
                except ClientError as e:
                    module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

            # Attach each policy (skip is a blank item specified)
            for policy_arn in managed_policies:
                if policy_arn != "":
                    try:
                        connection.attach_user_policy(UserName=params['UserName'], PolicyArn=policy_arn)
                    except (ClientError, ParamValidationError) as e:
                        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

            changed = True

        # Check group membership
        current_group_membership = get_group_membership_dict(connection, params['UserName'], module)
        if not compare_group_membership(current_group_membership, groups):

            # Detach groups not present
            for group_name in list(set(get_group_membership_list(current_group_membership)) - set(groups)):
                try:
                    connection.remove_user_from_group(UserName=params['UserName'], GroupName=group_name)
                except ClientError as e:
                    module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

            # Attach each group (skip if a blank item specified)
            for group_name in groups:
                if group_name != "":
                    try:
                        connection.add_user_to_group(UserName=params['UserName'], GroupName=group_name)
                    except (ClientError, ParamValidationError) as e:
                        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

            changed = True

        # Check path
        if params['Path'] is not None and user['Path'] != params['Path']:
            try:
                connection.update_user(UserName=params['UserName'], NewPath=params['Path'])
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        # Get the user again
        user = get_user(connection, params['UserName'], module)

    # Set password
    if module.params.get('password') is not None or module.params.get('password_reset_required') is not None:
        changed = create_or_update_user_password(connection, module, user_existed, changed)

    # SSH key
    if module.params.get('ssh_public_key') is not None:
        changed = create_or_update_user_ssh_public_key(connection, module, changed)

    user['attached_policies'] = get_attached_policy_dict(connection, params['UserName'], module)
    user['groups'] = get_group_membership_dict(connection, params['UserName'], module)
    user['login_profile'] = get_login_profile(connection, params['UserName'], module)
    user['ssh_public_keys'] = get_ssh_public_key_list_of_dicts(connection, module, params['UserName'])
    module.exit_json(changed=changed, iam_user=camel_dict_to_snake_dict(user))


def destroy_user(connection, module):

    params = dict()
    params['UserName'] = module.params.get('name')

    if get_user(connection, params['UserName'], module):
        try:
            connection.delete_user(**params)
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=True)


def get_user(connection, name, module):

    params = dict()
    params['UserName'] = name

    try:
        return connection.get_user(**params)['User']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return None
        else:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))


def get_attached_policy_dict(connection, name, module):

    try:
        return connection.list_attached_user_policies(UserName=name)['AttachedPolicies']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return None
        else:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))


def get_group_membership_dict(connection, name, module):

    """

    :param connection:
    :param name:
    :param module:
    :return:
    """

    try:
        return connection.list_groups_for_user(UserName=name)['Groups']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return None
        else:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))


def get_ssh_public_key_list_of_dicts(connection, module, name):

    """ Use boto3 to retrieve ssh public key detail for a particular user

    Uses boto3 to first query for SSH public key list for a particular user and then uses this detail
    to query for each individual SSH public key. This detail is then returned as a list of dicts

    :param connection: AWS connection object
    :param module: Ansible module object
    :param name: IAM username
    :return: list of dicts with each dict containing detail about the user's SSH public keys
    """

    # Set key encoding type to recognisable AWS format
    if module.params.get('ssh_public_key_encoding') == 'ssh-rsa':
        ssh_public_key_encoding = 'SSH'
    elif module.params.get('ssh_public_key_encoding') == 'pem':
        ssh_public_key_encoding = 'PEM'

    try:
        ssh_public_keys = connection.list_ssh_public_keys(UserName=name)['SSHPublicKeys']
    except ClientError as e:
        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    ssh_public_keys_detail = []
    for key in ssh_public_keys:
        ssh_public_keys_detail.append(connection.get_ssh_public_key(UserName=name,
                                                                    SSHPublicKeyId=key['SSHPublicKeyId'],
                                                                    Encoding=ssh_public_key_encoding)['SSHPublicKey'])
    return ssh_public_keys_detail


def get_login_profile(connection, name, module):

    try:
        return connection.get_login_profile(UserName=name)['LoginProfile']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return {}
        else:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            group=dict(required=False, default=[], type='list'),
            name=dict(required=True, type='str'),
            path=dict(default=None, required=False, type='str'),
            password=dict(default=None, required=False, type='str'),
            password_reset_required=dict(default=None, required=False, type='bool'),
            password_update_policy=dict(default='on_create', required=False, type='str', choices=['on_create', 'always']),
            managed_policy=dict(default=[], required=False, type='list'),
            ssh_public_key=dict(default=None, required=False, type='str'),
            ssh_public_key_encoding=dict(default='ssh-rsa', required=False, type='str', choices=['ssh-rsa', 'pem']),
            state=dict(default=None, choices=['present', 'absent'], required=True)
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    connection = boto3_conn(module, conn_type='client', resource='iam', region=region, endpoint=ec2_url, **aws_connect_params)

    state = module.params.get("state")

    if state == 'present':
        create_or_update_user(connection, module)
    else:
        destroy_user(connection, module)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
