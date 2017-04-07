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

ANSIBLE_METADATA = {
    'version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: aws_kms_cmk
short_description: Manage KMS Customer Master Keys
author: Rob White (@wimnat)
description:
     - Manage KMS CMKs.  See U(http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html) for more information.
version_added: "2.4"
options:
  alias:
    description:
      - String that contains the display name. The name must start with the word "alias" followed by a forward slash (alias/). Aliases that begin with "alias/AWS" are reserved.
    required: false
  description:
    description:
      - A description of the CMK.
    required: false
  key_id:
    description:
      - A unique KMS key ID.
    required: false
  key_deletion_window:
    description:
      - The waiting period, specified in number of days. The period must be between 7 and 30 inclusive. After the waiting period ends,
        AWS KMS deletes the customer master key (CMK). Is only effective when state=absent
    default: 30
  policy:
    description:
      - The key policy to attach to the CMK. If you set a policy you must also specify C(bypass_policy_lockout_safety_check).
    required: false
  origin:
    description:
      - The default is AWS_KMS, which means AWS KMS creates the key material. When this parameter is set to EXTERNAL , the request
        creates a CMK without key material so that you can import key material from your existing key management infrastructure.
    required: false
    default: AWS_KMS
    choices: [ "AWS_KMS", "EXTERNAL" ]
  bypass_policy_lockout_safety_check:
    description:
      - A flag to indicate whether to bypass the key policy lockout safety check. If you set this value then changed state will always
        report True because there is no way to determine the existing state of this flag using current AWS API. If you set this flag, you
        must also specify a C(policy).
    required: false
    choices: [ "true", "false" ]
  enabled:
    description:
      - Whether the key is marked as enabled, thereby permitting its use.
    required: false
    choices: [ "true", "false" ]
  purge_tags:
    description:
      - If yes, existing tags will be purged from the resource to match exactly what is defined by tags parameter. If the tag parameter is not set then tags
        will not be modified.
    required: false
    default: yes
    choices: [ 'yes', 'no' ]
  tags:
    description:
      - A dictionary of tags to apply to the key.
    required: false
  state:
    description:
      - Create or schedule removal of the KMS CMK.
    required: true
    choices: [ 'present', 'absent' ]
notes:
  - Idempotency is difficult with KMS CMKs as only the Key ID is a unique identifier. You can specify an alias but note that an alias can be reassigned
    to different keys so it could be dangerous to use it as an idempotent identifier.
  - Specifying state=absent will ensure that the key does not exist OR that the key is scheduled for deletion.  See
    U(http://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html) for more information.
extends_documentation_fragment:
- aws
- ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Create a KMS CMK
- aws_kms_cmk:
    alias: alias/my-key
    state: present


'''

RETURN = '''

'''

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info, camel_dict_to_snake_dict, \
    sort_json_policy_dict, boto3_tag_list_to_ansible_dict, ansible_dict_to_boto3_tag_list, compare_aws_tags
import traceback

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def _get_cmk_id(connection, module):
    """
    Get the CMK key ID by looking up the alias if provided

    :param connection: KMS AWS connection
    :param module: Ansible module object
    :return: CMK ID or None if not found
    """

    alias = module.params.get("alias")
    key_id = None

    if alias is not None and key_id is None:
        # Get all aliases and check for a match
        try:
            aliases_paginator = connection.get_paginator('list_aliases')
            aliases = aliases_paginator.paginate().build_full_result()
            for an_alias in aliases['Aliases']:
                if an_alias['AliasName'] == alias:
                    key_id = an_alias['TargetKeyId']
                    break
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    return key_id


def create_or_update_cmk(connection, module):
    """
    Create KMS CMK or modify existing attributes

    :param connection: KMS AWS connection
    :param module: Ansible module object
    :return: exit_json or fail_json before return
    """

    changed = False
    alias = module.params.get("alias")
    key_id = module.params.get("key_id")
    enabled = module.params.get("enabled")
    description = module.params.get("description")
    policy = module.params.get("policy")
    origin = module.params.get("origin")
    bypass_policy_lockout_safety_check = module.params.get("bypass_policy_lockout_safety_check")
    tags = module.params.get("tags")
    purge_tags = module.params.get("purge_tags")

    # If key_id not provided, try to find it
    if key_id is None:
        key_id = _get_cmk_id(connection, module)

    # If we've found or been given a key ID, fetch the key otherwise, create a new key
    if key_id is not None:
        try:
            cmk_key = connection.describe_key(KeyId=key_id)
        except ClientError:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        # Only check description if it's been set in the module
        if description is not None:
            # Check description
            if description != cmk_key['KeyMetadata']['Description']:
                try:
                    connection.update_key_description(KeyId=key_id, Description=description)
                    changed = True
                except ClientError as e:
                    module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        # Only check enabled status if it's set in the module
        if enabled is not None:
            # Check enabled status
            if enabled != cmk_key['KeyMetadata']['Enabled']:
                if enabled:
                    try:
                        connection.enable_key(KeyId=key_id)
                        changed = True
                    except ClientError as e:
                        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
                else:
                    try:
                        connection.disable_key(KeyId=key_id)
                        changed = True
                    except ClientError as e:
                        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        # Only check policy if it's set in the module
        if policy is not None and bypass_policy_lockout_safety_check is not None:
            # Get policy
            try:
                # Retrieve the policy - currently AWS spec says PolicyName must be 'default' but this could change!
                current_key_policy = connection.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

            # Compare policies
            if sort_json_policy_dict(current_key_policy) != sort_json_policy_dict(policy):
                try:
                    connection.put_key_policy(KeyId=key_id, PolicyName='default', Policy=policy, BypassPolicyLockoutSafetyCheck=bypass_policy_lockout_safety_check)
                    changed = True
                except ClientError as e:
                    module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
    else:
        params = {}
        if policy is not None:
            params['Policy'] = policy
        if description is not None:
            params['Description'] = description
        if origin is not None:
            params['Origin'] = origin
        if bypass_policy_lockout_safety_check is not None:
            params['BypassPolicyLockoutSafetyCheck'] = bypass_policy_lockout_safety_check
        if tags is not None:
            params['Tags'] = ansible_dict_to_boto3_tag_list(tags, tag_name_key_name='TagKey', tag_value_key_name='TagValue')
        params['KeyUsage'] = 'ENCRYPT_DECRYPT'

        try:
            cmk_key = connection.create_key(**params)
            key_id = cmk_key['KeyMetadata']['KeyId']
            changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    # Add / modify alias
    if alias is not None and key_id is not None:
        # Create the alias
        try:
            connection.create_alias(AliasName=alias, TargetKeyId=key_id)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                pass
            else:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    # Add / modify tags
    if tags is not None:
        # Get current tags
        try:
            tags_to_set, tags_to_unset = compare_aws_tags(boto3_tag_list_to_ansible_dict(connection.list_resource_tags(KeyId=key_id)['Tags'], tag_name_key_name='TagKey', tag_value_key_name='TagValue'), tags, purge_tags)
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        if tags_to_unset:
            try:
                connection.untag_resource(KeyId=key_id, TagKeys=tags_to_unset)
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        if tags_to_set:
            try:
                connection.tag_resource(KeyId=key_id, Tags=ansible_dict_to_boto3_tag_list(tags, tag_name_key_name='TagKey', tag_value_key_name='TagValue'))
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    # Get tags
    current_tags = boto3_tag_list_to_ansible_dict(connection.list_resource_tags(KeyId=key_id)['Tags'], tag_name_key_name='TagKey', tag_value_key_name='TagValue')

    module.exit_json(changed=changed, tags=current_tags, **camel_dict_to_snake_dict(cmk_key['KeyMetadata']))


def delete_cmk(connection, module):
    """
    Schedules a KMS CMK for deletion

    :param connection: KMS AWS connection
    :param module: Ansible module object
    :return: exit_json or fail_json before return
    """

    changed = False
    key_id = module.params.get("key_id")
    key_deletion_window = module.params.get("key_deletion_window")

    # If key_id not provided, try to find it
    if key_id is None:
        key_id = _get_cmk_id(connection, module)

    if key_id is not None:
        # Get the key so we can check the state
        try:
            cmk_key = connection.describe_key(KeyId=key_id)
        except ClientError:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

        if cmk_key['KeyMetadata']['KeyState'] != "PendingDeletion":
            try:
                connection.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=key_deletion_window)
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
    else:
        module.fail_json(msg="Unable to find key. Please specify a valid key ID or alias.")

    module.exit_json(changed=changed, key_id=key_id)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            alias=dict(required=False, type='str'),
            description=dict(required=False, type='str'),
            policy=dict(required=False, type='json'),
            origin=dict(required=False, default='AWS_KMS', choices=['AWS_KMS', 'EXTERNAL'], type='str'),
            bypass_policy_lockout_safety_check=dict(required=False, type='bool'),
            enabled=dict(required=False, type='bool'),
            key_id=dict(required=False, type='str'),
            key_deletion_window=dict(required=False, default=30, type='int'),
            purge_tags=dict(required=False, default=True, type='bool'),
            tags=dict(required=False, type='dict'),
            state=dict(required=True, choices=['present', 'absent'], type='str')
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=['policy', 'bypass_policy_lockout_safety_check']
    )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)

    if region:
        connection = boto3_conn(module, conn_type='client', resource='kms', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    else:
        module.fail_json(msg="region must be specified")

    state = module.params.get("state")

    if state == 'present':
        create_or_update_cmk(connection, module)
    else:
        delete_cmk(connection, module)

if __name__ == '__main__':
    main()
