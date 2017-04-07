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
module: aws_kms_alias
short_description: Manage KMS aliases
author: Rob White (@wimnat)
description:
     - Manage KMS aliases.  See U(http://docs.aws.amazon.com/kms/latest/developerguide/programming-aliases.html) for more information.
version_added: "2.4"
options:
  name:
    description:
      - String that contains the display name. The name must start with the word "alias" followed by a forward slash (alias/). Aliases that begin with "alias/AWS" are reserved.
    required: true
  target_key_id:
    description:
      - An identifier of the key for which you are creating the alias. This value cannot be another alias but can be a globally unique identifier or a fully specified ARN to a key.
        Required when I(state) is present.
    required: false
  state:
    description:
      - Create or remove the KMS alias.
    required: true
    choices: [ 'present', 'absent' ]
notes:
  - An alias can not be created without a attaching it to a key. Therefore, you might want to use the M(aws_kms_cmk) module to first
    ensure that the KMS CMK exists.
  - The alias and the key it is mapped to must be in the same AWS account and the same region.
extends_documentation_fragment:
- aws
- ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Create a KMS CMK
- aws_kms_cmk:
    state: present
  register: key

# Assign an alias to the new key
- aws_kms_alias:
    name: alias/my-key
    target_key_id: "{{ key.key_id }}"
    state: present

# Delete an alias
- aws_key_alias:
    name: alias/my-key
    state: absent

'''

RETURN = '''
alias_name:
  description: String that contains the alias.
  returned: when state is present
  type: string
  sample: alias/
alias_arn:
  description: String that contains the key ARN.
  rreturned: when state is present
  type: string
  sample: alias/
target_key_id:
  description: String that contains the key identifier referred to by the alias.
  returned: when state is present
  type: string
  sample: alias/
'''

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info, camel_dict_to_snake_dict, sort_json_policy_dict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def _get_alias(connection, module):
    """ Get KMS alias and return. Returns None if no alias found. """

    alias_name = module.params.get("name")
    alias = None

    # Get all aliases and check for a match
    try:
        aliases_paginator = connection.get_paginator('list_aliases')
        aliases = aliases_paginator.paginate().build_full_result()
        for an_alias in aliases['Aliases']:
            if an_alias['AliasName'] == alias_name:
                alias = an_alias
                break
    except ClientError as e:
        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    return alias


def create_or_update_alias(connection, module):
    """ Create or update a KMS alias """

    changed = False
    alias_name = module.params.get("name")
    target_key_id = module.params.get("target_key_id")

    alias = _get_alias(connection, module)

    # If key exists, update it (if necessary)
    if alias is not None:
        if alias['TargetKeyId'] != target_key_id:
            try:
                connection.update_alias(AliasName=alias_name, TargetKeyId=target_key_id)
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
    else:
        try:
            connection.create_alias(AliasName=alias_name, TargetKeyId=target_key_id)
            changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    # Get alias again
    alias = _get_alias(connection, module)

    module.exit_json(changed=changed, **camel_dict_to_snake_dict(alias))


def delete_alias(connection, module):

    changed = False
    alias_name = module.params.get("name")

    alias = _get_alias(connection, module)

    if alias is not None:
        try:
            connection.delete_alias(AliasName=alias_name)
            changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    module.exit_json(changed=changed)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            alias=dict(required=False, type='str'),
            state=dict(default='present', required=True, choices=['present', 'absent'], type='str')
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[['state', 'present', ['target_key_id']]]
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
        create_or_update_alias(connection, module)
    else:
        delete_alias(connection, module)

if __name__ == '__main__':
    main()
