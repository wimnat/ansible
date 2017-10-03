#!/usr/bin/python
#
# Copyright (c) 2017 Ansible Project
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: elasticache_replication_group
short_description: Manage AWS Elasticache replication groups
description:
    - Manage AWS Elasticache replication groups
version_added: "2.5"
author:
  - Rob White (@wimnat)
  - Will Thames (@willthames)
options: 
  name:
    description:
      - The replication group identifier.
    required: true
  description:
    description:
      - A user-created description for the replication group. Required when I(state) is C(present)
  primary_cluster_id:
    description:
      - The identifier of the cache cluster that will serve as the primary for this replication group.
        This cache cluster must already exist and have a status of available.
  failover_enabled:
    description:
      - Specifies whether a read-only replica will be automaticaly promoted to read/write primary
        if the existing primary fails. If true, Multi-AZ is enabled for this replication group.
    default: false
  region:
    description:
     - The AWS region to use. If not specified then the value of the EC2_REGION environment variable,
       if any, is used. See U(http://docs.aws.amazon.com/general/latest/gr/rande.html#ec2_region).
  num_cache_clusters:
    description:
      - The number of cache clusters this replication group will have. If Multi-AZ
        is enabled (see failover_enabled option), this parameter must be at least 2.
  apply_immediately:
    description:
      - Whether to apply major changes (engine version, node type) immediately or await a later reboot
    default: False
  auto_minor_version_upgrade:
    description:
      - Whether to automatically perform minor engine upgrades.
    default: false
  preferred_cache_cluster_azs:
    description:
      - A list of EC2 availability zones in which the replication group's cache clusters will be created.
  node_type:
    description:
      - The compute and memory capacity of the nodes in the node group.
  engine:
    description:
      - The name of the cache engine to be used for the cache clusters in this replication group.
    default: redis
  cache_engine_version:
    description:
      - The version number of the cache engine to be used for the cache clusters in this replication group.
  cache_parameter_group:
    description:
      - The name of the parameter group to associate with this replication group.
        If this argument is omitted, the default cache parameter group for the specified engine is used.
  cache_subnet_group_name:
    description:
      - The name of the cache subnet group to be used for the replication group.
  cache_security_groups:
    description:
      - A list of cache security group names to associate with this replication group.
  security_group_ids:
    description:
      - One or more Amazon VPC security groups associated with this replication group.
        Use this parameter only when you are creating a replication group in an Amazon Virtual Private Cloud (VPC).
  snapshot_arn:
    description:
      - An Amazon Resource Name (ARN) that uniquely identifies a Redis RDB snapshot
        file stored in Amazon S3. The snapshot file will be used to populate the node group.
        The Amazon S3 object name in the ARN cannot contain any commas. This parameter is
        only valid if the I(engine) parameter is C(redis).
  snapshot_name:
    description:
      - The name of a snapshot from which to restore data into the new node group.
        The snapshot status changes to restoring while the new node group is being created.
        This parameter is only valid if the I(engine) parameter is C(redis).
  preferred_maintenance_window:
    description:
      - Specifies the weekly time range during which maintenance on the cache cluster
        is performed. It is specified as a range in the format C(ddd:hh24:mi-ddd:hh24:mi) (24H Clock UTC).
        e.g. C(sun:05:00-sun:09:00). The minimum maintenance window is a 60 minute period.
  cache_port:
    description:
      - The port number on which each member of the replication group will accept connections.
  notification_topic_arn:
    description:
      - The Amazon Resource Name (ARN) of the Amazon Simple Notification Service (SNS) topic
        to which notifications will be sent. The Amazon SNS topic owner must be the same as the cache cluster owner.
  state:
    description:
      - Create or remove the Elasticache replication group
    required: true
    choices: [ 'present', 'absent', 'rebooted' ]
  snapshot_retention_limit:
    description:
      - The number of days for which ElastiCache will retain automatic snapshots before deleting them.
        For example, if you set I(snapshot_retention_limit) to 5, then a snapshot that was taken today
        will be retained for 5 days before being deleted.
    default: 0 (backups disabled)
  snapshot_window:
    description:
      - The daily time range (in UTC) during which ElastiCache will begin taking a daily snapshot of your node group e.g. C(05:00-09:00).
        If you do not specify this parameter, then ElastiCache will automatically choose an appropriate time range.
        This parameter is only valid if the I(engine) parameter is C(redis).
  retain_primary_cluster:
    description:
      - When removing a replication group, if set to true, all of the read replicas will be deleted, but the primary node will be retained.
  final_snapshot_id:
    description:
      - When removing a replication group, if set, the name of a final node group snapshot.
  wait:
    description: Wait for the replication group to be in state 'available' before returning
    required: false
    default: no
    choices: [ "yes", "no" ]

extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: create a 2 node, multi AZ replication group
  elasticache_replication_group:
    name: my-replica-group
    num_cache_clusters: 2
    failover_enabled: yes
    description: Ansible Test Elasticache Replication Group
    node_type: cache.t2.micro
    security_group_ids:
      - "{{ ec2_group_create.group_id }}"
    cache_subnet_group_name: "{{ resource_prefix}}elasticache-subnet-group"
    wait: yes

- name: increase the replication group size to 4 nodes
  elasticache_replication_group:
    name: my-replica-group
    num_cache_clusters: 4
    failover_enabled: yes
    description: Ansible Test Elasticache Replication Group
    node_type: cache.t2.micro
    security_group_ids:
      - "{{ ec2_group_create.group_id }}"
    cache_subnet_group_name: "{{ resource_prefix}}elasticache-subnet-group"
    wait: yes
'''

RETURN = '''
automatic_failover:
  description: Whether the Replication Group fails over automatically
  returned: always
  type: string
  sample: disabled
cache_node_type:
  description: Instance type of the cache nodes
  returned: always
  type: string
  sample: cache.t2.micro
cluster_enabled:
  description: Whether the cluster is of type enabled or disabled
  returned: always
  type: bool
  sample: false
description:
  description: Description of the Replication Group
  returned: always
  type: string
  sample: Ansible Test Elasticache Replication Group
member_clusters:
  description: Cache clusters belonging to the replication group
  returned: always
  type: list
  sample:
  - cache-cluster-001
  - cache-cluster-002
node_groups:
  description: Node groups belonging to the cluster
  returned: always
  type: complex
  contains:
    node_group_id:
      description: ID of the node group
      returned: always
      type: string
      sample: '0001'
    node_group_members:
      description: List of members of the node group
      returned: always
      type: complex
      contains:
        cache_cluster_id:
          description: ID of the cache cluster
          returned: always
          type: string
          sample: ansible-testing-erg-001
        cache_node_id:
          description: ID of the cache node
          returned: always
          type: string
          sample: '0001'
        current_role:
          description: Whether the node is primary or replica
          returned: always
          type: string
          sample: primary
        preferred_availability_zone:
          description: Availability Zone preferred by the cache node
          returned: always
          type: string
          sample: us-east-2a
        read_endpoint:
          description: Endpoint used to read from this node
          returned: always
          type: complex
          contains:
            address:
              description: Address of this endpoint
              returned: always
              type: string
              sample: ansible-testing-erg-001.qh5gss.0001.use2.cache.amazonaws.com
            port:
              description: Port for the endpoint of the current node
              returned: always
              type: int
              sample: 6379
    primary_endpoint:
      description: Endpoint for the Primary node in the replication group
      returned: always
      type: complex
      contains:
        address:
          description: Address of the replication group endpoint
          returned: always
          type: string
          sample: ansible-testing-erg.qh5gss.ng.0001.use2.cache.amazonaws.com
        port:
          description: Port of the replication group endpoint
          returned: always
          type: int
          sample: 6379
    status:
      description: Status of the node group
      returned: always
      type: string
      sample: available
pending_modified_values:
  description: Values that are awaiting a reboot to complete modification
  returned: always
  type: complex
  contains: {}
replication_group_id:
  description: ID of the Replication Group
  returned: always
  type: string
  sample: ansible-testing-erg
status:
  description: Status of the replication group
  returned: always
  type: string
  sample: available
'''

from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, ec2_argument_spec
from ansible.module_utils.ec2 import HAS_BOTO3, camel_dict_to_snake_dict
from ansible.module_utils.aws.core import AnsibleAWSModule


try:
    import botocore
except ImportError:
    pass  # caught by imported HAS_BOTO3


def check_for_rep_group(module, connection):

    params = dict()

    params['ReplicationGroupId'] = module.params['name']

    try:
        result = connection.describe_replication_groups(**params)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        if e.response['Error']['Code'] == 'ReplicationGroupNotFoundFault':
            return None
        else:
            module.fail_json_aws(e, msg="Couldn't search for replication group %s" % module.params['name'])

    return result['ReplicationGroups'][0]


def create_rep_group(module, connection):

    params = dict()

    params['ReplicationGroupId'] = module.params.get('name')
    params['ReplicationGroupDescription'] = module.params.get('description')
    params['PrimaryClusterId'] = module.params.get('primary_cluster_id')
    params['AutomaticFailoverEnabled'] = module.params.get('failover_enabled')
    params['NumCacheClusters'] = module.params.get('num_cache_clusters')
    params['PreferredCacheClusterAZs'] = module.params.get('preferred_cache_cluster_azs')
    params['CacheNodeType'] = module.params.get('node_type')
    params['Engine'] = module.params.get('engine')
    params['EngineVersion'] = module.params.get('cache_engine_version')
    params['CacheParameterGroupName'] = module.params.get('cache_parameter_group')
    params['CacheSubnetGroupName'] = module.params.get('cache_subnet_group_name')
    params['CacheSecurityGroupNames'] = module.params.get('cache_security_groups')
    params['SecurityGroupIds'] = module.params.get('security_group_ids')
    # need to do stuff here
    params['SnapshotArns'] = module.params.get('snapshot_arn')
    params['PreferredMaintenanceWindow'] = module.params.get('preferred_maintenance_window')
    params['Port'] = module.params.get('cache_port')
    params['NotificationTopicArn'] = module.params.get('notification_topic_arn')
    params['AutoMinorVersionUpgrade'] = module.params.get('auto_minor_version_upgrade')
    params['SnapshotRetentionLimit'] = module.params.get('snapshot_retention_limit')
    params['SnapshotWindow'] = module.params.get('snapshot_window')

    # Remove any items with a value of None
    for k, v in list(params.items()):
        if v is None:
            del params[k]

    try:
        connection.create_replication_group(**params)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        msg = "Couldn't create replication group"
        if e.response['Error']['Code'] == 'InvalidParameterCombination':
            msg = msg + (". This might be because of unsupported settings for T1/T2 instances. See: "
                         "http://docs.aws.amazon.com/AmazonElastiCache/latest/UserGuide/ParameterGroups.Redis.html#ParameterGroups.Redis.NodeSpecific"
                         " for more details")
        module.fail_json_aws(e, msg=msg)

    if module.params.get('wait'):
        waiter = connection.get_waiter('replication_group_available')
        waiter.wait(ReplicationGroupId=params['ReplicationGroupId'])

    rep_group = check_for_rep_group(module, connection)
    module.exit_json(changed=True, **camel_dict_to_snake_dict(rep_group))


def destroy_rep_group(module, connection):

    params = dict()

    params['ReplicationGroupId'] = module.params.get('name')
    params['RetainPrimaryCluster'] = module.params.get('retain_primary_cluster')
    params['FinalSnapshotIdentifier'] = module.params.get('final_snapshot_id')

    # Remove any items with a value of None
    for k, v in list(params.items()):
        if v is None:
            del params[k]

    try:
        connection.delete_replication_group(**params)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, msg="Couldn't delete replication group")

    if module.params.get('wait'):
        waiter = connection.get_waiter('replication_group_deleted')
        waiter.wait(ReplicationGroupId=params['ReplicationGroupId'])
        module.exit_json(changed=True)
    else:
        module.exit_json(changed=True)


def reboot_rep_group(module, connection, rep_group):
    for node_group in rep_group['NodeGroups'][0]['NodeGroupMembers']:
        try:
            connection.reboot_cache_cluster(CacheClusterId=node_group['CacheClusterId'],
                                            CacheNodeIdsToReboot=[node_group['CacheNodeId']])
            changed = True
            if module.params.get('wait'):
                waiter = connection.get_waiter('cache_cluster_available')
                waiter.wait(CacheClusterId=node_group['CacheClusterId'])
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, "Couldn't reboot cache cluster %s" % node_group['CacheClusterId'])

    result = check_for_rep_group(module, connection)
    module.exit_json(changed=changed, **camel_dict_to_snake_dict(result))


def modify_rep_group(module, connection, rep_group):

    changed = False

    params = dict()
    warnings = list()

    # Get Primary cluster ID
    primary_cluster_id = None
    for node_group in rep_group['NodeGroups']:
        for node_group_member in node_group['NodeGroupMembers']:
            if node_group_member['CurrentRole'] == 'primary':
                primary_cluster_id = node_group_member['CacheClusterId']
                break
        if primary_cluster_id is not None:
            break

    # Use the primary cluster ID to get cluster detail. This will be used for comparison to user passed parameters.
    try:
        primary_cache_cluster = connection.describe_cache_clusters(CacheClusterId=primary_cluster_id)['CacheClusters'][0]
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        if e.response['Error']['Code'] == 'CacheClusterNotFound':
            primary_cache_cluster = dict()
        else:
            module.fail_json_aws(e, msg=e.message)

    # Description
    if module.params.get('description') is not None and rep_group['Description'] != module.params.get('description'):
        params['ReplicationGroupDescription'] = module.params.get('description')

    # Primary cluster (used to change to the primary cluster ID)
    if module.params.get('primary_cluster_id') is not None and primary_cluster_id != module.params.get('primary_cluster_id'):
        params['PrimaryClusterId'] = module.params.get('primary_cluster_id')

    # Automatic failover
    if module.params['failover_enabled'] is not None:
        if (module.params['failover_enabled'] and rep_group['AutomaticFailover'] in ['disabled', 'disabling'] or
                    not module.params['failover_enabled'] and rep_group['AutomaticFailover'] in ['enabled', 'enabling']):
            params['AutomaticFailoverEnabled'] = module.params['failover_enabled']

    # Cache security groups (compared using primary cluster)
    #   Create a list of sec group names
    cluster_sec_group_name_list = []
    for sec_group in primary_cache_cluster['CacheSecurityGroups']:
        cluster_sec_group_name_list.append(sec_group['CacheSecurityGroupName'])

    if module.params.get('cache_security_groups') is not None and set(cluster_sec_group_name_list) != set(module.params.get('cache_security_groups')):
        params['CacheSecurityGroupNames'] = module.params.get('cache_security_groups')

    # Security groups (compared using primary cluster)
    #   Create a list of sec group IDs
    # FIXME: Handle both security group Ids and Names for SGs
    cluster_sec_group_id_list = []
    for sec_group in primary_cache_cluster['SecurityGroups']:
        cluster_sec_group_id_list.append(sec_group['SecurityGroupId'])

    if module.params.get('security_group_ids') is not None and set(cluster_sec_group_id_list) != set(module.params.get('security_group_ids')):
        params['SecurityGroupIds'] = module.params.get('security_group_ids')

    # Preferred maintenance window (compared using primary cluster)
    if module.params.get('preferred_maintenance_window') is not None and primary_cache_cluster['PreferredMaintenanceWindow'] != module.params.get('preferred_maintenance_window'):
        params['PreferredMaintenanceWindow'] = module.params.get('preferred_maintenance_window')

    # Notification topic (compared using primary cluster)
    if module.params.get('notification_topic_arn') is not None and 'NotificationConfiguration' in primary_cache_cluster and primary_cache_cluster['NotificationConfiguration']['TopicArn'] != module.params.get('notification_topic_arn'):
        params['NotificationTopicArn'] = module.params.get('notification_topic_arn')

    # Cache parameter group (compared using primary cluster)
    if module.params.get('cache_parameter_group') is not None and primary_cache_cluster['CacheParameterGroup']['CacheParameterGroupName'] != module.params.get('cache_parameter_group'):
        params['CacheParameterGroupName'] = module.params.get('cache_parameter_group')

    # Engine version (compared using primary cluster)
    if module.params.get('cache_engine_version') is not None and primary_cache_cluster['EngineVersion'] != module.params.get('cache_engine_version'):
        params['EngineVersion'] = module.params.get('cache_engine_version')

    # Snapshot retention limit
    if module.params.get('snapshot_retention_limit') is not None and rep_group['SnapshotRetentionLimit'] != module.params.get('snapshot_retention_limit'):
        params['SnapshotRetentionLimit'] = module.params.get('snapshot_retention_limit')

    # Snapshot window
    if module.params.get('snapshot_window') is not None and rep_group['SnapshotWindow'] != module.params.get('snapshot_window'):
        params['SnapshotWindow'] = module.params.get('snapshot_window')

    # Cache node type
    #   Boto3 docs state CacheNodeType is returned as part of replication_group describe but this is inaccurate.  Use cluster describe instead.
    if module.params.get('node_type') is not None and primary_cache_cluster['CacheNodeType'] != module.params.get('node_type'):
        params['CacheNodeType'] = module.params.get('node_type')

    # Cache size
    current_cache_cluster_count = len(rep_group['MemberClusters'])
    while module.params['num_cache_clusters'] < current_cache_cluster_count:
        cluster_to_remove = [cc for cc in rep_group['NodeGroups'][0]['NodeGroupMembers']
                             if cc['CurrentRole'] != 'primary'][-1]
        try:
            connection.delete_cache_cluster(CacheClusterId=cluster_to_remove['CacheClusterId'])
            current_cache_cluster_count -= 1
            changed = True
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, "Couldn't remove cache cluster %s" % cluster_to_remove['CacheClusterId'])

    # TODO: Check this line below. I changed to add 2 because otherwise it would create an ID already in use
    new_node_id = max([int(cc['CacheNodeId']) for cc in rep_group['NodeGroups'][0]['NodeGroupMembers']]) + 2
    while module.params['num_cache_clusters'] > current_cache_cluster_count:
        try:
            # Cache Cluster Ids must be less than 20 letters and not contain two consecutive hyphens
            # The replace is needed when the 16th character of the replication group happens to be a hyphen
            new_cache_cluster_id = ("%s-%03d" % (rep_group['ReplicationGroupId'][:16], new_node_id)).replace('--', '-')
            connection.create_cache_cluster(CacheClusterId=new_cache_cluster_id,
                                            ReplicationGroupId=rep_group['ReplicationGroupId'])
            new_node_id += 1
            current_cache_cluster_count += 1
            changed = True
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            module.fail_json_aws(e, "Couldn't add new cache cluster %s" % new_cache_cluster_id)
        if module.params.get('wait'):
            waiter = connection.get_waiter('cache_cluster_available')
            waiter.wait(CacheClusterId=new_cache_cluster_id)

    if params:
        params['ReplicationGroupId'] = module.params.get('name')
        params['ApplyImmediately'] = module.params.get('apply_immediately')

        try:
            connection.modify_replication_group(**params)
            changed = True
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            msg = "Couldn't modify replication group"
            if e.response['Error']['Code'] == 'InvalidParameterCombination':
                msg = msg + (". This might be because of unsupported settings for T1/T2 instances. See: "
                             "http://docs.aws.amazon.com/AmazonElastiCache/latest/UserGuide/ParameterGroups.Redis.html#ParameterGroups.Redis.NodeSpecific"
                             " for more details")
            module.fail_json_aws(e, msg=msg)

    result = check_for_rep_group(module, connection)
    module.exit_json(changed=changed, warnings=warnings, **camel_dict_to_snake_dict(result))


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            auto_minor_version_upgrade=dict(default=False, type='bool'),
            name=dict(required=True),
            description=dict(),
            primary_cluster_id=dict(),
            failover_enabled=dict(default=False, type='bool'),
            apply_immediately=dict(default=False, type='bool'),
            num_cache_clusters=dict(type='int'),
            preferred_cache_cluster_azs=dict(type='list'),
            node_type=dict(),
            engine=dict(default='redis', choices=['redis']),
            cache_engine_version=dict(),
            cache_parameter_group=dict(),
            cache_subnet_group_name=dict(),
            cache_security_groups=dict(type='list'),
            security_group_ids=dict(type='list'),
            snapshot_arn=dict(),
            snapshot_name=dict(),
            preferred_maintenance_window=dict(),
            cache_port=dict(type='int'),
            notification_topic_arn=dict(),
            state=dict(required=True, choices=['present', 'absent', 'rebooted']),
            snapshot_retention_limit=dict(type='int'),
            snapshot_window=dict(),
            retain_primary_cluster=dict(default=False, type='bool'),
            final_snapshot_id=dict(),
            wait=dict(default=False, type='bool'),
        )
    )

    module = AnsibleAWSModule(argument_spec=argument_spec,
                              required_one_of=[['primary_cluster_id', 'num_cache_clusters']],
                              required_if=[['state', 'present', ['description', 'node_type']]])

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    if not region:
        module.fail_json(msg="Region must be specified for this module")
    try:
        connection = boto3_conn(module, conn_type='client', resource='elasticache',
                                region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.BotoCoreError as e:
        module.fail_json_aws(e, msg="Couldn't connect to AWS")

    state = module.params.get('state')

    if module.params["num_cache_clusters"]:
        if module.params["failover_enabled"] and module.params["num_cache_clusters"] == 1:
            module.fail_json("Failover enabled requires at least two nodes")

    if state == "present":
        rep_group = check_for_rep_group(module, connection)
        if rep_group is None:
            create_rep_group(module, connection)
        else:
            modify_rep_group(module, connection, rep_group)
    elif state == "absent":
        rep_group = check_for_rep_group(module, connection)
        if rep_group is None:
            module.exit_json(changed=False)
        else:
            destroy_rep_group(module, connection)
    elif state == "rebooted":
        rep_group = check_for_rep_group(module, connection)
        if rep_group:
            reboot_rep_group(module, connection)
        else:
            module.fail_json(msg="Replication Group %s does not exist to reboot" % module.params['name'])


if __name__ == '__main__':
    main()
