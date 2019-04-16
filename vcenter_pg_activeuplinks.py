#!/usr/bin/python
#
# (c) 2015, Joseph Callen <jcallen () csc.com>
# Portions Copyright (c) 2015 VMware, Inc. All rights reserved.
# Updated on 4/16/19 by Michael Tipton <mike () ibeta.org>
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: vcenter_pg_activeuplinks
short_description: set uplink to active or standby for portgroup
description:
    set uplink to active or standby for portgroup
options:
    vds_name:
        description:
            - name of the vds
        type: str
    pg_name:
        description:
            - Name of the portgroup to modify
        type: str
    uplink_state:
        description:
            - Set to active or standby
    uplinks:
        description:
            - list of desired active uplinks.
            - when specifing lag group only 1 lag may be specified
        type: list
    state:
        description:
            - be present or absent
        choices: ['present', 'absent']
        required: True
'''

EXAMPLES = '''
- name: modify pg
  vcenter_pg_activeuplinks:
    hostname: '172.16.0.100'
    username: 'administrator@corp.local'
    password: 'VMware1!'
    validate_certs: False
    vds_name: 'vds-001'
    pg_name: 'mgmt-pg-01'
    uplinks:
      - 'lag-grp-001'
    state: 'present'
'''


vc = {}

results = dict(changed=False, msg=dict())

def state_destroy_pguplink(module):
    results['changed'] = True

def state_exit_unchanged(module):
    results['changed'] = False

def state_update_pguplinks(module):
    results['changed'] = True

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.vmware import (connect_to_api, vmware_argument_spec, 
                                         find_dvs_by_name, find_dvspg_by_name,
                                         TaskError, wait_for_task)

def get_current_active_uplinks():

    pg = vc['pg']

    active_uplinks = \
        pg.config.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort

    return active_uplinks

def uplink_spec(module, uplinks, pg_config_version):

    spec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
    spec.configVersion = pg_config_version
    spec.defaultPortConfig =vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
    spec.defaultPortConfig.uplinkTeamingPolicy = vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortTeamingPolicy()

    if module.params['uplink_state'] == 'active':
        spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder = \
            vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortOrderPolicy()
        spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort = uplinks

    if module.params['uplink_state'] == 'standby':

        active_uplinks = get_current_active_uplinks()
        if not uplinks:
            uplinks = module.params['uplinks']

        spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder = \
            vim.dvs.VmwareDistributedVirtualSwitch.UplinkPortOrderPolicy()
        spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort = active_uplinks
        spec.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.standbyUplinkPort = uplinks

    return spec


def create_active_uplink(module, pg):

    changed = False
    result = None

    pg_spec = uplink_spec(module,
                          module.params['uplinks'],
                          vc['pg_config_version'])

    try:
        reconfig_task = pg.ReconfigureDVPortgroup_Task(pg_spec)
        changed, result = wait_for_task(reconfig_task)
    except TaskError as invalid_argument:
        module.fail_json(msg="Failed to update uplink portgroup : %s" % to_native(invalid_argument))

    return changed, result

def state_create_pguplinks(module):

    pg = vc['pg']

    changed, result = create_active_uplink(module, pg)

    if not changed:
        module.fail_json(msg="Failed to reconfigure active or standby uplinks")

    module.exit_json(changed=changed, result=result, msg="STATE CREATE")

def check_vds_for_lags(vds):

    lags = []

    if vds.config.lacpApiVersion != "multipleLag":
        return lags

    if not vds.config.lacpGroupConfig:
        return lags

    lags = [lag.name for lag in vds.config.lacpGroupConfig]

    return lags


def check_uplinks_lag_uplink(module, vds_lags):

    state = False

    uplinks = module.params['uplinks']
    check_lags = [v for v in uplinks if v in vds_lags]

    if len(uplinks) > 1 and not check_lags:
        state = (len(uplinks) == len(set(uplinks)))
    elif len(uplinks) == 1:
        state = True

    return state

def check_uplinks_valid(module):

    uplinks = module.params['uplinks']

    vds = vc['vds']

    vds_uplinks = vds.config.uplinkPortPolicy.uplinkPortName
    vds_lags = check_vds_for_lags(vds)

    invalid_uplinks = [x for x in uplinks if x not in vds_uplinks + vds_lags]

    if invalid_uplinks:
        module.fail_json(msg="Uplinks specified invalid: {}".format(invalid_uplinks))

    state = check_uplinks_lag_uplink(module, vds_lags)

    return state

def check_uplinks_present(module):

    state = False

    pg = vc['pg']

    if module.params['uplink_state'] == 'active':
        pg_uplinks = pg.config.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.activeUplinkPort

    if module.params['uplink_state'] == 'standby':
        pg_uplinks = pg.config.defaultPortConfig.uplinkTeamingPolicy.uplinkPortOrder.standbyUplinkPort

    if (pg_uplinks == module.params['uplinks']):
        state = True

    return state

def check_pguplink_state(module):

    state = 'absent'

    si = connect_to_api(module)
    vc['si'] = si

    vds = find_dvs_by_name(si, module.params['vds_name'])

    if not vds:
        module.fail_json(msg="Failed to get vds: {}".format(module.params['vds_name']))

    vc['vds'] = vds

    pg = find_dvspg_by_name(vds, module.params['pg_name'])

    if not pg:
        module.fail_json(msg="Failed to get portgroup: {}".format(module.params['pg_name']))

    vc['pg'] = pg
    vc['pg_config_version'] = pg.config.configVersion

    valid_uplinks = check_uplinks_valid(module)

    if not valid_uplinks:
        fail_msg = invalid_uplinks_fail_msg.format(module.params['uplinks'])
        module.fail_json(msg=fail_msg)

    uplinks_present = check_uplinks_present(module)

    if uplinks_present:
        state = 'present'

    return state

def main():
    argument_spec = vmware_argument_spec()

    argument_spec.update(
        dict(
            vds_name=dict(required=True, type='str'),
            pg_name=dict(required=True, type='str'),
            uplink_state=dict(required=True, choices=['active', 'standby'], type='str'),
            uplinks=dict(required=True, type='list'),
            state=dict(required=True, choices=['present', 'absent'], type='str'),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    pguplink_states = {
        'absent': {
            'present': state_destroy_pguplink,
            'absent': state_exit_unchanged,
        },
        'present': {
            'present': state_exit_unchanged,
            'update': state_update_pguplinks,
            'absent': state_create_pguplinks,
        }
    }

    desired_state = module.params['state']
    current_state = check_pguplink_state(module)
    pguplink_states[desired_state][current_state](module)
    module.exit_json(**results)

if __name__ == '__main__':
    main()
