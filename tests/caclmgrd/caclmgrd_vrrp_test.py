import os
import sys

from swsscommon import swsscommon
from unittest import TestCase, mock
from sonic_py_common.general import load_module_from_source
from pyfakefs.fake_filesystem_unittest import patchfs

from tests.common.mock_configdb import MockConfigDb

DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'


class TestCaclmgrdVrrp(TestCase):
    """
    Test that caclmgrd always emits an ACCEPT rule for VRRP (IP protocol 112)
    so VRRP/VRRPv3 advertisements reach the CPU even once a control-plane ACL
    installs the catch-all DROP.
    """
    def setUp(self):
        swsscommon.ConfigDBConnector = MockConfigDb
        test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.dirname(test_path)
        scripts_path = os.path.join(modules_path, "scripts")
        sys.path.insert(0, modules_path)
        caclmgrd_path = os.path.join(scripts_path, 'caclmgrd')
        self.caclmgrd = load_module_from_source('caclmgrd', caclmgrd_path)
        self.maxDiff = None

        self.vrrp_accept_rule_v4 = ('iptables', '-A', 'INPUT', '-p', '112', '-j', 'ACCEPT')
        self.vrrp_accept_rule_v6 = ('ip6tables', '-A', 'INPUT', '-p', '112', '-j', 'ACCEPT')
        self.default_deny_rule_v4 = ('iptables', '-A', 'INPUT', '-j', 'DROP')
        self.default_deny_rule_v6 = ('ip6tables', '-A', 'INPUT', '-j', 'DROP')

    def _run(self):
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ip = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ipv6 = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.generate_block_ip2me_traffic_iptables_commands = mock.MagicMock(return_value=[])
        self.caclmgrd.ControlPlaneAclManager.get_chain_list = mock.MagicMock(return_value=["INPUT", "FORWARD", "OUTPUT"])
        self.caclmgrd.ControlPlaneAclManager.get_chassis_midplane_interface_ip = mock.MagicMock(return_value='')
        caclmgrd_daemon = self.caclmgrd.ControlPlaneAclManager("caclmgrd")

        iptables_rules_ret, _ = caclmgrd_daemon.get_acl_rules_and_translate_to_iptables_commands('', MockConfigDb())
        return [tuple(i) for i in iptables_rules_ret]

    @patchfs
    def test_vrrp_accept_without_ctrlplane_acl(self, fs):
        """VRRP is accepted even with no control-plane ACL (no catch-all DROP)."""
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)

        MockConfigDb.set_config_db({
            "ACL_RULE": {},
            "ACL_TABLE": {},
            "DEVICE_METADATA": {"localhost": {}},
            "FEATURE": {},
        })

        rules = self._run()
        self.assertIn(self.vrrp_accept_rule_v4, rules)
        self.assertIn(self.vrrp_accept_rule_v6, rules)
        self.assertNotIn(self.default_deny_rule_v4, rules)

    @patchfs
    def test_vrrp_accept_precedes_ctrlplane_deny(self, fs):
        """With a CTRLPLANE ACL the catch-all DROP appears, but the VRRP ACCEPT
        is emitted before it so VRRP still reaches the CPU."""
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)

        MockConfigDb.set_config_db({
            "ACL_RULE": {
                "SSH_ONLY|RULE_22": {
                    "PACKET_ACTION": "ACCEPT",
                    "PRIORITY": "9978",
                    "SRC_IPV6": "2001::23/128",
                },
            },
            "ACL_TABLE": {
                "SSH_ONLY": {
                    "policy_desc": "SSH_ONLY",
                    "services": ["SSH"],
                    "stage": "ingress",
                    "type": "CTRLPLANE",
                },
            },
            "DEVICE_METADATA": {"localhost": {}},
            "FEATURE": {},
        })

        rules = self._run()
        self.assertIn(self.vrrp_accept_rule_v4, rules)
        self.assertIn(self.vrrp_accept_rule_v6, rules)
        self.assertIn(self.default_deny_rule_v4, rules)
        self.assertIn(self.default_deny_rule_v6, rules)
        # The ACCEPT must come before the catch-all DROP or it is dead.
        self.assertLess(rules.index(self.vrrp_accept_rule_v4), rules.index(self.default_deny_rule_v4))
        self.assertLess(rules.index(self.vrrp_accept_rule_v6), rules.index(self.default_deny_rule_v6))
