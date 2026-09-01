import importlib.machinery
import importlib.util
import os
import subprocess
import sys

from unittest import TestCase, mock

test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
modules_path = os.path.dirname(test_path)
scripts_path = os.path.join(modules_path, "scripts")
sys.path.insert(0, modules_path)

# Load the file under test
hostcfgd_path = os.path.join(scripts_path, 'hostcfgd')
loader = importlib.machinery.SourceFileLoader('hostcfgd', hostcfgd_path)
spec = importlib.util.spec_from_loader(loader.name, loader)
hostcfgd = importlib.util.module_from_spec(spec)
loader.exec_module(hostcfgd)
sys.modules['hostcfgd'] = hostcfgd

V4_BASE = ['iptables', '-t', 'mangle']
V6_BASE = ['ip6tables', '-t', 'mangle']
CHAIN = hostcfgd.TACPLUS_DSCP_CHAIN
SERVERS = [{'ip': '10.0.0.1', 'tcp_port': '49'}]


def v4_rule(addr='10.0.0.1', port='49', dscp='32'):
    return V4_BASE + ['-A', CHAIN, '-p', 'tcp', '-d', addr, '--dport', port,
                      '-j', 'DSCP', '--set-dscp', dscp]


class TestHostcfgdTacacsDscp(TestCase):
    """
        Test hostcfgd daemon - DSCP marking of TACACS+ client traffic
    """

    def setUp(self):
        self.aaacfg = hostcfgd.AaaCfg(mock.Mock())

    def run_update(self, servers_conf, dscp, chain_exists=True, fails=False):
        """
            Drive update_tacacs_dscp with iptables mocked out and return the
            commands it would have run. chain_exists decides how the iptables
            queries answer, fails makes every iptables command fail.
        """
        # Patch the module object this file loaded rather than the name
        # "hostcfgd": every hostcfgd test module loads its own copy and
        # overwrites sys.modules, so a string target can land on someone
        # else's module and leave the real run_cmd in place.
        error = subprocess.CalledProcessError(1, 'iptables')
        with mock.patch.object(hostcfgd, 'run_cmd',
                               side_effect=error if fails else None) as run_cmd, \
                mock.patch.object(hostcfgd.subprocess, 'call',
                                  return_value=0 if chain_exists else 1):
            self.aaacfg.update_tacacs_dscp(servers_conf, dscp)
        return [call.args[0] for call in run_cmd.call_args_list]

    def prime(self):
        """
            Run the reconcile that happens at start up, so that the assertions
            of a test cover the steady state rather than the first pass.
        """
        self.run_update([], None, chain_exists=False)

    def test_first_pass_without_dscp_creates_nothing(self):
        # Fresh box: no chain and no dscp, so iptables must stay untouched.
        self.assertEqual(self.run_update(SERVERS, None, chain_exists=False), [])

    def test_first_pass_clears_rules_left_by_an_earlier_run(self):
        # dscp removed while hostcfgd was down: the leftover chain is flushed.
        self.assertEqual(self.run_update(SERVERS, None, chain_exists=True), [
            V4_BASE + ['-F', CHAIN],
            V6_BASE + ['-F', CHAIN],
        ])

    def test_chain_is_created_and_hooked_on_first_use(self):
        self.assertEqual(self.run_update(SERVERS, '32', chain_exists=False), [
            V4_BASE + ['-N', CHAIN],
            V4_BASE + ['-A', 'OUTPUT', '-j', CHAIN],
            V4_BASE + ['-F', CHAIN],
            v4_rule(),
        ])

    def test_ipv4_server_is_marked(self):
        self.prime()
        self.assertEqual(self.run_update(SERVERS, '32'), [
            V4_BASE + ['-F', CHAIN],
            v4_rule(),
        ])

    def test_ipv6_server_uses_ip6tables(self):
        self.prime()
        self.assertEqual(self.run_update([{'ip': 'fc00::1', 'tcp_port': '4949'}], '46'), [
            V6_BASE + ['-F', CHAIN],
            V6_BASE + ['-A', CHAIN, '-p', 'tcp', '-d', 'fc00::1',
                       '--dport', '4949', '-j', 'DSCP', '--set-dscp', '46'],
        ])

    def test_missing_tcp_port_falls_back_to_49(self):
        self.prime()
        self.assertEqual(self.run_update([{'ip': '10.0.0.1'}], '8')[-1],
                         v4_rule(dscp='8'))

    def test_unchanged_config_does_not_touch_iptables(self):
        self.prime()
        self.assertNotEqual(self.run_update(SERVERS, '32'), [])
        self.assertEqual(self.run_update(SERVERS, '32'), [])

    def test_removing_dscp_flushes_the_chain(self):
        self.prime()
        self.run_update(SERVERS, '32')
        self.assertEqual(self.run_update(SERVERS, None),
                         [V4_BASE + ['-F', CHAIN]])

    def test_removing_a_server_drops_its_rule(self):
        self.prime()
        both = SERVERS + [{'ip': '10.0.0.2', 'tcp_port': '49'}]
        self.run_update(both, '32')
        self.assertEqual(self.run_update(SERVERS, '32'), [
            V4_BASE + ['-F', CHAIN],
            v4_rule(),
        ])

    def test_a_failed_install_is_retried(self):
        self.prime()
        self.assertNotEqual(self.run_update(SERVERS, '32', fails=True), [])
        # The failure must not be cached as applied, or the identical config
        # that follows would be skipped and the marking never installed.
        self.assertEqual(self.run_update(SERVERS, '32'), [
            V4_BASE + ['-F', CHAIN],
            v4_rule(),
        ])

    def test_invalid_dscp_is_rejected(self):
        for bad in ('abc', '-1', '64'):
            with mock.patch.object(hostcfgd.syslog, 'syslog') as mocked_syslog:
                self.assertEqual(
                    self.aaacfg.build_tacacs_dscp_rules(SERVERS, bad),
                    {'4': [], '6': []})
                mocked_syslog.assert_called_once()

    def test_hostname_server_is_skipped(self):
        with mock.patch.object(hostcfgd.syslog, 'syslog') as mocked_syslog:
            self.assertEqual(
                self.aaacfg.build_tacacs_dscp_rules(
                    [{'ip': 'tacacs.example.com'}], '32'),
                {'4': [], '6': []})
            mocked_syslog.assert_called_once()
