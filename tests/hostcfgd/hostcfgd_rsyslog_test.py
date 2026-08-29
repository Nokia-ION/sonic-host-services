import importlib.machinery
import importlib.util
import os
import sys

from copy import copy
from swsscommon import swsscommon
from syslog import syslog, LOG_ERR
from tests.hostcfgd.test_rsyslog_vectors \
    import HOSTCFGD_TEST_RSYSLOG_VECTOR as rsyslog_test_data
from tests.common.mock_configdb import MockConfigDb, MockDBConnector
from unittest import TestCase, mock

test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
modules_path = os.path.dirname(test_path)
scripts_path = os.path.join(modules_path, "scripts")
templates_path = os.path.join(modules_path, "data/templates")
output_path = os.path.join(test_path, "hostcfgd/output")
sample_output_path = os.path.join(test_path, "hostcfgd/sample_output")
sys.path.insert(0, modules_path)

# Load the file under test
hostcfgd_path = os.path.join(scripts_path, 'hostcfgd')
loader = importlib.machinery.SourceFileLoader('hostcfgd', hostcfgd_path)
spec = importlib.util.spec_from_loader(loader.name, loader)
hostcfgd = importlib.util.module_from_spec(spec)
loader.exec_module(hostcfgd)
sys.modules['hostcfgd'] = hostcfgd

# Mock swsscommon classes
hostcfgd.ConfigDBConnector = MockConfigDb
hostcfgd.DBConnector = MockDBConnector
hostcfgd.Table = mock.Mock()
hostcfgd.run_cmd = mock.Mock()


class TestHostcfgdRSyslog(TestCase):
    """
        Test hostcfgd daemon - RSyslog
    """

    def __init__(self, *args, **kwargs):
        super(TestHostcfgdRSyslog, self).__init__(*args, **kwargs)
        self.host_config_daemon = None

    def setUp(self):
        MockConfigDb.set_config_db(rsyslog_test_data['initial'])
        self.host_config_daemon = hostcfgd.HostConfigDaemon()

        syslog_config = self.host_config_daemon.config_db.get_table(
            swsscommon.CFG_SYSLOG_CONFIG_TABLE_NAME)
        syslog_server = self.host_config_daemon.config_db.get_table(
            swsscommon.CFG_SYSLOG_SERVER_TABLE_NAME)

        assert self.host_config_daemon.rsyslogcfg.cache == {}
        self.host_config_daemon.rsyslogcfg.load(syslog_config, syslog_server)
        assert self.host_config_daemon.rsyslogcfg.cache != {}

        # Reset run_cmd mock
        hostcfgd.run_cmd.reset_mock()

    def tearDown(self):
        self.host_config_daemon = None
        MockConfigDb.set_config_db({})

    def update_config(self, config_name):
        MockConfigDb.mod_config_db(rsyslog_test_data[config_name])
        self.host_config_daemon.rsyslog_config_handler(None, None, None)

    def assert_applied(self, config_name):
        """Assert that updated config triggered appropriate services

        Args:
            config_name: str:   Test vectors config name

        Assert:
            Assert when config wasn't used
        """
        orig_cache = copy(self.host_config_daemon.rsyslogcfg.cache)
        self.update_config(config_name)
        assert self.host_config_daemon.rsyslogcfg.cache != orig_cache
        hostcfgd.run_cmd.assert_called()

    def assert_not_applied(self, config_name):
        """Assert that the same config does not affect on services

        Args:
            config_name: str:   Test vectors config name

        Assert:
            Assert when config was used
        """
        orig_cache = copy(self.host_config_daemon.rsyslogcfg.cache)
        self.update_config(config_name)
        assert self.host_config_daemon.rsyslogcfg.cache == orig_cache
        hostcfgd.run_cmd.assert_not_called()

    def test_rsyslog_handle_change_global(self):
        self.assert_applied('change_global')

    def test_rsyslog_handle_change_server(self):
        self.assert_applied('change_server')

    def test_rsyslog_handle_add_server(self):
        self.assert_applied('add_server')

    def test_rsyslog_handle_empty(self):
        self.assert_applied('empty_config')

    def test_rsyslog_handle_the_same_config(self):
        self.assert_not_applied('initial')

    def test_rsyslog_tls_missing_certs_sets_no_certificate(self):
        orig_cache = copy(self.host_config_daemon.rsyslogcfg.cache)
        with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready',
                               return_value=False):
            self.update_config('add_tls_server')
        assert self.host_config_daemon.rsyslogcfg.cache != orig_cache
        state = self.host_config_daemon.state_db_conn
        assert state.hget('SYSLOG_SERVER|10.0.0.5',
                          'applied_transport_security') == 'false'
        assert state.hget('SYSLOG_SERVER|10.0.0.5',
                          'failure_reason') == 'NO_CERTIFICATE'
        assert state.hget('SYSLOG_SERVER|1.1.1.1',
                          'applied_transport_security') == 'false'
        assert state.hget('SYSLOG_SERVER|1.1.1.1', 'failure_reason') == 'NONE'

    def test_rsyslog_tls_ready_certs_sets_applied(self):
        with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready',
                               return_value=True):
            self.update_config('add_tls_server')
        state = self.host_config_daemon.state_db_conn
        assert state.hget('SYSLOG_SERVER|10.0.0.5',
                          'applied_transport_security') == 'true'
        assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NONE'

    def test_profile_files_ready_requires_all_three(self):
        with mock.patch('os.path.isfile', side_effect=lambda p: p.endswith('ca-bundle.pem')):
            assert hostcfgd.RSyslogCfg.profile_files_ready('siem-east') is False
        with mock.patch('os.path.isfile', return_value=True):
            assert hostcfgd.RSyslogCfg.profile_files_ready('siem-east') is True
        assert hostcfgd.RSyslogCfg.profile_files_ready('') is False
        assert hostcfgd.RSyslogCfg.profile_files_ready(None) is False

    def test_profile_files_ready_uses_ssl_certs_dir(self):
        seen = []

        def fake_isfile(path):
            seen.append(path)
            return True

        with mock.patch('os.path.isfile', side_effect=fake_isfile):
            assert hostcfgd.RSyslogCfg.profile_files_ready('siem-east') is True
        assert any('/etc/sonic/ssl-certs/siem-east/' in path for path in seen)
        assert not any('rsyslog-certs' in path for path in seen)

    def test_ssl_profile_install_restarts_rsyslog_for_tls_row(self):
        with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready',
                               return_value=True):
            self.update_config('add_tls_server')
            hostcfgd.run_cmd.reset_mock()
            self.host_config_daemon.ssl_profile_handler(
                'siem-east', 'SET', {'installed': 'true'})
            hostcfgd.run_cmd.assert_called()
            state = self.host_config_daemon.state_db_conn
            assert state.hget('SYSLOG_SERVER|10.0.0.5',
                              'applied_transport_security') == 'true'
            assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NONE'

    def test_ssl_profile_unused_id_does_not_restart(self):
        hostcfgd.run_cmd.reset_mock()
        self.host_config_daemon.ssl_profile_handler(
            'other-id', 'SET', {'installed': 'true'})
        hostcfgd.run_cmd.assert_not_called()
