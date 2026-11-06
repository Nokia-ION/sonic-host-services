"""Standalone tests for RSyslogCfg TLS apply-state helpers."""

import os
import sys
import types
from unittest import mock

# Stub deps so hostcfgd can be imported without the full SONiC test env.
if 'swsscommon' not in sys.modules:
    swss = types.ModuleType('swsscommon')
    swss_inner = types.ModuleType('swsscommon.swsscommon')
    swss_inner.ConfigDBConnector = mock.Mock()
    swss_inner.DBConnector = mock.Mock()
    swss_inner.Table = mock.Mock()
    swss_inner.CFG_SYSLOG_CONFIG_TABLE_NAME = 'SYSLOG_CONFIG'
    swss_inner.CFG_SYSLOG_SERVER_TABLE_NAME = 'SYSLOG_SERVER'
    swss_inner.RestartWaiter = mock.Mock()
    swss.swsscommon = swss_inner
    sys.modules['swsscommon'] = swss
    sys.modules['swsscommon.swsscommon'] = swss_inner

for name in ('psutil', 'sonic_py_common', 'sonic_py_common.device_info',
             'sonic_py_common.general', 'sonic_installer', 'sonic_installer.bootloader',
             'ldap'):
    sys.modules.setdefault(name, mock.MagicMock())

import importlib.machinery
import importlib.util

test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
modules_path = os.path.dirname(test_path)
scripts_path = os.path.join(modules_path, 'scripts')
sys.path.insert(0, modules_path)

hostcfgd_path = os.path.join(scripts_path, 'hostcfgd')
loader = importlib.machinery.SourceFileLoader('hostcfgd_tls', hostcfgd_path)
spec = importlib.util.spec_from_loader(loader.name, loader)
hostcfgd = importlib.util.module_from_spec(spec)
loader.exec_module(hostcfgd)


class FakeStateDb(object):
    def __init__(self):
        self.data = {}

    def hget(self, key, field):
        return self.data.get(key, {}).get(field)

    def hset(self, key, field, value):
        self.data.setdefault(key, {})[field] = value

    def delete(self, key):
        self.data.pop(key, None)


def test_is_tls_server():
    assert hostcfgd.RSyslogCfg._is_tls_server({'protocol': 'tls'})
    assert hostcfgd.RSyslogCfg._is_tls_server({'transport_security': 'true'})
    assert not hostcfgd.RSyslogCfg._is_tls_server({'protocol': 'udp'})
    assert not hostcfgd.RSyslogCfg._is_tls_server({})


def test_publish_tls_state_missing_and_ready():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    servers = {
        '10.0.0.5': {'protocol': 'tls', 'tls_profile_id': 'siem-east',
                     'tls_permitted_peers': 'syslog.example.com'},
        '10.0.0.7': {'protocol': 'udp'},
        '10.0.0.9': {'protocol': 'tls'},
    }
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready',
                           side_effect=lambda pid: pid == 'siem-east'):
        cfg._publish_tls_apply_state(servers, apply_ok=True)
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'applied_transport_security') == 'true'
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NONE'
    assert state.hget('SYSLOG_SERVER|10.0.0.7', 'applied_transport_security') == 'false'
    assert state.hget('SYSLOG_SERVER|10.0.0.7', 'failure_reason') == 'NONE'
    assert state.hget('SYSLOG_SERVER|10.0.0.9', 'failure_reason') == 'NO_PROFILE'


def test_publish_tls_state_no_permitted_peers():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    servers = {
        '10.0.0.5': {'protocol': 'tls', 'tls_profile_id': 'siem-east'},
        '10.0.0.6': {'protocol': 'tls', 'tls_profile_id': 'siem-east',
                     'tls_permitted_peers': '  '},
        '10.0.0.7': {'transport_security': 'true', 'tls_profile_id': 'siem-east'},
    }
    # PEMs are present, so only the missing peers explain the failure.
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready', return_value=True):
        cfg._publish_tls_apply_state(servers, apply_ok=True)
    for addr in ('10.0.0.5', '10.0.0.6', '10.0.0.7'):
        key = 'SYSLOG_SERVER|' + addr
        assert state.hget(key, 'applied_transport_security') == 'false'
        assert state.hget(key, 'failure_reason') == 'NO_PERMITTED_PEERS'


def test_publish_tls_state_no_profile_wins_over_no_permitted_peers():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready', return_value=True):
        cfg._publish_tls_apply_state({'10.0.0.5': {'protocol': 'tls'}}, apply_ok=True)
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NO_PROFILE'


def test_publish_tls_state_no_permitted_peers_wins_over_no_certificate():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    servers = {'10.0.0.5': {'protocol': 'tls', 'tls_profile_id': 'siem-east'}}
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready', return_value=False):
        cfg._publish_tls_apply_state(servers, apply_ok=True)
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NO_PERMITTED_PEERS'


def test_publish_tls_state_no_certificate():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    servers = {'10.0.0.5': {'protocol': 'tls', 'tls_profile_id': 'siem-east',
                            'tls_permitted_peers': 'syslog.example.com'}}
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready', return_value=False):
        cfg._publish_tls_apply_state(servers, apply_ok=True)
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'applied_transport_security') == 'false'
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'NO_CERTIFICATE'


def test_publish_tls_state_apply_failed():
    state = FakeStateDb()
    cfg = hostcfgd.RSyslogCfg(state)
    cfg.cache = {'config': {}, 'servers': {}}
    servers = {'10.0.0.5': {'protocol': 'tls', 'tls_profile_id': 'siem-east',
                            'tls_permitted_peers': 'syslog.example.com'}}
    with mock.patch.object(hostcfgd.RSyslogCfg, 'profile_files_ready', return_value=True):
        cfg._publish_tls_apply_state(servers, apply_ok=False)
    assert state.hget('SYSLOG_SERVER|10.0.0.5', 'failure_reason') == 'RSYSLOG_APPLY_FAILED'


def test_profile_files_ready_paths_under_ssl_certs(tmp_path):
    dest = tmp_path / 'ssl-certs' / 'siem-east'
    dest.mkdir(parents=True)
    for name in hostcfgd.RSyslogCfg.DEST_FILES:
        (dest / name).write_text('x')
    orig = hostcfgd.RSyslogCfg.SSL_CERTS_DIR
    try:
        hostcfgd.RSyslogCfg.SSL_CERTS_DIR = str(tmp_path / 'ssl-certs')
        assert hostcfgd.RSyslogCfg.profile_files_ready('siem-east') is True
        (dest / 'key.pem').unlink()
        assert hostcfgd.RSyslogCfg.profile_files_ready('siem-east') is False
    finally:
        hostcfgd.RSyslogCfg.SSL_CERTS_DIR = orig
