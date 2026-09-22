"""Tests for ssl_profile host module."""

import os
import stat
import tempfile
import shutil
from unittest import mock

import pytest

from host_modules import ssl_profile
from host_modules.ssl_profile import (
    CA_NAME,
    CERT_NAME,
    KEY_NAME,
    MOD_NAME,
    SslProfile,
    register,
)


PROFILE = 'siem-east'
OTHER_PROFILE = 'siem-west'
# Bound at import (collection) time, before any test can replace os.remove.
_REAL_OS_REMOVE = os.remove


@pytest.fixture
def tls_mod():
    with mock.patch.object(SslProfile, '__init__', return_value=None):
        yield SslProfile(MOD_NAME)


@pytest.fixture
def fs(tls_mod, monkeypatch):
    """Temp dest/checkpoint/source trees; no real STATE_DB."""
    root = tempfile.mkdtemp(prefix='ssl_profile_test_')
    src_root = os.path.join(root, 'telemetry') + os.sep
    dest_root = os.path.join(root, 'ssl-certs')
    ckpt_root = os.path.join(root, 'checkpoint')
    monkeypatch.setattr(ssl_profile, 'SSL_CERTS_DIR', dest_root)
    monkeypatch.setattr(ssl_profile, 'CHECKPOINT_ROOT', ckpt_root)
    monkeypatch.setattr(ssl_profile, 'ALLOWED_SOURCE_PREFIXES', (src_root,))
    monkeypatch.setattr(ssl_profile, '_ssl_certs_ids', lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(ssl_profile, '_publish_ssl_profile_state', mock.Mock())
    monkeypatch.setattr(ssl_profile, '_profile_used_by_syslog', mock.Mock(return_value=False))
    monkeypatch.setattr(ssl_profile, '_restart_rsyslog_config', mock.Mock())
    # Collection-time os.remove, in case an earlier test leaked a mock onto os.remove.
    monkeypatch.setattr(os, 'remove', _REAL_OS_REMOVE)
    yield {
        'root': root,
        'src_root': src_root,
        'dest_root': dest_root,
        'ckpt_root': ckpt_root,
        'state': ssl_profile._publish_ssl_profile_state,
        'used': ssl_profile._profile_used_by_syslog,
        'restart': ssl_profile._restart_rsyslog_config,
    }
    shutil.rmtree(root, ignore_errors=True)


def _write_sources(src_root, profile_id, cert='cert-body', key='key-body', ca='ca-body'):
    profile_dir = os.path.join(src_root, 'certz_profiles', profile_id)
    os.makedirs(profile_dir, exist_ok=True)
    paths = {}
    for name, body in (
            ('cert', cert),
            ('key', key),
            ('ca', ca)):
        path = os.path.join(profile_dir, name)
        if body is None:
            paths[name] = ''
            continue
        with open(path, 'w') as handle:
            handle.write(body)
        os.chmod(path, 0o600)
        paths[name] = path
    return paths


def _dest_path(fs, profile_id, name):
    return os.path.join(fs['dest_root'], profile_id, name)


class TestSslProfile(object):

    def test_register(self):
        cls, name = register()
        assert cls is SslProfile
        assert name == 'ssl_profile'

    def test_install_rejects_empty_and_gnxi(self, tls_mod, fs):
        code, msg = tls_mod.install_profile('', 'a', 'b', 'c')
        assert code == 1
        assert 'empty' in msg
        code, msg = tls_mod.install_profile('gnxi', 'a', 'b', 'c')
        assert code == 1
        assert 'gNMI' in msg
        code, msg = tls_mod.install_profile('../etc', 'a', 'b', 'c')
        assert code == 1
        assert 'invalid' in msg
        code, msg = tls_mod.install_profile('bad/id', 'a', 'b', 'c')
        assert code == 1
        assert 'invalid' in msg

    def test_install_success(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        with mock.patch('host_modules.ssl_profile.subprocess', create=True) as sub:
            sub.run = mock.Mock()
            code, msg = tls_mod.install_profile(
                PROFILE, src['cert'], src['key'], src['ca'])
        assert code == 0, msg
        assert PROFILE in msg
        assert 'SSL profile' in msg
        for name, body in (
                (CERT_NAME, 'cert-body'),
                (KEY_NAME, 'key-body'),
                (CA_NAME, 'ca-body')):
            dest = _dest_path(fs, PROFILE, name)
            assert os.path.isfile(dest)
            with open(dest) as handle:
                assert handle.read() == body
            mode = stat.S_IMODE(os.stat(dest).st_mode)
            assert mode in (0o640, 0o644)
        fs['state'].assert_called_with(PROFILE, True)
        fs['restart'].assert_not_called()

    def test_install_does_not_restart_when_profile_unused(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        with mock.patch('subprocess.run') as run:
            code, msg = tls_mod.install_profile(
                PROFILE, src['cert'], src['key'], src['ca'])
            assert code == 0, msg
            run.assert_not_called()
        fs['restart'].assert_not_called()

    def test_install_restarts_rsyslog_when_syslog_uses_profile(self, tls_mod, fs):
        fs['used'].return_value = True
        src = _write_sources(fs['src_root'], PROFILE)
        code, msg = tls_mod.install_profile(
            PROFILE, src['cert'], src['key'], src['ca'])
        assert code == 0, msg
        fs['restart'].assert_called_once()

    def test_delete_restarts_rsyslog_when_syslog_uses_profile(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        fs['restart'].reset_mock()
        fs['used'].return_value = True
        code, msg = tls_mod.delete_profile(PROFILE)
        assert code == 0, msg
        fs['restart'].assert_called_once()

    def test_restore_restarts_rsyslog_when_syslog_uses_profile(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE, cert='v1')
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        tls_mod.create_checkpoint(PROFILE)
        src2 = _write_sources(fs['src_root'], PROFILE, cert='v2')
        tls_mod.install_profile(PROFILE, src2['cert'], src2['key'], src2['ca'])
        fs['restart'].reset_mock()
        fs['used'].return_value = True
        code, msg = tls_mod.restore_checkpoint(PROFILE)
        assert code == 0, msg
        fs['restart'].assert_called_once()

    def test_checkpoint_does_not_restart_rsyslog(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        fs['used'].return_value = True
        fs['restart'].reset_mock()
        code, msg = tls_mod.create_checkpoint(PROFILE)
        assert code == 0, msg
        fs['restart'].assert_not_called()

    def test_notify_consumers_only_restarts_syslog_when_used(self, fs):
        fs['used'].return_value = False
        ssl_profile._notify_consumers(PROFILE)
        fs['restart'].assert_not_called()
        fs['used'].return_value = True
        ssl_profile._notify_consumers(PROFILE)
        fs['restart'].assert_called_once()

    def test_install_ca_only(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        code, msg = tls_mod.install_profile(PROFILE, '', '', src['ca'])
        assert code == 0, msg
        assert os.path.isfile(_dest_path(fs, PROFILE, CA_NAME))
        assert not os.path.exists(_dest_path(fs, PROFILE, CERT_NAME))

    def test_install_rejects_path_outside_allowlist(self, tls_mod, fs):
        outside = os.path.join(fs['root'], 'evil.pem')
        with open(outside, 'w') as handle:
            handle.write('nope')
        code, msg = tls_mod.install_profile(PROFILE, outside, '', '')
        assert code == 1
        assert 'not an allowed' in msg

    def test_install_rejects_other_profile_dir(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], OTHER_PROFILE)
        code, msg = tls_mod.install_profile(
            PROFILE, src['cert'], src['key'], src['ca'])
        assert code == 1
        assert 'not an allowed' in msg

    def test_install_rejects_missing_source(self, tls_mod, fs):
        profile_dir = os.path.join(fs['src_root'], 'certz_profiles', PROFILE)
        os.makedirs(profile_dir, exist_ok=True)
        missing = os.path.join(profile_dir, 'cert')
        code, msg = tls_mod.install_profile(PROFILE, missing, '', '')
        assert code == 1
        assert 'does not exist' in msg

    def test_install_rejects_empty_sources(self, tls_mod, fs):
        code, msg = tls_mod.install_profile(PROFILE, '', '', '')
        assert code == 1
        assert 'no cert' in msg

    def test_two_profiles_isolated(self, tls_mod, fs):
        east = _write_sources(fs['src_root'], PROFILE, cert='east-cert')
        west = _write_sources(fs['src_root'], OTHER_PROFILE, cert='west-cert')
        assert tls_mod.install_profile(
            PROFILE, east['cert'], east['key'], east['ca'])[0] == 0
        assert tls_mod.install_profile(
            OTHER_PROFILE, west['cert'], west['key'], west['ca'])[0] == 0
        with open(_dest_path(fs, PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'east-cert'
        with open(_dest_path(fs, OTHER_PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'west-cert'

    def test_checkpoint_restore_roundtrip(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE, cert='v1')
        assert tls_mod.install_profile(
            PROFILE, src['cert'], src['key'], src['ca'])[0] == 0
        code, msg = tls_mod.create_checkpoint(PROFILE)
        assert code == 0, msg

        src2 = _write_sources(fs['src_root'], PROFILE, cert='v2')
        assert tls_mod.install_profile(
            PROFILE, src2['cert'], src2['key'], src2['ca'])[0] == 0
        with open(_dest_path(fs, PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'v2'

        code, msg = tls_mod.restore_checkpoint(PROFILE)
        assert code == 0, msg
        with open(_dest_path(fs, PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'v1'
        # Checkpoint remains so Certz can call delete_checkpoint next.
        assert os.path.isdir(os.path.join(fs['ckpt_root'], PROFILE))
        code, msg = tls_mod.delete_checkpoint(PROFILE)
        assert code == 0, msg
        assert not os.path.isdir(os.path.join(fs['ckpt_root'], PROFILE))

    def test_restore_empty_checkpoint_removes_dest(self, tls_mod, fs):
        code, msg = tls_mod.create_checkpoint(PROFILE)
        assert code == 0, msg
        src = _write_sources(fs['src_root'], PROFILE)
        assert tls_mod.install_profile(
            PROFILE, src['cert'], src['key'], src['ca'])[0] == 0
        assert os.path.isdir(os.path.join(fs['dest_root'], PROFILE))
        code, msg = tls_mod.restore_checkpoint(PROFILE)
        assert code == 0, msg
        assert not os.path.isdir(os.path.join(fs['dest_root'], PROFILE))
        fs['state'].assert_called_with(PROFILE, False)

    def test_restore_missing_checkpoint(self, tls_mod, fs):
        code, msg = tls_mod.restore_checkpoint(PROFILE)
        assert code == 1
        assert 'does not exist' in msg

    def test_delete_checkpoint_missing(self, tls_mod, fs):
        code, msg = tls_mod.delete_checkpoint(PROFILE)
        assert code == 1
        assert 'does not exist' in msg

    def test_create_checkpoint_replaces_old(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE, cert='v1')
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        assert tls_mod.create_checkpoint(PROFILE)[0] == 0
        src2 = _write_sources(fs['src_root'], PROFILE, cert='v2')
        tls_mod.install_profile(PROFILE, src2['cert'], src2['key'], src2['ca'])
        assert tls_mod.create_checkpoint(PROFILE)[0] == 0
        tls_mod.restore_checkpoint(PROFILE)
        with open(_dest_path(fs, PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'v2'

    def test_delete_profile_success(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        code, msg = tls_mod.delete_profile(PROFILE)
        assert code == 0, msg
        assert not os.path.isdir(os.path.join(fs['dest_root'], PROFILE))
        fs['state'].assert_called_with(PROFILE, False)

    def test_delete_profile_succeeds_even_if_syslog_still_references(self, tls_mod, fs):
        """Generic installer does not refuse based on SYSLOG_SERVER."""
        src = _write_sources(fs['src_root'], PROFILE)
        tls_mod.install_profile(PROFILE, src['cert'], src['key'], src['ca'])
        code, msg = tls_mod.delete_profile(PROFILE)
        assert code == 0, msg
        assert not os.path.isdir(os.path.join(fs['dest_root'], PROFILE))

    def test_delete_profile_idempotent_when_missing(self, tls_mod, fs):
        code, msg = tls_mod.delete_profile(PROFILE)
        assert code == 0, msg

    def test_checkpoints_are_per_profile(self, tls_mod, fs):
        east = _write_sources(fs['src_root'], PROFILE, cert='east-v1')
        west = _write_sources(fs['src_root'], OTHER_PROFILE, cert='west-v1')
        tls_mod.install_profile(PROFILE, east['cert'], east['key'], east['ca'])
        tls_mod.install_profile(
            OTHER_PROFILE, west['cert'], west['key'], west['ca'])
        tls_mod.create_checkpoint(PROFILE)
        east2 = _write_sources(fs['src_root'], PROFILE, cert='east-v2')
        tls_mod.install_profile(PROFILE, east2['cert'], east2['key'], east2['ca'])
        tls_mod.restore_checkpoint(PROFILE)
        with open(_dest_path(fs, PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'east-v1'
        with open(_dest_path(fs, OTHER_PROFILE, CERT_NAME)) as handle:
            assert handle.read() == 'west-v1'


class TestNotifyConsumers(object):

    def test_profile_used_by_syslog_reads_tls_profile_id(self):
        fake_db = mock.Mock()
        fake_db.get_table.return_value = {
            '10.0.0.5': {'protocol': 'tls', 'tls_profile_id': PROFILE},
        }
        fake_cls = mock.Mock(return_value=fake_db)
        swss = mock.MagicMock()
        swss.ConfigDBConnector = fake_cls
        with mock.patch.dict('sys.modules', {
                'swsscommon': mock.MagicMock(),
                'swsscommon.swsscommon': swss}):
            assert ssl_profile._profile_used_by_syslog(PROFILE) is True
            assert ssl_profile._profile_used_by_syslog('other') is False

    def test_profile_used_by_syslog_false_on_empty_or_error(self):
        fake_db = mock.Mock()
        fake_db.get_table.return_value = {}
        swss = mock.MagicMock()
        swss.ConfigDBConnector = mock.Mock(return_value=fake_db)
        with mock.patch.dict('sys.modules', {
                'swsscommon': mock.MagicMock(),
                'swsscommon.swsscommon': swss}):
            assert ssl_profile._profile_used_by_syslog(PROFILE) is False
        assert ssl_profile._profile_used_by_syslog('') is False
        swss.ConfigDBConnector = mock.Mock(side_effect=RuntimeError('no redis'))
        with mock.patch.dict('sys.modules', {
                'swsscommon': mock.MagicMock(),
                'swsscommon.swsscommon': swss}):
            assert ssl_profile._profile_used_by_syslog(PROFILE) is False

    def test_restart_rsyslog_config_invokes_systemctl(self):
        with mock.patch('host_modules.ssl_profile.subprocess.run') as run:
            ssl_profile._restart_rsyslog_config()
            assert run.call_count == 2
            assert run.call_args_list[0][0][0][:2] == ['systemctl', 'reset-failed']
            assert run.call_args_list[1][0][0] == ['systemctl', 'restart', 'rsyslog-config']
