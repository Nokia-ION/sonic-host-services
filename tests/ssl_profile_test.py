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
    # Collection-time os.remove, in case an earlier test leaked a mock onto os.remove.
    monkeypatch.setattr(os, 'remove', _REAL_OS_REMOVE)
    yield {
        'root': root,
        'src_root': src_root,
        'dest_root': dest_root,
        'ckpt_root': ckpt_root,
        'state': ssl_profile._publish_ssl_profile_state,
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
        # Generic installer must not restart rsyslog.
        if hasattr(sub, 'run'):
            sub.run.assert_not_called()

    def test_install_does_not_call_systemctl(self, tls_mod, fs):
        src = _write_sources(fs['src_root'], PROFILE)
        with mock.patch('subprocess.run') as run:
            code, msg = tls_mod.install_profile(
                PROFILE, src['cert'], src['key'], src['ca'])
            assert code == 0, msg
            run.assert_not_called()

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

    def test_module_has_no_systemctl_helpers(self):
        assert not hasattr(ssl_profile, '_reload_rsyslog')
        assert not hasattr(ssl_profile, '_syslog_servers_using_profile')
