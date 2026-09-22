"""Generic SSL profile install for gNSI Certz.

Copies Certz-rotated PEMs from the telemetry / certz_profiles tree into a
host directory that any TLS consumer (syslog, later RADIUS, etc.) can read.
One directory per SSL profile id:

    /etc/sonic/ssl-certs/<profile_id>/{cert,key,ca-bundle}.pem

After a completed install, delete, or restore, notifies CONFIG_DB consumers
via `_notify_consumers()` (syslog today: restart rsyslog-config only when a
SYSLOG_SERVER row uses this tls_profile_id). Add future TLS consumers there.

STATE_DB SSL_PROFILE|<id> tracks Certz profile existence on the host:
AddProfile creates the key with installed=false; install_profile sets
installed=true; DeleteProfile deletes the key.

D-Bus names (matching sonic-gnmi DbusClient):

    org.SONiC.HostService.ssl_profile.add_profile
    org.SONiC.HostService.ssl_profile.install_profile
    org.SONiC.HostService.ssl_profile.delete_profile
    org.SONiC.HostService.ssl_profile.create_checkpoint
    org.SONiC.HostService.ssl_profile.restore_checkpoint
    org.SONiC.HostService.ssl_profile.delete_checkpoint
"""

import grp
import logging
import os
import re
import shutil
import subprocess

from host_modules import host_service

MOD_NAME = 'ssl_profile'

# Host dest consumed by rsyslog.conf.j2 StreamDriver.*File and later consumers.
SSL_CERTS_DIR = '/etc/sonic/ssl-certs'
CHECKPOINT_ROOT = '/tmp/ssl_profile_checkpoint'
SSL_PROFILE_TABLE = 'SSL_PROFILE'
SSL_CERTS_GROUP = 'ssl-certs'

CERT_NAME = 'cert.pem'
KEY_NAME = 'key.pem'
CA_NAME = 'ca-bundle.pem'
DEST_FILES = (CERT_NAME, KEY_NAME, CA_NAME)

# Certz writes custom-profile PEMs under Dir(SrvCertLnk)/certz_profiles/<id>/
# (typically /etc/sonic/telemetry/...) and persists CA under
# /etc/sonic/certz_profiles/<id>/. /keys is the in-container Certz default.
ALLOWED_SOURCE_PREFIXES = (
    '/etc/sonic/telemetry/',
    '/etc/sonic/certz_profiles/',
    '/keys/',
)

DEFAULT_PROFILE = 'gnxi'
PROFILE_ID_RE = re.compile(r'^[A-Za-z0-9._-]+$')

DEST_DIR_MODE = 0o750
DEST_FILE_MODE = 0o640
DEST_FILE_MODE_FALLBACK = 0o644

logger = logging.getLogger(__name__)


def _validate_profile_id(profile_id):
    """Return an error string if profile_id is not usable, else None."""
    if not profile_id or not isinstance(profile_id, str):
        return 'profile id is empty'
    if profile_id in ('.', '..') or not PROFILE_ID_RE.match(profile_id):
        return 'invalid profile id %r' % (profile_id,)
    if profile_id == DEFAULT_PROFILE:
        return 'profile %r is the gNMI listener and is not installed as a host SSL profile' % (
            profile_id,)
    return None


def _dest_dir(profile_id):
    return os.path.join(SSL_CERTS_DIR, profile_id)


def _checkpoint_dir(profile_id):
    return os.path.join(CHECKPOINT_ROOT, profile_id)


def _is_under(path, prefix):
    """True if realpath(path) is prefix or a descendant of realpath(prefix)."""
    try:
        real_path = os.path.realpath(path)
        real_prefix = os.path.realpath(prefix)
        return os.path.commonpath([real_path, real_prefix]) == real_prefix
    except (ValueError, OSError):
        return False


def _is_allowed_source(src, profile_id):
    """Allow sources under telemetry / certz_profiles for this profile id."""
    if not src:
        return False
    if os.path.isabs(src) is False:
        return False
    marker = os.path.join('certz_profiles', profile_id) + os.sep
    real = os.path.realpath(src)
    # realpath of a missing leaf still keeps parent dirs; require the
    # profile directory in the resolved path so another id cannot feed this one.
    if marker not in (real + os.sep):
        return False
    for prefix in ALLOWED_SOURCE_PREFIXES:
        if _is_under(real, prefix):
            return True
    return False


def _ssl_certs_ids():
    """Return (uid, gid) for host SSL dest: root + ssl-certs group if present."""
    uid = 0
    gid = 0
    try:
        gid = grp.getgrnam(SSL_CERTS_GROUP).gr_gid
    except KeyError:
        pass
    return uid, gid


def _chown_chmod(path, mode, uid, gid):
    try:
        os.chmod(path, mode)
    except OSError as err:
        logger.warning('%s: chmod %s failed: %s', MOD_NAME, path, err)
        return False
    try:
        os.chown(path, uid, gid)
        return True
    except OSError as err:
        # Non-root unit tests, or missing ssl-certs group: loosen mode so
        # consumer daemons can still read after the image creates that group.
        logger.warning('%s: chown %s failed: %s', MOD_NAME, path, err)
        try:
            fallback = 0o755 if os.path.isdir(path) else DEST_FILE_MODE_FALLBACK
            os.chmod(path, fallback)
        except OSError:
            pass
        return False


def _secure_dir(path):
    os.makedirs(path, exist_ok=True)
    uid, gid = _ssl_certs_ids()
    _chown_chmod(path, DEST_DIR_MODE, uid, gid)


def _install_file(src, dest):
    """Copy src to dest via a sibling temp file, then chmod/chown for consumers."""
    dest_dir = os.path.dirname(dest)
    _secure_dir(dest_dir)
    tmp = dest + '.tmp'
    try:
        shutil.copy2(src, tmp)
        uid, gid = _ssl_certs_ids()
        _chown_chmod(tmp, DEST_FILE_MODE, uid, gid)
        os.replace(tmp, dest)
        # replace may keep dest's previous ownership; set again.
        _chown_chmod(dest, DEST_FILE_MODE, uid, gid)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _copy_existing(src_dir, dest_dir, names):
    """Copy named files that exist in src_dir into dest_dir. Missing is OK."""
    copied = 0
    for name in names:
        src = os.path.join(src_dir, name)
        if not os.path.isfile(src):
            continue
        _install_file(src, os.path.join(dest_dir, name))
        copied += 1
    return copied


def _remove_dest_files(dest_dir):
    if not os.path.isdir(dest_dir):
        return
    for name in DEST_FILES:
        path = os.path.join(dest_dir, name)
        try:
            os.remove(path)
        except FileNotFoundError:
            continue
        except OSError as err:
            logger.error('%s: failed to remove %s: %s', MOD_NAME, path, err)
            raise


def _dest_installed(profile_id):
    dest_dir = _dest_dir(profile_id)
    return all(os.path.isfile(os.path.join(dest_dir, name)) for name in DEST_FILES)


def _publish_ssl_profile_state(profile_id, installed):
    """Create or update STATE_DB SSL_PROFILE|<id> installed=true/false."""
    try:
        from swsscommon import swsscommon
        db = swsscommon.SonicV2Connector()
        db.connect(db.STATE_DB)
        key = '%s|%s' % (SSL_PROFILE_TABLE, profile_id)
        db.set(db.STATE_DB, key, 'installed', 'true' if installed else 'false')
        db.close()
    except Exception as err:
        logger.warning('%s: STATE_DB SSL_PROFILE write failed: %s', MOD_NAME, err)


def _delete_ssl_profile_state(profile_id):
    """Remove STATE_DB SSL_PROFILE|<id> after Certz DeleteProfile."""
    try:
        from swsscommon import swsscommon
        db = swsscommon.SonicV2Connector()
        db.connect(db.STATE_DB)
        key = '%s|%s' % (SSL_PROFILE_TABLE, profile_id)
        db.delete(db.STATE_DB, key)
        db.close()
    except Exception as err:
        logger.warning('%s: STATE_DB SSL_PROFILE delete failed: %s', MOD_NAME, err)


def _profile_used_by_syslog(profile_id):
    """True if CONFIG_DB SYSLOG_SERVER has a row with this tls_profile_id."""
    if not profile_id:
        return False
    try:
        from swsscommon.swsscommon import ConfigDBConnector
        db = ConfigDBConnector()
        db.connect(wait_for_init=False, retry_on=False)
        servers = db.get_table('SYSLOG_SERVER') or {}
        for row in servers.values():
            if isinstance(row, dict) and row.get('tls_profile_id') == profile_id:
                return True
    except Exception as err:
        logger.warning('%s: CONFIG_DB SYSLOG_SERVER lookup failed: %s',
                       MOD_NAME, err)
    return False


def _restart_rsyslog_config():
    """Restart rsyslog-config so Jinja re-scans /etc/sonic/ssl-certs."""
    try:
        subprocess.run(['systemctl', 'reset-failed', 'rsyslog-config',
                        'rsyslog'], check=False)
        subprocess.run(['systemctl', 'restart', 'rsyslog-config'], check=True)
    except Exception as err:
        logger.warning('%s: failed to restart rsyslog-config: %s', MOD_NAME, err)


def _notify_consumers(profile_id):
    """Reload host services that bind this SSL profile in CONFIG_DB.

    Add future TLS consumers here (RADIUS, OpenSSH, ...): check whether
    the profile id is referenced, then restart that consumer's config unit.
    """
    if _profile_used_by_syslog(profile_id):
        _restart_rsyslog_config()


class SslProfile(host_service.HostModule):
    """DBus endpoint that stages host-readable TLS PEMs per Certz profile."""

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def add_profile(self, profile_id):
        """Record STATE_DB SSL_PROFILE|<id> installed=false (Certz AddProfile)."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err
        _publish_ssl_profile_state(profile_id, False)
        return 0, 'Successfully added SSL profile %s' % profile_id

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='ssss', out_signature='is')
    def install_profile(self, profile_id, cert_src, key_src, ca_src):
        """Copy cert/key/CA from Certz into /etc/sonic/ssl-certs/<id>/."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err

        sources = []
        for src, dest_name in (
                (cert_src, CERT_NAME),
                (key_src, KEY_NAME),
                (ca_src, CA_NAME)):
            if not src:
                continue
            if not _is_allowed_source(src, profile_id):
                return 1, 'source %s is not an allowed certz_profiles path for %r' % (
                    src, profile_id)
            if not os.path.isfile(src):
                return 1, 'source file does not exist: %s' % src
            sources.append((src, dest_name))

        if not sources:
            return 1, 'no cert, key, or CA path given for profile %r' % (profile_id,)

        dest_dir = _dest_dir(profile_id)
        try:
            for src, dest_name in sources:
                _install_file(src, os.path.join(dest_dir, dest_name))
        except Exception as exc:
            logger.error('%s: install_profile %s failed: %s', MOD_NAME, profile_id, exc)
            return 1, 'failed to install profile %s: %s' % (profile_id, exc)

        _publish_ssl_profile_state(profile_id, True)
        _notify_consumers(profile_id)
        return 0, 'Successfully installed SSL profile %s' % profile_id

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def delete_profile(self, profile_id):
        """Remove host copies. Consumers must drop CONFIG_DB bindings first."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err

        dest_dir = _dest_dir(profile_id)
        try:
            if os.path.isdir(dest_dir):
                shutil.rmtree(dest_dir)
        except Exception as exc:
            logger.error('%s: delete_profile %s failed: %s', MOD_NAME, profile_id, exc)
            return 1, 'failed to delete profile %s: %s' % (profile_id, exc)

        _delete_ssl_profile_state(profile_id)
        _notify_consumers(profile_id)
        return 0, 'Successfully deleted SSL profile %s' % profile_id

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def create_checkpoint(self, profile_id):
        """Save current host copies (if any) so Rotate can roll back."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err

        ckpt = _checkpoint_dir(profile_id)
        if os.path.isdir(ckpt):
            logger.warning('%s: replacing existing checkpoint %s', MOD_NAME, ckpt)
            try:
                shutil.rmtree(ckpt)
            except Exception as exc:
                return 1, 'failed to replace checkpoint: %s' % exc

        try:
            os.makedirs(ckpt, exist_ok=True)
            dest_dir = _dest_dir(profile_id)
            if os.path.isdir(dest_dir):
                _copy_existing(dest_dir, ckpt, DEST_FILES)
        except Exception as exc:
            logger.error('%s: create_checkpoint %s failed: %s', MOD_NAME, profile_id, exc)
            try:
                shutil.rmtree(ckpt)
            except Exception:
                pass
            return 1, 'failed to create checkpoint: %s' % exc

        return 0, 'Successfully created checkpoint'

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def restore_checkpoint(self, profile_id):
        """Put host copies back to the pre-Rotate state. Leaves the checkpoint."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err

        ckpt = _checkpoint_dir(profile_id)
        if not os.path.isdir(ckpt):
            return 1, 'Checkpoint does not exist'

        dest_dir = _dest_dir(profile_id)
        try:
            if os.path.isdir(dest_dir):
                _remove_dest_files(dest_dir)
            _copy_existing(ckpt, dest_dir, DEST_FILES)
            # Empty checkpoint (first Rotate of this id): drop the dest dir.
            if os.path.isdir(dest_dir) and not any(
                    os.path.isfile(os.path.join(dest_dir, name))
                    for name in DEST_FILES):
                shutil.rmtree(dest_dir)
        except Exception as exc:
            logger.error('%s: restore_checkpoint %s failed: %s', MOD_NAME, profile_id, exc)
            return 1, 'failed to restore checkpoint: %s' % exc

        _publish_ssl_profile_state(profile_id, _dest_installed(profile_id))
        _notify_consumers(profile_id)
        return 0, 'Successfully restored checkpoint'

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def delete_checkpoint(self, profile_id):
        """Drop the checkpoint after Finalize or after restore."""
        err = _validate_profile_id(profile_id)
        if err:
            return 1, err

        ckpt = _checkpoint_dir(profile_id)
        if not os.path.isdir(ckpt):
            return 1, 'Checkpoint does not exist'
        try:
            shutil.rmtree(ckpt)
        except Exception as exc:
            logger.error('%s: delete_checkpoint %s failed: %s', MOD_NAME, profile_id, exc)
            return 1, 'Error in deleting checkpoint'
        return 0, 'Successfully deleted checkpoint'


def register():
    """Return class name."""
    return SslProfile, MOD_NAME
