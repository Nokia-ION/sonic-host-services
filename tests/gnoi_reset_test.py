"""Tests for gnoi_reset."""

import importlib.util
import importlib.machinery
import json
import os
import subprocess
import sys

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock

test_path = os.path.dirname(os.path.abspath(__file__))
sonic_host_service_path = os.path.dirname(test_path)
host_modules_path = os.path.join(sonic_host_service_path, "host_modules")
sys.path.insert(0, sonic_host_service_path)

# Input requests based on gNOI CLI examples (snake_case and camelCase mix)
DEFAULT_RESET_REQUEST = '{}'
RETAIN_CERTS_REQUEST = '{"retainCerts": true}'
RETAIN_CERTS_SNAKE_REQUEST = '{"retain_certs": true}'
FACTORY_OS_REQUEST = '{"factory_os": true}'
ZERO_FILL_REQUEST = '{"zeroFill": true}'
FACTORY_OS_ZERO_FILL_REQUEST = '{"factory_os": true, "zero_fill": true}'
INVALID_RESET_REQUEST = '"factory_os": true, "zero_fill": true'
NON_OBJECT_RESET_REQUEST = '[1, 2]'

IS_ACTIVE_CMD = [
    "systemctl", "is-active", "--quiet",
    "gnoi-factory-reset.timer", "gnoi-factory-reset.service",
]
SYSTEMD_RUN_CMD = [
    "systemd-run",
    "--unit=gnoi-factory-reset",
    "--description=gNOI FactoryReset",
    "--collect",
    "--on-active=5s",
    "--timer-property=AccuracySec=100ms",
    "/usr/bin/reset-factory",
    "--ztp",
]


def load_source(modname, filename):
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
    module = importlib.util.module_from_spec(spec)
    # The module is always executed and not cached in sys.modules.
    # Uncomment the following line to cache the module.
    sys.modules[module.__name__] = module
    loader.exec_module(module)
    return module

load_source("host_service", host_modules_path + "/host_service.py")
load_source("gnoi_reset", host_modules_path + "/gnoi_reset.py")
from gnoi_reset import *


def completed(returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


class FakeSystemd:
    """Fakes subprocess.run for systemctl is-active and systemd-run."""

    def __init__(self, active=False, run_result=None, is_active_error=None):
        self.active = active
        self.run_result = run_result if run_result is not None else completed()
        self.is_active_error = is_active_error
        self.run_cmds = []

    def __call__(self, cmd, **kwargs):
        if cmd[0] == "systemctl":
            assert cmd == IS_ACTIVE_CMD
            if self.is_active_error:
                raise self.is_active_error
            return completed(returncode=0 if self.active else 3)
        assert cmd[0] == "systemd-run"
        self.run_cmds.append(cmd)
        if isinstance(self.run_result, Exception):
            raise self.run_result
        if self.run_result.returncode == 0:
            self.active = True
        return self.run_result


class TestGnoiReset:
    def setup_method(self):
        with mock.patch("gnoi_reset.super"):
            self.gnoi_reset_module = GnoiReset(MOD_NAME)
        self.multi_npu_patch = mock.patch("gnoi_reset.device_info.is_multi_npu", return_value=False)
        self.mock_multi_npu = self.multi_npu_patch.start()

    def teardown_method(self):
        self.multi_npu_patch.stop()

    def issue(self, request, fake):
        with mock.patch("gnoi_reset.subprocess.run", side_effect=fake):
            return self.gnoi_reset_module.issue_reset(request)

    def test_default_reset_success(self):
        fake = FakeSystemd()
        assert self.issue(DEFAULT_RESET_REQUEST, fake) == (0, '{"reset_success": {}}')
        assert fake.run_cmds == [SYSTEMD_RUN_CMD]

    def test_retain_certs(self):
        fake = FakeSystemd()
        assert self.issue(RETAIN_CERTS_REQUEST, fake) == (0, '{"reset_success": {}}')
        assert fake.run_cmds == [SYSTEMD_RUN_CMD + ["--retain-certs"]]

    def test_retain_certs_snake_case(self):
        fake = FakeSystemd()
        assert self.issue(RETAIN_CERTS_SNAKE_REQUEST, fake) == (0, '{"reset_success": {}}')
        assert fake.run_cmds == [SYSTEMD_RUN_CMD + ["--retain-certs"]]

    def test_options_as_string_list(self):
        fake = FakeSystemd()
        assert self.issue(['{"retain', 'Certs": true}'], fake) == (0, '{"reset_success": {}}')
        assert fake.run_cmds == [SYSTEMD_RUN_CMD + ["--retain-certs"]]

    def test_factory_os_unsupported(self):
        fake = FakeSystemd()
        result = self.issue(FACTORY_OS_REQUEST, fake)
        assert result[0] == 0
        assert json.loads(result[1]) == {
            "reset_error": {
                "factory_os_unsupported": True,
                "detail": "factory_os currently unsupported.",
            }
        }
        assert fake.run_cmds == []

    def test_zero_fill_unsupported(self):
        fake = FakeSystemd()
        result = self.issue(ZERO_FILL_REQUEST, fake)
        assert result[0] == 0
        assert json.loads(result[1]) == {
            "reset_error": {
                "zero_fill_unsupported": True,
                "detail": "zero_fill currently unsupported.",
            }
        }
        assert fake.run_cmds == []

    def test_factory_os_and_zero_fill_unsupported(self):
        fake = FakeSystemd()
        result = self.issue(FACTORY_OS_ZERO_FILL_REQUEST, fake)
        assert json.loads(result[1]) == {
            "reset_error": {
                "factory_os_unsupported": True,
                "zero_fill_unsupported": True,
                "detail": "factory_os and zero_fill currently unsupported.",
            }
        }
        assert fake.run_cmds == []

    def test_multi_asic_unsupported(self):
        self.mock_multi_npu.return_value = True
        fake = FakeSystemd()
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1]) == {
            "reset_error": {
                "other": True,
                "detail": "Factory reset is not supported on multi-asic platforms.",
            }
        }
        assert fake.run_cmds == []

    def test_invalid_json_format(self):
        fake = FakeSystemd()
        result = self.issue(INVALID_RESET_REQUEST, fake)
        assert result[0] == 0
        assert json.loads(result[1]) == {
            "reset_error": {
                "other": True,
                "detail": "Failed to parse json formatted factory reset request into python dict.",
            }
        }
        assert fake.run_cmds == []

    def test_non_object_json(self):
        fake = FakeSystemd()
        result = self.issue(NON_OBJECT_RESET_REQUEST, fake)
        assert json.loads(result[1])["reset_error"]["other"] is True
        assert fake.run_cmds == []

    def test_reset_ongoing(self):
        fake = FakeSystemd(active=True)
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1]) == {
            "reset_error": {"other": True, "detail": "Previous reset is ongoing."}
        }
        assert fake.run_cmds == []

    def test_second_reset_rejected(self):
        fake = FakeSystemd()
        assert self.issue(DEFAULT_RESET_REQUEST, fake) == (0, '{"reset_success": {}}')
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1])["reset_error"]["detail"] == "Previous reset is ongoing."
        assert len(fake.run_cmds) == 1

    def test_retry_after_failed_reset(self):
        fake = FakeSystemd()
        assert self.issue(DEFAULT_RESET_REQUEST, fake) == (0, '{"reset_success": {}}')
        # reset-factory exited without rebooting; systemd collected the units.
        fake.active = False
        assert self.issue(DEFAULT_RESET_REQUEST, fake) == (0, '{"reset_success": {}}')
        assert len(fake.run_cmds) == 2

    def test_is_active_query_failure_falls_back_to_systemd_run(self):
        fake = FakeSystemd(is_active_error=FileNotFoundError("systemctl"))
        assert self.issue(DEFAULT_RESET_REQUEST, fake) == (0, '{"reset_success": {}}')
        assert fake.run_cmds == [SYSTEMD_RUN_CMD]

    def test_systemd_run_failure(self):
        fake = FakeSystemd(run_result=completed(
            returncode=1, stderr="Unit gnoi-factory-reset.timer was already loaded or has a fragment file."))
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1]) == {
            "reset_error": {
                "other": True,
                "detail": "Failed to schedule factory reset: "
                          "Unit gnoi-factory-reset.timer was already loaded or has a fragment file.",
            }
        }

    def test_systemd_run_missing(self):
        fake = FakeSystemd(run_result=FileNotFoundError("systemd-run"))
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1])["reset_error"]["other"] is True

    def test_systemd_run_timeout(self):
        fake = FakeSystemd(run_result=subprocess.TimeoutExpired(cmd="systemd-run", timeout=5))
        result = self.issue(DEFAULT_RESET_REQUEST, fake)
        assert json.loads(result[1])["reset_error"]["other"] is True

    def test_populate_reset_response_success(self):
        _, response = self.gnoi_reset_module.populate_reset_response(reset_success=True)
        assert response == '{"reset_success": {}}'

    def test_populate_reset_response_other_error(self):
        _, response = self.gnoi_reset_module.populate_reset_response(
            reset_success=False,
            detail="Generic failure."
        )
        assert response == (
            '{"reset_error": {"other": true, "detail": "Generic failure."}}'
        )

    def test_register(self):
        result = register()
        assert result[0] == GnoiReset
        assert result[1] == MOD_NAME
