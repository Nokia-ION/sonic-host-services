"""gNOI reset module which performs factory reset."""

import json
import logging
import subprocess
import threading
from host_modules import host_service
from sonic_py_common import device_info

MOD_NAME = "gnoi_reset"

RESET_FACTORY_CMD = "/usr/bin/reset-factory"
# Transient systemd unit that runs reset-factory outside of this daemon, so
# the reset survives the gnmi container and sonic.target being stopped.
RESET_UNIT = "gnoi-factory-reset"
# Give the gnmi front end time to send the StartResponse before reset-factory
# stops sonic.target (and with it the gnmi container).
RESET_DELAY_SEC = 5
SYSTEMD_RUN_TIMEOUT_SEC = 5

logger = logging.getLogger(__name__)


class GnoiReset(host_service.HostModule):
    """DBus endpoint that executes the factory reset and returns the reset status and response."""

    def __init__(self, mod_name):
        self.lock = threading.Lock()
        self.reset_request = {}
        self.reset_response = {}
        super(GnoiReset, self).__init__(mod_name)

    def populate_reset_response(
        self,
        reset_success=True,
        factory_os_unsupported=False,
        zero_fill_unsupported=False,
        detail="",
    ) -> tuple[int, str]:
        """Populate the factory reset response as a protojson StartResponse."""
        response = {}
        if reset_success:
            response["reset_success"] = {}
        else:
            error = {}
            if factory_os_unsupported:
                error["factory_os_unsupported"] = True
            if zero_fill_unsupported:
                error["zero_fill_unsupported"] = True
            if not factory_os_unsupported and not zero_fill_unsupported:
                error["other"] = True
            error["detail"] = detail
            response["reset_error"] = error
        self.reset_response = response
        return 0, json.dumps(response)

    def _check_reboot_in_progress(self) -> int:
        """Checks if a factory reset is already scheduled or running.

        The transient units are the source of truth: they are collected once
        reset-factory exits, so a failed reset does not block a retry.
        """
        cmd = ["systemctl", "is-active", "--quiet",
               RESET_UNIT + ".timer", RESET_UNIT + ".service"]
        try:
            result = subprocess.run(cmd, timeout=SYSTEMD_RUN_TIMEOUT_SEC)
        except (OSError, subprocess.SubprocessError) as e:
            # systemd-run still refuses to create a unit that already exists.
            logger.error("%s: Failed to query %s state: %s", MOD_NAME, RESET_UNIT, str(e))
            return 0
        return 1 if result.returncode == 0 else 0

    def _parse_arguments(self, options):
        """Parses and validates the given arguments into a reset request.

        Returns None when the request is valid and supported, otherwise the
        (rc, response) tuple to send back to the front end.
        """
        # The gnmi front end sends a single JSON string. It arrives as a str
        # on the real bus, but as a list of str fragments via some bindings.
        if not isinstance(options, str):
            options = "".join(options)
        try:
            raw = json.loads(options)
            if not isinstance(raw, dict):
                raise ValueError("request is not a JSON object")
        except ValueError as e:
            logger.error("%s: Failed to parse factory reset request: %s", MOD_NAME, str(e))
            return self.populate_reset_response(
                reset_success=False,
                detail="Failed to parse json formatted factory reset request into python dict.",
            )

        # Normalize: support both camelCase and snake_case
        self.reset_request = {
            "factoryOs": bool(raw.get("factoryOs", raw.get("factory_os", False))),
            "zeroFill": bool(raw.get("zeroFill", raw.get("zero_fill", False))),
            "retainCerts": bool(raw.get("retainCerts", raw.get("retain_certs", False))),
        }

        factory_os = self.reset_request["factoryOs"]
        zero_fill = self.reset_request["zeroFill"]
        if factory_os or zero_fill:
            unsupported = [name for name, is_set in
                           (("factory_os", factory_os), ("zero_fill", zero_fill)) if is_set]
            return self.populate_reset_response(
                reset_success=False,
                factory_os_unsupported=factory_os,
                zero_fill_unsupported=zero_fill,
                detail="%s currently unsupported." % " and ".join(unsupported),
            )

        # reset-factory --ztp relies on config-setup initializing the config
        # at boot, which it does not do on multi-asic platforms.
        if device_info.is_multi_npu():
            return self.populate_reset_response(
                reset_success=False,
                detail="Factory reset is not supported on multi-asic platforms.",
            )
        return None

    def _execute_reset(self, retain_certs) -> tuple[bool, str]:
        """Schedules reset-factory in a transient systemd unit."""
        cmd = [
            "systemd-run",
            "--unit=" + RESET_UNIT,
            "--description=gNOI FactoryReset",
            "--collect",
            "--on-active=%ds" % RESET_DELAY_SEC,
            "--timer-property=AccuracySec=100ms",
            RESET_FACTORY_CMD,
            "--ztp",
        ]
        if retain_certs:
            cmd.append("--retain-certs")
        logger.info("%s: Scheduling factory reset: %s", MOD_NAME, " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SYSTEMD_RUN_TIMEOUT_SEC,
            )
        except (OSError, subprocess.SubprocessError) as e:
            logger.error("%s: Failed to schedule factory reset: %s", MOD_NAME, str(e))
            return False, str(e)
        if result.returncode != 0:
            err = result.stderr.strip()
            logger.error("%s: systemd-run failed rc=%d: %s", MOD_NAME, result.returncode, err)
            return False, err
        return True, ""

    @host_service.method(
        host_service.bus_name(MOD_NAME), in_signature="as", out_signature="is"
    )
    def issue_reset(self, options) -> tuple[int, str]:
        """Issues the factory reset."""
        logger.info("%s: Issuing reset from back end", MOD_NAME)

        with self.lock:
            error = self._parse_arguments(options)
            if error is not None:
                return error

            if self._check_reboot_in_progress():
                return self.populate_reset_response(
                    reset_success=False, detail="Previous reset is ongoing."
                )

            ok, err = self._execute_reset(self.reset_request["retainCerts"])
            if not ok:
                return self.populate_reset_response(
                    reset_success=False,
                    detail="Failed to schedule factory reset: %s" % err,
                )

        logger.info("%s: Factory reset scheduled in %d seconds", MOD_NAME, RESET_DELAY_SEC)
        return self.populate_reset_response(reset_success=True)


def register():
    """Return the class name"""
    return GnoiReset, MOD_NAME
