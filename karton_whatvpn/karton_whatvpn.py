import subprocess

from artemis import load_risk_class, utils
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host
from karton.core import Task

from extra_modules_config import ExtraModulesConfig

logger = utils.build_logger(__name__)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class WhatVPN(ArtemisBase):  # type: ignore
    """
    Runs what-vpn -> SSL VPN identifier
    """

    identity = "what-vpn"
    filters = [{"type": TaskType.IP.value}]

    def _process(self, current_task: Task, host: str) -> None:

        version_output = subprocess.run(
            ["what-vpn", "--version"],
            capture_output=True,
        )

        library_version = version_output.stdout.decode("utf-8").strip().split(" ")[1]

        output = subprocess.run(
            ["what-vpn", "--keep-going-after-exception", "--timeout", ExtraModulesConfig.WHATVPN_TIMEOUT_SECONDS, host],
            capture_output=True,
        )

        output_str = output.stdout.decode("utf-8")
        detected_vpn = None
        data = None

        error_messages = ["error", "timeout"]
        if any(msg in output_str for msg in error_messages):
            status = TaskStatus.ERROR
            status_reason = "Error or timeout occurred"
        elif "no match" in output_str:
            status = TaskStatus.OK
            status_reason = "Could not identify a VPN gateway"
        else:
            # Format of what-vpn output:
            # scanned_host: identified_VPN [VPN_version]
            detected_vpn = output_str.split(" ", 1)[1]

            if "(" in detected_vpn:  # cases like 'Juniper Secure Connect (80%)'
                detected_vpn = detected_vpn.split("(")[0]

            status = TaskStatus.INTERESTING

            detected_vpn = detected_vpn.strip()

            status_reason = f"Detected {detected_vpn}"

            data: dict[str, str | None] = dict()

            # in that exact version of what-vpn, library only scans
            # for the vpns on the 443 port
            if library_version == "0.7":
                data = {"vpn": detected_vpn, "port": "443"}
                status_reason += " on port 443"
            else:
                data = {"vpn": detected_vpn, "port": None}

        # Save the task result to the database
        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=data,
        )

    def run(self, current_task: Task) -> None:
        target_host = get_target_host(current_task)

        self.log.info("Requested to check if %s is a VPN gateway", target_host)

        self._process(current_task, target_host)


if __name__ == "__main__":
    WhatVPN().loop()
