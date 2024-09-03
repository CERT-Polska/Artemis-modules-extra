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
        output = subprocess.run(
            ["what-vpn", "--keep-going-after-exception", "--timeout", ExtraModulesConfig.WHATVPN_TIMEOUT_SECONDS, host],
            capture_output=True,
        )
        output_str = output.stdout.decode("utf-8")
        detected_vpn = None

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
            status = TaskStatus.INTERESTING
            status_reason = f"Detected {detected_vpn}"

        # Save the task result to the database
        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=detected_vpn,
        )

    def run(self, current_task: Task) -> None:
        target_host = get_target_host(current_task)

        self.log.info("Requested to check if %s is a VPN gateway", target_host)

        self._process(current_task, target_host)


if __name__ == "__main__":
    WhatVPN().loop()
