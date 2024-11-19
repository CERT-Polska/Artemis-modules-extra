#!/usr/bin/env python3
import nmap
import time
import tempfile

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host
from karton.core import Task

from extra_modules_config import ExtraModulesConfig


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class VncAuth(ArtemisBase):  # type: ignore[misc]
    """
    Performs a brute force attack on VNC servers to guess password.
    """

    identity = "vnc_auth"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
    ]

    def brute_vnc(self, host, port, passwords_file) -> dict:
        np = nmap.PortScanner()
        result = np.scan(
            host,
            str(port),
            arguments=" ".join([
                "-Pn",
                "--disable-arp-ping",
                "--script vnc-brute",
                "--script-args",
                "'{}'".format(','.join([
                    "brute.mode=pass",
                    "brute.useraspass=false",
                    f"brute.delay={ExtraModulesConfig.VNC_AUTH_BRUTE_DELAY}",
                    "brute.passonly=true",
                    "brute.threads=0",
                    "brute.start=1",
                    "brute.firstonly=true",
                    "brute.retries=1",
                    f"passdb={passwords_file}"
                ]))
            ])
        )

        return result

    def parse_result(self, result, host, port) -> tuple[int, str]:
        try:
            script_result = result["scan"][host]["tcp"][port]["script"]["vnc-brute"]
        except KeyError:
            return -1, "ERROR - no script results found"

        if "Valid credentials" in script_result:
            return 1, "Valid credentials: {}".format(script_result.split('\n')[2].removesuffix('- Valid credentials').strip())
        elif "ERROR" in script_result:
            return -1, script_result[script_result.find("ERROR"):]
        elif "No valid accounts found" in script_result:
            return 0, "No valid credentials found"

    def run(self, current_task: Task) -> None:
        result = []
        status = TaskStatus.OK
        status_reason = None

        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, 'w') as f:
            f.write("\n".join(ExtraModulesConfig.VNC_AUTH_PASSWORD_LIST))

        time.sleep(ExtraModulesConfig.VNC_AUTH_INITIAL_SLEEP)

        result = self.brute_vnc(host, port, tmp.name)
        check_status, status_reason = self.parse_result(result, host, port)

        if check_status == -1:
            status = TaskStatus.ERROR
        elif check_status == 0:
            status = TaskStatus.OK
        elif check_status == 1:
            status = TaskStatus.INTERESTING

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    VncAuth().loop()
