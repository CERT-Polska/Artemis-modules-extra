#!/usr/bin/env python3
import socket
import ssl
from typing import Optional, Tuple

from artemis import load_risk_class
from artemis.binds import Device, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host
from artemis.utils import throttle_request
from karton.core import Task

CONTROL_REQUEST = """POST /remote/VULNCHECK HTTP/1.1\r
Host: {}\r
User-Agent: {}\r
Transfer-Encoding: chunked\r
\r
0\r
\r
\r
"""

VULN_CHECK_REQUEST = """POST /remote/VULNCHECK HTTP/1.1\r
Host: {}\r
User-Agent: {}\r
Transfer-Encoding: chunked\r
\r
0000000000000000FF\r
\r
"""


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class FortiVuln(ArtemisBase):  # type: ignore
    """
    Checks FortiOS instance for CVE-2024-21762 vulnerability
    source: https://github.com/BishopFox/CVE-2024-21762-check
    """

    identity = "forti_vuln"
    filters = [
        {"type": TaskType.DEVICE.value, "device": Device.FORTIOS.value},
    ]

    @staticmethod
    def _send_req(ssl_context: Optional[ssl.SSLContext], address: Tuple[str, int], req: bytes) -> int:
        try:
            s = socket.create_connection(address, timeout=5)
        except Exception:
            return -1

        if ssl_context is not None:
            ss = ssl_context.wrap_socket(s)
            ss.send(req)
        else:
            s.send(req)

        try:
            if ssl_context is not None:
                ss.read(2048)
            else:
                s.recv(2048)
            return 1
        except socket.timeout:
            return 0

    def vuln_check(self, host: str, port: int, is_ssl: bool) -> int:
        ssl_context = None
        if is_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        http_host = f"{host}:{port}"
        self.log.info(f"forti vuln scanning {http_host}")

        user_agent = "FortiOS vulnerability scanner"
        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            user_agent = Config.Miscellaneous.CUSTOM_USER_AGENT

        r1 = throttle_request(
            lambda: self._send_req(ssl_context, (host, port), CONTROL_REQUEST.format(http_host, user_agent).encode())
        )
        if r1 in [-1, 0]:
            return -1
        else:
            r2 = throttle_request(
                lambda: self._send_req(
                    ssl_context, (host, port), VULN_CHECK_REQUEST.format(http_host, user_agent).encode()
                )
            )
            if r2 == 0:
                return 1
        return 0

    def run(self, current_task: Task) -> None:
        result = []
        status = TaskStatus.OK
        status_reason = None

        ssl = current_task.get_payload("ssl")
        host = get_target_host(current_task)
        port = current_task.get_payload("port")
        check = self.vuln_check(host, port, ssl)

        if check == -1:
            status = TaskStatus.ERROR
            status_reason = "Could not send control request"
        elif check == 1:
            result.append("CVE-2024-21762")
            status = TaskStatus.INTERESTING
            status_reason = "Detected CVE-2024-21762 vulnerability"

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    FortiVuln().loop()
