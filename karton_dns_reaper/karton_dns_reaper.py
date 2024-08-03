#!/usr/bin/env python3
import json
import subprocess

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from karton.core import Task


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DNSReaper(ArtemisBase):  # type: ignore
    """
    Detects subdomain takeover vulnerabilities with DNSReaper
    """

    identity = "dns_reaper"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def run(self, current_task: Task) -> None:
        domain = current_task.payload["domain"]

        data = subprocess.check_output(
            [
                "python3",
                "/dnsReaper/main.py",
                "single",
                "--domain",
                domain,
                "--out-format",
                "json",
                "--out",
                "/dev/stdout",
            ],
            stderr=subprocess.DEVNULL,
        )

        data_str = data.decode("ascii", errors="ignore")

        if data_str.strip():
            result = json.loads(data_str)
        else:
            result = []

        messages = []
        for item in result:
            messages.append(item["info"])

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    DNSReaper().loop()
