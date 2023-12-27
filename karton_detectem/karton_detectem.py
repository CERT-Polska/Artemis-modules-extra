#!/usr/bin/env python3
import json
import subprocess

from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from karton.core import Task


class Detectem(ArtemisBase):  # type: ignore
    """
    Runs detectem -> detectem is a specialized software detector
    """

    identity = "detectem"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def run(self, current_task: Task) -> None:
        domain = current_task.payload["domain"]

        data = subprocess.check_output(
            [
                "det",
                "https://" + domain,
                "--format",
                "json",
                "--metadata"
            ],
            stderr=subprocess.DEVNULL,
        )

        data_str = data.decode("ascii", errors="ignore")

        # Check if the input string is empty
        if data_str.strip():
            result = json.loads(data_str)
        else:
            result = []

        messages = []
        for item in result[0]["softwares"]:
            messages.append(item["name"])

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Detectem().loop()
