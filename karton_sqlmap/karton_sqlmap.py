#!/usr/bin/env python3
import os
import random
import shutil
import subprocess

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.module_base import ArtemisBase
from karton.core import Task

OUTPUT_PATH = "/root/.local/share/sqlmap/output"


class SQLmap(ArtemisBase):  # type: ignore
    """
    Runs sqlmap
    """

    identity = "sqlmap"
    filters = [
        # Run only on UNKNOWN webapps, i.e. homegrown CMS
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
    ]

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        number1 = random.randint(10, 99)
        number2 = random.randint(10, 99)
        number3 = random.randint(10, 99)

        if Config.CUSTOM_USER_AGENT:
            additional_configuration = ["-A", Config.CUSTOM_USER_AGENT]
        else:
            additional_configuration = []

        try:
            shutil.rmtree(OUTPUT_PATH)
        except FileNotFoundError:
            pass

        # The logic here is as follows: we want SQLmap to blind the value of number1*number2*number3, therefore
        # making sure we have an actual SQL database behind, not a false positive. We make sure the value blinded
        # by SQLmap is equal to the actual product of these numbers.
        query = f"SELECT {number1}*{number2}*{number3}"
        cmd = [
            "python3",
            "/sqlmap/sqlmap.py",
            "--delay",
            str(Config.SECONDS_PER_REQUEST_FOR_ONE_IP),
            "-u",
            url,
            "--crawl",
            "1",
            "--batch",
            "--technique",
            "B",
            "--skip-waf",
            "--skip-heuristics",
            "--sql-query",
            query,
        ] + additional_configuration
        data = subprocess.check_output(cmd)

        data_str = data.decode("ascii", errors="ignore")

        message = None
        result = {}
        if f"{query}: '{number1 * number2 * number3}'" in data_str:
            for item in os.listdir(os.path.join(OUTPUT_PATH)):
                log_path = os.path.join(OUTPUT_PATH, item, "log")
                target_path = os.path.join(OUTPUT_PATH, item, "target.txt")

                if os.path.exists(log_path):
                    with open(target_path) as f:
                        target, _ = f.read().split("#", 1)
                        target = target.strip()

                    with open(log_path) as f:
                        log = f.read().strip()

                    message = f"Found SQL Injection in {target}"
                    result["target"] = target
                    result["log"] = log

        if message:
            status = TaskStatus.INTERESTING
            status_reason = message
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task, status=status, status_reason=status_reason, data=result
        )


if __name__ == "__main__":
    SQLmap().loop()
