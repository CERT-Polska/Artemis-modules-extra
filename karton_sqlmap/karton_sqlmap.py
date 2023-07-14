#!/usr/bin/env python3
import os
import random
import re
import shutil
import subprocess
from typing import List, Optional

import timeout_decorator
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.module_base import ArtemisBase
from karton.core import Task

OUTPUT_PATH = "/root/.local/share/sqlmap/output"
SQLI_ADDITIONAL_DATA_TIMEOUT = 600


class SQLmap(ArtemisBase):  # type: ignore
    """
    Runs sqlmap
    """

    identity = "sqlmap"
    filters = [
        # Run only on UNKNOWN webapps, e.g. homegrown CMS
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
    ]

    def _call_sqlmap(
        self, url: str, arguments: List[str], find_in_output: str, timeout_seconds: Optional[int] = None
    ) -> Optional[str]:
        def _run() -> Optional[str]:
            if Config.CUSTOM_USER_AGENT:
                additional_configuration = ["-A", Config.CUSTOM_USER_AGENT]
            else:
                additional_configuration = []

            cmd = (
                [
                    "python3",
                    "/sqlmap/sqlmap.py",
                    "--delay",
                    str(Config.Limits.SECONDS_PER_REQUEST),
                    "-u",
                    url,
                    "--crawl",
                    "1",
                    "--batch",
                    "--technique",
                    "B",
                    "--skip-waf",
                    "--skip-heuristics",
                    "-v",
                    "0",
                ]
                + arguments
                + additional_configuration
            )
            data = subprocess.check_output(cmd)

            data_str = data.decode("ascii", errors="ignore")

            for line in data_str.split("\n"):
                match_result = re.compile(f"^{re.escape(find_in_output)}[^:]*: '(.*)'$").fullmatch(line)
                if match_result:
                    return match_result.group(1)
            return None

        if timeout_seconds:
            try:
                return timeout_decorator.timeout(timeout_seconds)(_run)()  # type: ignore
            except TimeoutError:
                return None
        else:
            return _run()

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        number1 = random.randint(10, 99)
        number2 = random.randint(10, 99)
        number3 = random.randint(10, 99)

        try:
            shutil.rmtree(OUTPUT_PATH)
        except FileNotFoundError:
            pass

        # The logic here is as follows: we want SQLmap to blind the value of number1*number2*number3, therefore
        # making sure we have an actual SQL database behind, not a false positive. We make sure the value blinded
        # by SQLmap is equal to the actual product of these numbers.
        query = f"SELECT {number1}*{number2}*{number3}"

        message = None
        result = {}
        if self._call_sqlmap(url, ["--sql-query", query], query) == f"{number1 * number2 * number3}":
            for item in os.listdir(os.path.join(OUTPUT_PATH)):
                log_path = os.path.join(OUTPUT_PATH, item, "log")
                target_path = os.path.join(OUTPUT_PATH, item, "target.txt")

                if os.path.exists(log_path):
                    with open(target_path) as f:
                        # The format of the target is:
                        # url (METHOD)  # sqlmap_command
                        # e.g. http://127.0.0.1:8000/vuln.php?id=4 (GET)  # sqlmap.py --technique B -v 4 -u http://127.0.0.1:8000/ --crawl=1
                        target, _ = f.read().split("#", 1)
                        target = target.strip()

                    with open(log_path) as f:
                        log = f.read().strip()

                    message = f"Found SQL Injection in {target}"
                    result["target"] = target
                    result["log"] = log

                    version_query = "SELECT SUBSTR(VERSION(), 1, 15)"
                    for information_name, sqlmap_options, find_in_output in [
                        ("version", ["--sql-query", version_query], version_query),
                        ("user", ["--current-user"], "current user"),
                    ]:
                        try:
                            result[information_name] = self._call_sqlmap(
                                url, sqlmap_options, find_in_output, timeout_seconds=SQLI_ADDITIONAL_DATA_TIMEOUT
                            )  # type: ignore
                        except Exception:  # Whatever happens, we prefer to report SQLi without additional data than no SQLi
                            self.log.exception(f"Unable to obtain {information_name} via blind SQL injection")

        if message:
            status = TaskStatus.INTERESTING
            status_reason = message
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    SQLmap().loop()
