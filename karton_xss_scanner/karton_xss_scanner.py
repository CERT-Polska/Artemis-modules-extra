import string
import subprocess
from urllib.parse import quote

import requests
from artemis import http_requests, load_risk_class, utils
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from karton.core import Task

logger = utils.build_logger(__name__)

XSS_PLACEHOLDER = "{xss}"


def prepare_crawling_result(output_str: str) -> list[str]:
    # Prepare set of vectors based on output from XSStrike library.
    lines = output_str.splitlines()
    vectors = set()

    for line in lines:
        line = line.lower().replace(" ", "")

        if "vulnerablewebpage:" in line:
            webpage = ""
            webpage = line.split("vulnerablewebpage:")[1]
            if webpage.count("http") == 2:
                webpage = webpage[: webpage[webpage.index("http") + 4 :].index("http") + 4]

            elif webpage.count("http") > 2:
                continue

            webpage = webpage[:-1] if webpage[-1] == "/" else webpage

        elif "vectorfor" in line:
            vector = "?" + line.split("vectorfor")[1].split(":")[0] + "=" + XSS_PLACEHOLDER
            if webpage:
                vectors.add(webpage + vector)

    return list(vectors)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class XssScanner(ArtemisBase):  # type: ignore
    identity = "xss_scanner"
    """
    Checks for potential XSS vulnerabilities.
    Preapre result with parameters that can be exploited and further test with specific payloads.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    filters = [
        # We run on all HTTP services, as even if it's a known CMS, it may contain custom plugins
        # and therefore it's worth scanning.
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _process(self, current_task: Task, host: str) -> None:
        host_sanitized = quote(host, safe="/:.?=&-")
        assert host_sanitized.startswith("http://") or host_sanitized.startswith("https://")
        assert all(i.lower() in "/:.?=&-" + string.ascii_lowercase + string.digits for i in host_sanitized)
        output = subprocess.run(["sh", "run_crawler.sh", host_sanitized], stdout=subprocess.PIPE)
        output_str = output.stdout.decode("utf-8")
        vectors = prepare_crawling_result(output_str)
        vectors_filtered = []
        for vector in vectors:
            payload = '"><testpayload'
            try:
                response = http_requests.get(vector.replace(XSS_PLACEHOLDER, payload)).content
                if payload in response.content:
                    vectors_filtered.append(vector)
            except requests.exceptions.RequestException:
                continue

        error_messages = ["error", "timeout"]
        if vectors_filtered:
            status = TaskStatus.INTERESTING
            status_reason = "Detected XSS vulnerabilities: {}".format(str(vectors_filtered))

        elif any(msg in output_str for msg in error_messages):
            status = TaskStatus.ERROR
            status_reason = "Error or timeout occurred"

        else:
            status = TaskStatus.OK
            status_reason = "Could not identify any XSS Vulnerability"

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"result": vectors_filtered},
        )

    def run(self, current_task: Task) -> None:
        target_host = get_target_url(current_task)

        self.log.info("Requested to check if %s has XSS Vulnerabilities", target_host)
        self._process(current_task, target_host)


if __name__ == "__main__":
    XssScanner().loop()
