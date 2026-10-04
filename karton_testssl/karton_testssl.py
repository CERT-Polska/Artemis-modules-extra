import json
import subprocess
import tempfile
from difflib import SequenceMatcher
from typing import Dict, List

from karton.core import Task
from typing_extensions import Any

from artemis import load_risk_class, http_requests
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import throttle_request

from extra_modules_config import ExtraModulesConfig


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class TestSSL(ArtemisBase):
    """
    Testing TLS/SSL
    """

    identity = "testssl"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def _call_testssl(self, domain: str, arguments: List[str], timeout_seconds: int) -> list:
        with tempfile.NamedTemporaryFile() as f:
            subprocess.run(
                [
                    "bash",
                    "testssl.sh/testssl.sh",
                    f"--jsonfile={f.name}",
                    f"--openssl-timeout={timeout_seconds}",
                    *arguments,
                    domain,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            f.seek(0)
            data = f.read()

        return json.loads(data)

    def run(self, current_task: Task) -> None:
        domain = current_task.payload["domain"]
        self.log.info(f"testssl module checking {domain}")

        domain_parts = [part for part in domain.split(".") if part]
        if domain_parts[0] in ExtraModulesConfig.SUBDOMAINS_TO_SKIP_SSL_CHECKS:
            self.save_task_result(task=current_task, status=TaskStatus.OK)
            return

        try:
            response = http_requests.get(f"https://{domain}")
            parent_domain = ".".join(domain_parts[1:])
            parent_response = http_requests.get(f"https://{parent_domain}")
            if SequenceMatcher(None, response.content, parent_response.content).quick_ratio() >= 0.8:
                # Do not report misconfigurations if a domain has identical content to a parent domain - e.g.
                # if we have mail.domain.com with identical content to domain.com, we assume that it's domain.com
                # which is actually used, and therefore don't report subdomains.
                self.save_task_result(
                    task=current_task,
                    status=TaskStatus.OK,
                    status_reason=f"Detected that {domain} has similar content to {parent_domain}, not scanning to avoid duplicate reports",
                )
                return
        except Exception:
            self.log.exception(
                f"Unable to check whether domain {domain} has similar content to parent domain. Artemis SSL check "
                "module tries to reduce the number of false positives by skipping scanning domains when domain has "
                "similar content to parent domain, as there are cases where e.g. mail.example.com serves the same "
                "content as example.com.",
            )

        messages = []
        result: Dict[str, Any] = {}

        try:
            testssl_results = throttle_request(
                lambda: self._call_testssl(domain, ["--poodle"], Config.Limits.REQUEST_TIMEOUT_SECONDS)
            )
        except Exception:
            self.log.exception(f"Unable to complete scan for {domain}")
            testssl_results = []

        for testssl_result in testssl_results:
            if testssl_result["id"] == "POODLE_SSL" and testssl_result["severity"] == "HIGH":
                messages.append(f"{domain}: POODLE vulnerable")
                result["poodle"] = True

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    TestSSL.parallel_loop()
