#!/usr/bin/env python3
import datetime
import subprocess
import urllib.parse
from typing import Any, Dict, List

import requests
from artemis import http_requests
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import throttle_request
from cryptography import x509
from karton.core import Task
from sslyze import ServerNetworkLocation
from sslyze.plugins.certificate_info._certificate_utils import get_common_names
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.scanner import Scanner, ServerScanRequest, ServerScanResult


class SSL_checks(ArtemisBase):  # type: ignore
    """
    Runs SSL checks
    """

    identity = "ssl_checks"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def _matches_hostname(self, hostname: str, names: List[str]) -> bool:
        for name in names:
            if name.startswith("*."):
                name = name[2:]
                if is_subdomain(hostname, name):
                    return True
            if hostname == name:
                return True
        return False

    def run(self, current_task: Task) -> None:
        domain = current_task.payload["domain"]

        messages = []
        result: Dict[str, Any] = {}

        # We do not use sslyze verified_certificate_chain because it returns multiple false positives -
        # certificates with incomplete chains are marked as broken although they work in major browsers (e.g.
        # Chrome or Firefox). This is a misconfiguration, albeit not a serious one. Let's use then the perspective
        # of users and report only certificates that would be marked by Chrome as having bad certificate authority.
        try:
            output = subprocess.check_output(
                [
                    "chromium-browser",
                    "--headless",
                    "--no-sandbox",
                    "--enable-logging=v=1",
                    f"https://{domain}",
                ],
                stderr=subprocess.STDOUT,
            ).decode("ascii", errors="ignore")
            if "SSL error code 1, net_error -202" in output:  # -202 is ERR_CERT_AUTHORITY_INVALID
                messages.append(f"{domain}: certificate authority invalid")
                result["certificate_authority_invalid"] = True
        except Exception as e:
            result["certificate_authority_check_error"] = repr(e)

        try:
            original_url = f"http://{domain}"
            response = throttle_request(
                lambda: requests.get(
                    original_url,
                    verify=False,
                    stream=True,
                    timeout=Config.REQUEST_TIMEOUT_SECONDS,
                    headers=http_requests.HEADERS,
                )
            )
            result["response_status_code"] = response.status_code
            result["response_content_prefix"] = response.content.decode("utf-8", errors="ignore")[
                : Config.CONTENT_PREFIX_SIZE
            ]

            redirect_url = response.url
            if redirect_url:
                redirect_url_parsed = urllib.parse.urlparse(redirect_url)
                result["redirect_url"] = redirect_url

                if redirect_url_parsed.scheme != "https":
                    messages.append(
                        f"No https redirect from {original_url} to https detected, final url: {redirect_url}"
                    )
                    result["bad_redirect"] = True
            else:
                messages.append(f"No redirect from {original_url} to https detected")
                result["no_redirect"] = True
        except Exception as e:
            self.log.info("Unable to check redirect: %s", repr(e))
            result["redirect_check_exception"] = repr(e)

        server_location = ServerNetworkLocation(hostname=domain, port=443)

        def scan() -> List[ServerScanResult]:
            server_scan_req = ServerScanRequest(
                server_location=server_location,
                scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.HEARTBLEED},
            )
            scanner = Scanner(concurrent_server_scans_limit=1)
            scanner.queue_scans([server_scan_req])

            return list(scanner.get_results())

        results = throttle_request(scan)

        for server_scan_result in results:
            certinfo_result = server_scan_result.scan_result.certificate_info.result

            for cert_deployment in certinfo_result.certificate_deployments:
                names = get_common_names(cert_deployment.received_certificate_chain[0].subject)

                for extension in cert_deployment.received_certificate_chain[0].extensions:
                    if extension.oid.dotted_string == "2.5.29.17":  # subjectAltName
                        names.extend(extension.value.get_values_for_type(x509.DNSName))

                if not self._matches_hostname(domain, names):
                    messages.append(f"{domain}: certificate CN doesn't match hostname, CN: {names}")
                    result["cn_different_from_hostname"] = True
                    result["names"] = names
                    result["hostname"] = domain

            days_left = (cert_deployment.received_certificate_chain[0].not_valid_after - datetime.datetime.now()).days
            if days_left <= 0:
                messages.append(
                    f"{domain} : Certificate expired. "
                    f"Validity date: {cert_deployment.received_certificate_chain[0].not_valid_after}"
                )
                result["expired"] = True
                result["expiry_date"] = str(cert_deployment.received_certificate_chain[0].not_valid_after)

            if days_left <= 5 and days_left > 0:
                messages.append(
                    f"{domain} : Certificate almost expired. "
                    f"Validity date: {cert_deployment.received_certificate_chain[0].not_valid_after}"
                )
                result["almost_expired"] = True
                result["expiry_date"] = str(cert_deployment.received_certificate_chain[0].not_valid_after)

            heartbleed_result = server_scan_result.scan_result.heartbleed.result
            if heartbleed_result.is_vulnerable_to_heartbleed:
                messages.append(f"{domain} : Heartbleed vulnerable")
                result["heartbleed"] = True

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    SSL_checks().loop()
