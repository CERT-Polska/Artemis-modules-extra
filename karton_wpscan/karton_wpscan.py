#!/usr/bin/env python3
import json
import subprocess
import urllib.parse

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from karton.core import Task

from extra_modules_config import ExtraModulesConfig


class ScanningException(Exception):
    pass


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class WPScan(ArtemisBase):  # type: ignore
    """
    Runs WPScan -> WordPress Vulnerability Scanner
    """

    identity = "wpscan"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": "wordpress"},
    ]

    def run(self, current_task: Task) -> None:
        target_url = current_task.payload["url"]

        wpscan_api_key = ExtraModulesConfig.WPSCAN_API_KEY
        if not wpscan_api_key:
            # Run WPScan and get the JSON output without API key
            data = subprocess.run(
                [
                    "wpscan",
                    "--url",
                    target_url,
                    "--no-update",
                    "--disable-tls-checks",
                    "--format",
                    "json",
                    "--random-user-agent",
                ],
                capture_output=True,
            )
        elif wpscan_api_key:
            # Run WPScan and get the JSON output with API key

            data = subprocess.run(
                [
                    "wpscan",
                    "--url",
                    target_url,
                    "--no-update",
                    "--disable-tls-checks",
                    "--format",
                    "json",
                    "--random-user-agent",
                    "--api-token",
                    wpscan_api_key,
                ],
                capture_output=True,
            )

        try:
            result = json.loads(data.stdout.decode("utf-8"))
        except json.JSONDecodeError:
            result = {"error": "Failed to decode JSON output from WPScan."}

        if result.get("scan_aborted", None):
            raise ScanningException(result["scan_aborted"])

        if not result:
            result = {"error": "No JSON output from WPScan."}

        interesting_urls = []
        if "interesting_findings" in result:
            for entry in result["interesting_findings"]:
                if "url" in entry and urllib.parse.urlparse(entry["url"]).path.strip("/") != "":
                    interesting_urls.append(entry["url"])

        vulnerabilities = []
        for entry in result.get("plugins", {}).values():
            for vulnerability in entry["vulnerabilities"]:
                vulnerabilities.append(vulnerability["title"])
        for entry in result.get("themes", {}).values():
            for vulnerability in entry["vulnerabilities"]:
                vulnerabilities.append(vulnerability["title"])
        for vulnerability in result.get("main_theme", {}).get("vulnerabilities", []):
            vulnerabilities.append(vulnerability["title"])

        wp_version = result.get("version", {}).get("number", "")

        messages = [
            f"Vulnerabilities: {vulnerabilities}",
            f"Interesting URLs: {interesting_urls}",
            f"WP Version: {wp_version}",
        ]

        # Determine the task status based on the messages
        if vulnerabilities or interesting_urls:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        # Save the task result to the database
        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"vulnerabilities": vulnerabilities, "interesting_urls": interesting_urls, "result": result},
        )


if __name__ == "__main__":
    WPScan().loop()
