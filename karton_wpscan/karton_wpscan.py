#!/usr/bin/env python3
import json
import subprocess
import urllib.parse

from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from karton.core import Task

from extra_modules_config import ExtraModulesConfig


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

        # Parse the JSON data
        try:
            result = json.loads(data.stdout.decode("utf-8"))
        except json.JSONDecodeError:
            result = {"error": "Failed to decode JSON output from WPScan."}

        # Check if the input string is empty
        if not result:
            result = {"error": "No JSON output from WPScan."}

        # Extract interesting information from the result if available
        vulnerabilities = []
        interesting_urls = []

        if "interesting_findings" in result:
            for entry in result["interesting_findings"]:
                if "type" in entry and entry["type"] == "vulnerabilities":
                    vulnerabilities.append(entry)
                elif "url" in entry and urllib.parse.urlparse(entry["url"]).path.strip("/") != "":
                    interesting_urls.append(entry["url"])

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
