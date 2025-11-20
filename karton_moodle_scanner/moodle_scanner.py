#!/usr/bin/env python3
import re
from hashlib import md5
from pathlib import Path
from typing import Tuple

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.http_requests import get
from artemis.modules.base.base_newer_version_comparer import (
    BaseNewerVersionComparerModule,
)
from artemis.task_utils import get_target_url
from karton.core import Task


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class MoodleScanner(BaseNewerVersionComparerModule):  # type: ignore
    """
    Runs Moodle-Scanner -> A Moodle Vulnerability Analyzer and checks for obsolete versions
    """

    identity: str = "moodle_scanner"
    filters: list[dict[str, str]] = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
    ]
    software_name = "moodle"

    def get_version_based_on_hash_file(self, url: str) -> Tuple[str, str] | None:
        files = [
            "/admin/environment.xml",
            "/composer.lock",
            "/privacy/export_files/general.js",
            "/composer.json",
            "/admin/tool/lp/tests/behat/course_competencies.feature",
        ]
        script_dir = Path(__file__).resolve().parent
        versions_file_path = script_dir / "moodle_versions.txt"

        versions = []
        with versions_file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(";")

                if len(parts) != 3:
                    raise ValueError(f"Malformed line in version file: {line}")

                ver, hash, file = parts
                versions.append({"ver": ver, "hash": hash, "file": file})

        for file in files:
            response = get(url + file)
            if response.status_code == 200:
                filehash = md5(response.text.encode("utf8")).hexdigest()
                version = next(
                    (ver["ver"] for ver in versions if filehash == ver["hash"] and file == ver["file"]), None
                )
                if version:
                    return version, f"Identified {version} based of hash of {file} being {filehash}"

        return None

    def extract_version_legacy_upgrade_file(self, url: str) -> Tuple[str, str] | None:
        # pattern: === x.y ===
        # there is possibility for === x.y.z+ === ; we will extract version without +
        pattern = re.compile(r"^===\s*(\d+(?:\.\d+)*)(?:\+)?\s*===$")

        legacy_files = ["/lib/upgrade.txt", "/question/upgrade.txt"]

        for file in legacy_files:
            response = get(url + file)
            if response.status_code != 200:
                continue

            text = response.text

            for line in text.splitlines():
                # ignores line "=== 4.5 Onwards ===", that can be included in legacy upgrade file
                if "Onwards" in line:
                    continue

                match = pattern.search(line)
                if match:
                    return match.group(1), f"Found {match.group(0)} in {file}"

        return None

    def extract_version_upgrade_file(self, url: str) -> Tuple[str, str] | None:
        # pattern: ## x.y (UPGRADING.md file)
        pattern = re.compile(r"(?m)^##\s*([0-9]+(?:\.[0-9]+){0,2})\s*$")

        new_file = "/UPGRADING.md"
        response = get(url + new_file)
        if response.status_code != 200:
            return None

        text = response.text
        pattern_match = pattern.search(text)
        return (pattern_match.group(1), f"Found {pattern_match.group(0)} in {new_file}") if pattern_match else None

    def get_moodle_specific_version(self, url: str) -> Tuple[str, str] | None:
        # moodle currently is using UPGRADING.md file that can help in determining version
        # it was moved from upgrade.txt file
        # if either file is found we fallback to use hashes built on official releases to determine the version
        if data := self.extract_version_upgrade_file(url):
            return data

        if data := self.extract_version_legacy_upgrade_file(url):
            return data

        if data := self.get_version_based_on_hash_file(url):
            return data

        return None

    def run(self, current_task: Task) -> None:
        base_url = get_target_url(current_task)

        status = None
        status_reason = ""
        if data := self.get_moodle_specific_version(base_url):
            version, reason = data

            if self.is_version_obsolete(version):
                status = TaskStatus.INTERESTING
                status_reason = f"Moodle version: {version} is obsolete (reason: {reason})."
                self.db.save_task_result(
                    task=current_task,
                    status=status,
                    status_reason=status_reason,
                    data={"version": version, "reason": reason},
                )
            else:
                status = TaskStatus.OK
                status_reason = f"Moodle version: {version} is up to date."
                self.db.save_task_result(task=current_task, status=status, status_reason=status_reason)
        else:
            status = TaskStatus.ERROR
            status_reason = "Cannot identify moodle version."
            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason)


if __name__ == "__main__":
    MoodleScanner().loop()
