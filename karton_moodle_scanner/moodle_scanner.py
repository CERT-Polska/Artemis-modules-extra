#!/usr/bin/env python3
import dataclasses
import re
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import requests
from bs4 import BeautifulSoup

from artemis import load_risk_class
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.module_base import ArtemisBase
from artemis.modules.base.base_newer_version_comparer import (
    BaseNewerVersionComparerModule,
)
from artemis.task_utils import get_target_url
from karton.core import Task

@dataclasses.dataclass
class MoodleMessage:
    category: str
    problems: List[str]

    @property
    def message(self) -> str:
        return f"{self.category}: {', '.join(self.problems)}"

class MoodleVersionException(Exception):
    pass

def process_moodle_json(result: Dict[str, Any]) -> List[MoodleMessage]:
    messages: Dict[str, MoodleMessage] = {}

    for key, value in result.items():
        key_parts = key.replace("[", "").replace("]", "").split(". ")

        if key in [
            "[2. Moodle Security Checks]",
            "[3. Deprecated Moodle Versions]",
        ]:
            continue

        if len(key_parts) >= 2:
            category = key_parts[1].capitalize()

            if category.lower() != "info":
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if subvalue and subvalue not in [
                            "Nothing to report, all seems OK!",
                        ]:
                            problem = f"{subkey} {subvalue}"
                            if category not in messages:
                                messages[category] = MoodleMessage(category=category, problems=[])
                            messages[category].problems.append(problem)
                elif isinstance(value, list):
                    for item in value:
                        if item and item not in [
                            "Nothing to report, all seems OK!",
                        ]:
                            if category not in messages:
                                messages[category] = MoodleMessage(category=category, problems=[])
                            messages[category].problems.append(str(item))

    return list(messages.values())

@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class MoodleScanner(BaseNewerVersionComparerModule):  # type: ignore
    """
    Runs Moodle-Scanner -> A Moodle Vulnerability Analyzer and checks for obsolete versions
    """

    identity: str = "moodle_scanner"
    filters: List[Dict[str, str]] = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
    ]
    software_name = "moodle_scanner"
    MOODLE_RELEASES_URL = "https://moodledev.io/general/releases"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._supported_versions = {}
        self._latest_lts = None
        self._latest_stable = None
        self._fetch_version_info()

    def _fetch_version_info(self) -> None:
        """Fetch and parse Moodle version information from the releases page."""
        try:
            response = requests.get(self.MOODLE_RELEASES_URL)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find the version support table
            version_table = None
            for table in soup.find_all('table'):
                if table.find('th', text=lambda t: t and 'Version' in t):
                    version_table = table
                    break

            if not version_table:
                self.log.error("Could not find version support table")
                return

            # Parse version information
            current_date = datetime.now()
            for row in version_table.find_all('tr')[1:]:  # Skip header row
                cols = row.find_all('td')
                if not cols:
                    continue

                version = cols[0].text.strip().split()[0]  # Remove "(LTS)" if present
                if "(LTS)" in cols[0].text:
                    version_type = "LTS"
                    if not self._latest_lts or float(version) > float(self._latest_lts):
                        self._latest_lts = version
                else:
                    version_type = "stable"
                    if not self._latest_stable or float(version) > float(self._latest_stable):
                        self._latest_stable = version

                try:
                    end_general = datetime.strptime(cols[2].text.strip(), "%d %B %Y").strftime("%Y-%m-%d")
                    end_security = datetime.strptime(cols[3].text.strip(), "%d %B %Y").strftime("%Y-%m-%d")
                    
                    # Only include versions that haven't reached end of security support
                    if datetime.strptime(end_security, "%Y-%m-%d") > current_date:
                        self._supported_versions[version] = {
                            "end_general": end_general,
                            "end_security": end_security,
                            "type": version_type
                        }
                except (ValueError, IndexError) as e:
                    self.log.warning(f"Error parsing dates for version {version}: {str(e)}")
                    continue

        except Exception as e:
            self.log.error(f"Error fetching Moodle version information: {str(e)}")

    def _parse_version(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """Parse version string into tuple of integers."""
        if not version_str:
            return None
        
        # Extract version numbers using regex
        match = re.search(r'(\d+(?:\.\d+)*)', version_str)
        if not match:
            return None
            
        try:
            return tuple(int(x) for x in match.group(1).split('.'))
        except (ValueError, AttributeError):
            return None

    def _get_major_minor(self, version_tuple: Tuple[int, ...]) -> str:
        """Get major.minor version string from version tuple."""
        if len(version_tuple) < 2:
            raise MoodleVersionException("Invalid version format")
        return f"{version_tuple[0]}.{version_tuple[1]}"

    def is_version_obsolete(self, version: str) -> bool:
        """Check if the given version is obsolete based on current supported versions."""
        if not self._supported_versions:
            self._fetch_version_info()
            
        version_tuple = self._parse_version(version)
        if not version_tuple:
            raise MoodleVersionException(f"Unable to parse version: {version}")

        major_minor = self._get_major_minor(version_tuple)
        
        # Check if version is in supported versions
        if major_minor not in self._supported_versions:
            return True

        return False

    def process_output(self, output: str) -> Dict[str, Any]:
        """Process moodlescan output and extract relevant information."""
        output_lines = output.splitlines()
        server_info: Optional[str] = None
        version_info: Optional[str] = None
        vulnerabilities: List[str] = []
        error_message: Optional[str] = None
        status: TaskStatus
        status_reason: Optional[str]
        is_version_obsolete: Optional[bool] = None

        for i, line in enumerate(output_lines):
            if "Error: Can't connect" in line:
                error_message = line
                break

            if "server" in line.lower() and ":" in line:
                server_info = line.split(":", 1)[1].strip()
            elif "version" in line.lower() and not line.startswith("."):
                # Look at next line for version info if it's not dots or error
                if i + 1 < len(output_lines):
                    next_line = output_lines[i + 1].strip()
                    if next_line and not next_line.startswith(".") and "error" not in next_line.lower():
                        version_info = next_line
            elif "vulnerability" in line.lower() or "cve" in line.lower():
                vulnerabilities.append(line.strip())

        # Check if version is obsolete
        if version_info:
            try:
                is_version_obsolete = self.is_version_obsolete(version_info)
            except MoodleVersionException as e:
                self.log.warning(f"Version check failed: {str(e)}")
                is_version_obsolete = None

        # Determine status and reason based on findings
        found_problems = []
        
        if error_message:
            status = TaskStatus.OK
            status_reason = error_message
        else:
            if vulnerabilities:
                found_problems.extend(vulnerabilities)
            
            if is_version_obsolete:
                found_problems.append(f"Moodle version {version_info} is obsolete")
            
            if found_problems:
                status = TaskStatus.INTERESTING
                status_reason = f"Found: {', '.join(found_problems)}"
            elif version_info:
                status = TaskStatus.OK
                status_reason = f"Found version: {version_info} (up to date)"
            else:
                status = TaskStatus.OK
                status_reason = "Version not found"

        return {
            "server": server_info,
            "version": version_info,
            "vulnerabilities": vulnerabilities,
            "is_version_obsolete": is_version_obsolete,
            "error": error_message,
            "raw_output": output,
            "status": status,
            "status_reason": status_reason,
        }

    def run(self, current_task: Task) -> None:
        base_url = get_target_url(current_task)
        self.log.info(f"Starting moodlescan for {base_url}")

        try:
            # Run moodlescan with error output captured
            process = subprocess.run(
                ["python3", "moodlescan.py", "-u", base_url, "-r", "-k"],
                cwd="/moodle_scanner",
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to run moodlescan for {base_url}")
            self.log.error(f"Exit code: {e.returncode}")
            self.log.error(f"Stdout: {e.stdout}")
            self.log.error(f"Stderr: {e.stderr}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Failed to execute moodlescan: {e.stderr}",
                data={"stdout": e.stdout, "stderr": e.stderr},
            )
            return

        self.log.info(f"Moodlescan stdout: {process.stdout}")
        if process.stderr:
            self.log.warning(f"Moodlescan stderr: {process.stderr}")

        result = self.process_output(process.stdout)

        if result["error"]:
            self.log.info(f"Connection error: {result['error']}")
            self.db.save_task_result(
                task=current_task,
                status=result["status"],
                status_reason=result["status_reason"],
                data={"raw_output": result["raw_output"]},
            )
            return

        self.db.save_task_result(
            task=current_task, status=result["status"], status_reason=result["status_reason"], data=result
        )


if __name__ == "__main__":
    MoodleScanner().loop()
