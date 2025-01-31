from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import (
    NormalForm,
    get_domain_normal_form,
    get_domain_score,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class MoodleScannerReporter(Reporter):  # type: ignore
    MOODLE_VERSION_FOUND = ReportType("moodle_version_found")
    MOODLE_VULNERABILITY_FOUND = ReportType("moodle_vulnerability_found")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "moodle_scanner":
            return []

        result = []
        target = get_top_level_target(task_result)

        # Report version if found
        if task_result["result"].get("version") and task_result["result"]["version"] != "Version not found":
            result.append(
                Report(
                    top_level_target=target,
                    target=target,
                    report_type=MoodleScannerReporter.MOODLE_VERSION_FOUND,
                    additional_data={
                        "version": task_result["result"]["version"],
                        "server": task_result["result"].get("server", "Unknown"),
                    },
                    timestamp=task_result["created_at"],
                )
            )

        # Report vulnerabilities
        for vuln in task_result["result"].get("vulnerabilities", []):
            result.append(
                Report(
                    top_level_target=target,
                    target=target,
                    report_type=MoodleScannerReporter.MOODLE_VULNERABILITY_FOUND,
                    additional_data={
                        "vulnerability": vuln,
                        "version": task_result["result"].get("version", "Unknown"),
                    },
                    timestamp=task_result["created_at"],
                )
            )

        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_moodle_version.jinja2"),
                priority=10,
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_moodle_vulnerability.jinja2"),
                priority=20,
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {
            MoodleScannerReporter.MOODLE_VERSION_FOUND: lambda report: [get_domain_score(report.target)],
            MoodleScannerReporter.MOODLE_VULNERABILITY_FOUND: lambda report: [get_domain_score(report.target) * 2],
        }

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            MoodleScannerReporter.MOODLE_VERSION_FOUND: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(report.target),
                    "version": report.additional_data["version"],
                    "server": report.additional_data["server"],
                }
            ),
            MoodleScannerReporter.MOODLE_VULNERABILITY_FOUND: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(report.target),
                    "vulnerability": report.additional_data["vulnerability"],
                    "version": report.additional_data["version"],
                }
            ),
        }
