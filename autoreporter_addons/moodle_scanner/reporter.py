from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class MoodleScannerReporter(Reporter):  # type: ignore
    OBSOLETE_MOODLE_VERSION_FOUND = ReportType("obsolete_moodle_version_found")
    MOODLE_VULNERABILITY_FOUND = ReportType("moodle_vulnerability_found")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "moodle_scanner":
            return []

        result = []
        target = get_top_level_target(task_result)

        if (
            task_result["result"].get("version")
            and task_result["result"].get("version_is_obsolete")
            and task_result["result"]["version"] != "Version not found"
        ):
            result.append(
                Report(
                    top_level_target=target,
                    target=target,
                    report_type=MoodleScannerReporter.OBSOLETE_MOODLE_VERSION_FOUND,
                    additional_data={
                        "version": task_result["result"]["version"],
                    },
                    timestamp=task_result["created_at"],
                )
            )

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
                str(Path(__file__).parents[0] / "template_moodle_vulnerability.jinja2"),
                priority=7,
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_moodle_version.jinja2"),
                priority=4,
            ),
        ]
