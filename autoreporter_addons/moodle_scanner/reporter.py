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

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "moodle_scanner":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        if "result" not in task_result:
            return []

        result = []
        top_level_target = get_top_level_target(task_result)
        target = task_result["task"]["payload"]["url"]
        result.append(
            Report(
                top_level_target=top_level_target,
                target=target,
                report_type=MoodleScannerReporter.OBSOLETE_MOODLE_VERSION_FOUND,
                additional_data={
                    "version": task_result["result"]["version"],
                },
                timestamp=task_result["created_at"],
            )
        )

        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_obsolete_moodle_version.jinja2"),
                priority=4,
            ),
        ]
