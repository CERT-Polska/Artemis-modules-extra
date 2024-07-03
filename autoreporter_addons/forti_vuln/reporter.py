from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class FortiVulnReporter(Reporter):  # type: ignore
    VULNERABLE_FORTIOS = ReportType("forti_vuln")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:

        if task_result["headers"]["receiver"] != "forti_vuln":
            return []

        if not task_result["status"] == "INTERESTING":
            return []

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=f"https://{task_result['target_string']}",
                report_type=FortiVulnReporter.VULNERABLE_FORTIOS,
                timestamp=task_result["created_at"],
                additional_data={"vuln": task_result["result"]},
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_vulnerable_fortios.jinja2"), priority=10
            ),
        ]
