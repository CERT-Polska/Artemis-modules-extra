import os
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class XSSReporter(Reporter):  # type: ignore
    xss_vulnerability = ReportType("xss_vulnerability")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:

        if all(
            [
                task_result.get("headers", {}).get("receiver") == "xss_scanner",
                task_result.get("status") == "INTERESTING",
            ]
        ):

            return [
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f"https://{task_result['target_string']}",
                    report_type=XSSReporter.xss_vulnerability,
                    timestamp=task_result["created_at"],
                    additional_data={"vuln": task_result["result"]},
                )
            ]

        return []

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_xss_vulnerability.jinja2"), priority=7
            ),
        ]
