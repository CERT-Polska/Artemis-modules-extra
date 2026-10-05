from pathlib import Path
from typing import Any, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class TestSSLReporter(Reporter):  # type: ignore
    POODLE = ReportType("poodle")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "testssl":
            return []

        result = task_result["result"]
        payload = task_result["payload"]

        if not isinstance(result, dict):
            return []

        reports = []

        if result.get("poodle", False):
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{payload["domain"]}:443/',
                    report_type=TestSSLReporter.POODLE,
                    additional_data={},
                    timestamp=task_result["created_at"],
                )
            )

        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_poodle.jinja2"), priority=2
            ),
        ]
