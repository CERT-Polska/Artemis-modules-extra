from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import (
    NormalForm,
    get_url_normal_form,
    get_url_score,
)
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import get_top_level_target


class WPScanReporter(Reporter):  # type: ignore
    WPSCAN_VULNERABILITY = ReportType("wpscan_vulnerability")
    WPSCAN_INTERESTING_URL = ReportType("wpscan_interesting_url")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "wpscan":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        result = []
        for item in task_result["result"]["vulnerabilities"]:
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=task_result["target_string"],
                    report_type=WPScanReporter.WPSCAN_VULNERABILITY,
                    additional_data={"vulnerability": item},
                    timestamp=task_result["created_at"],
                )
            )
        for item in task_result["result"]["interesting_urls"]:
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=task_result["target_string"],
                    report_type=WPScanReporter.WPSCAN_INTERESTING_URL,
                    additional_data={"url": item},
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_wpscan_vulnerability.jinja2"), priority=7
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_wpscan_interesting_url.jinja2"), priority=3
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {report_type: WPScanReporter.scoring_rule for report_type in WPScanReporter.get_report_types()}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {report_type: WPScanReporter.normal_form_rule for report_type in WPScanReporter.get_report_types()}

    @staticmethod
    def scoring_rule(report: Report) -> List[int]:
        return [get_url_score(report.target)]

    @staticmethod
    def normal_form_rule(report: Report) -> NormalForm:
        return Reporter.dict_to_tuple(
            {
                "type": report.report_type,
                "target": get_url_normal_form(report.target),
                "additional_data": report.additional_data,
            }
        )
