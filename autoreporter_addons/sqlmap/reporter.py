import os
from typing import Any, Callable, Dict, List

from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_url_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import add_port_to_url, get_top_level_target


class SQLmapReporter(Reporter):  # type: ignore
    SQL_INJECTION = ReportType("sql_injection")

    @staticmethod
    def get_report_types() -> List[ReportType]:
        return [
            SQLmapReporter.SQL_INJECTION,
        ]

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "sqlmap":
            return []

        if not isinstance(task_result["result"], dict):
            return []

        if "log" not in task_result["result"]:
            return []

        parameter = None

        for item in task_result["result"]["log"].split("\n"):
            if ":" in item:
                name, value = item.split(":", 1)
                if name == "Parameter":
                    parameter = value.strip()

        target = task_result["result"]["target"].split(" ")[0]
        target = add_port_to_url(target)

        user = task_result["result"].get("user", None)
        if user and "@" in user:  # sometimes the returned user has the form user@host, let's strip host
            user = user.split("@")[0]

        return [
            Report(
                top_level_target=get_top_level_target(task_result),
                target=target,
                report_type=SQLmapReporter.SQL_INJECTION,
                report_data={
                    "parameter": parameter,
                    "version": task_result["result"].get("version", None),
                    "user": user,
                },
                timestamp=task_result["created_at"],
            )
        ]

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_sql_injection.jinja2"), 10
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {report_type: Reporter.default_scoring_rule for report_type in SQLmapReporter.get_report_types()}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            SQLmapReporter.SQL_INJECTION: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_url_normal_form(report.target),
                    "description": report.report_data["parameter"],
                }
            )
        }
