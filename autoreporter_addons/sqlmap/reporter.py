import urllib
from pathlib import Path
from typing import Any, Callable, Dict, List

from artemis.domains import is_domain
from artemis.reporting.base.language import Language
from artemis.reporting.base.normal_form import NormalForm, get_domain_normal_form
from artemis.reporting.base.report import Report
from artemis.reporting.base.report_type import ReportType
from artemis.reporting.base.reporter import Reporter
from artemis.reporting.base.templating import ReportEmailTemplateFragment
from artemis.reporting.utils import add_port_to_url, get_top_level_target


class SQLmapReporter(Reporter):  # type: ignore
    SQL_INJECTION = ReportType("sql_injection")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "sqlmap":
            return []

        # Migrate from old format
        if isinstance(task_result["result"], dict):
            task_result["result"] = [task_result["result"]]

        if not isinstance(task_result["result"], list):
            return []

        result = []
        for found_injection in task_result["result"]:
            if not isinstance(found_injection, dict):
                continue

            if "log" not in found_injection:
                continue

            target = found_injection["target"].split(" ")[0]
            target = add_port_to_url(target)

            user = found_injection.get("extracted_user", None)
            if user and "@" in user:  # sometimes the returned user has the form user@host, let's strip host
                user = user.split("@")[0]

            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=target,
                    report_type=SQLmapReporter.SQL_INJECTION,
                    additional_data={
                        "version": found_injection.get("extracted_version", None),
                        "user": user,
                    },
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_sql_injection.jinja2"), priority=10
            ),
        ]

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""

        def rule(report: Report) -> NormalForm:
            hostname = urllib.parse.urlparse(report.target).hostname

            return Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(hostname) if is_domain(hostname) else hostname,
                }
            )

        return {SQLmapReporter.SQL_INJECTION: rule}
