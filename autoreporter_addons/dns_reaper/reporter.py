import os
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
from artemis.reporting.translations import translate_using_dictionary
from artemis.reporting.utils import get_top_level_target

from .translations import pl_PL as translations_pl_PL


class DNSReaperReporter(Reporter):  # type: ignore
    SUBDOMAIN_TAKEOVER_POSSIBLE = ReportType("subdomain_takeover_possible")

    @staticmethod
    def get_report_types() -> List[ReportType]:
        return [DNSReaperReporter.SUBDOMAIN_TAKEOVER_POSSIBLE]

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "dns_reaper":
            return []

        if not isinstance(task_result["result"], list):
            return []

        result = []
        for item in task_result["result"]:
            if item["confidence"] == "CONFIRMED":
                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=item["domain"],
                        report_type=DNSReaperReporter.SUBDOMAIN_TAKEOVER_POSSIBLE,
                        report_data={
                            "message_en": item["info"],
                            "message_translated": DNSReaperReporter._translate_info(
                                item["info"],
                                language,
                            ),
                        },
                        timestamp=task_result["created_at"],
                    )
                )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_subdomain_takeover_possible.jinja2"), 10
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {DNSReaperReporter.SUBDOMAIN_TAKEOVER_POSSIBLE: lambda report: [get_domain_score(report.target)]}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {
            DNSReaperReporter.SUBDOMAIN_TAKEOVER_POSSIBLE: lambda report: Reporter.dict_to_tuple(
                {
                    "type": report.report_type,
                    "target": get_domain_normal_form(report.target),
                    "message": report.report_data["message_en"],
                }
            )
        }

    @staticmethod
    def _translate_info(info: str, language: Language) -> str:
        if language == Language.en_US:
            return info
        elif language == Language.pl_PL:
            return translate_using_dictionary(info, translations_pl_PL.TRANSLATIONS)  # type: ignore
        else:
            raise NotImplementedError()
