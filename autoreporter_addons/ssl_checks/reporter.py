from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib.parse import urlparse

from artemis import utils
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
from artemis.reporting.utils import cached_get, get_top_level_target
from bs4 import BeautifulSoup

from extra_modules_config import ExtraModulesConfig

logger = utils.build_logger(__name__)


with open(str(Path(__file__).parents[0] / "filtered_website_fragments.txt"), "r") as f:
    FILTERED_WEBSITE_FRAGMENTS = [line.strip() for line in f.readlines() if line]

with open(str(Path(__file__).parents[0] / "filtered_website_fragments_waf_or_ratelimits.txt"), "r") as f:
    # These fragments, if occur, mean that we shouldn't report SSL problems for this site.
    # For instance, if Cloudflare returned HTTP 200 with a message "Please wait while your request is being verified...",
    # that tells us that we don't know what was the original site content - maybe something unimportant
    # that would get filtered by FILTERED_WEBSITE_FRAGMENTS?
    #
    # Therefore, to keep the number of false positives low, we don't report such sites.
    # **In case the decision changes, let's keep the list of WAF- or ratelimit-related matchers in a separate
    # file.**
    FILTERED_WEBSITE_FRAGMENTS_WAF_OR_RATELIMITS = [line.strip() for line in f.readlines() if line]


class SSLChecksReporter(Reporter):  # type: ignore
    CERTIFICATE_AUTHORITY_INVALID = ReportType("certificate_authority_invalid")
    NO_HTTPS_REDIRECT = ReportType("no_https_redirect")
    BAD_CERTIFICATE_NAMES = ReportType("bad_certificate_names")
    EXPIRED_SSL_CERTIFICATE = ReportType("expired_ssl_certificate")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ssl_checks":
            return []

        result = task_result["result"]
        payload = task_result["payload"]

        domain = payload["domain"]
        domain_parts = [part for part in domain.split(".") if part]
        # We do the filtering both in the scanning module and in the reporter so that after changing this setting
        # the user wouldn't need to wait for the next scan for the configuration to take effect.
        if domain_parts[0] in ExtraModulesConfig.SUBDOMAINS_TO_SKIP_SSL_CHECKS:
            return []

        if not isinstance(result, dict):
            return []

        try:
            response = cached_get(f"https://{domain}")
            parent_response = cached_get(f"https://{'.'.join(domain_parts[1:])}")
            if SequenceMatcher(None, response.content, parent_response.content).quick_ratio() >= 0.8:
                # Do not report misconfigurations if a domain has identical content to a parent domain - e.g.
                # if we have mail.domain.com with identical content to domain.com, we assume that it's domain.com
                # which is actually used, and therefore don't report subdomains.
                return []
        except Exception:
            logger.warning(f"Unable to check whether domain {domain} has identical content to parent domain")

        if "response_status_code" in result and "response_content_prefix" in result:
            response_status_code = result["response_status_code"]
            response_content_prefix = result["response_content_prefix"]

            filter_by_status_code = (
                # We don't filter out all 4xx codes - for example, we want to show a message for
                # e.g. 401 (unauthorized, where a login panel appears) or 405 (method not allowed).
                response_status_code == 404
                or response_status_code == 403
                or response_status_code == 400
                # This one is important - sometimes we reported false positives after getting a 5xx error (and thus no redirect)
                or (response_status_code >= 500 and response_status_code <= 599)
            )
            filter_by_content = (
                "<html" not in response_content_prefix.lower()
                or any(
                    [
                        fragment in response_content_prefix
                        for fragment in FILTERED_WEBSITE_FRAGMENTS + FILTERED_WEBSITE_FRAGMENTS_WAF_OR_RATELIMITS
                    ]
                )
                or response_content_prefix.strip() == ""
            )
            if filter_by_status_code or filter_by_content:
                # Not something actually usable, won't be reported
                return []

            # We have systems in our constituency where a redirect is performed from http://domain to a different domain and https://domain is not used
            # and is misconfigured/the certificate expires. For now let's treat this as a false positive.
            if not result.get("bad_redirect", False) and "redirect_url" in result:
                redirect_url_parsed = urlparse(result["redirect_url"])
                if redirect_url_parsed.hostname != payload["domain"]:
                    return []

        reports = []
        if result.get("certificate_authority_invalid", False):
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{payload["domain"]}:443/',
                    report_type=SSLChecksReporter.CERTIFICATE_AUTHORITY_INVALID,
                    additional_data={},
                    timestamp=task_result["created_at"],
                )
            )
        if result.get("bad_redirect", False):
            response_content_prefix = result.get("response_content_prefix", "")
            # If there is some kind of HTML redirect, let's better not report that, as it might be
            # a proper SSL redirect - here, we want to decrease the number of false positives at the
            # cost of true positives.
            try:
                soup = BeautifulSoup(response_content_prefix.lower(), "html.parser")
            except Exception:  # parsing errors
                logger.exception("Unable to parse HTML from %s", payload["domain"])
                soup = None

            if not soup or not soup.find_all("meta", attrs={"http-equiv": "refresh"}):
                reports.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=f'http://{payload["domain"]}:80/',
                        report_type=SSLChecksReporter.NO_HTTPS_REDIRECT,
                        additional_data={},
                        timestamp=task_result["created_at"],
                    )
                )

        if result.get("cn_different_from_hostname", False):
            # If the domain starts with www. but the version without www. is in the names list,
            # let's assume just the version without www. is advertised and used by the users.
            if not (payload["domain"].startswith("www.") and payload["domain"][4:] in result["names"]):
                names_string = ", ".join(sorted(set(result["names"])))

                reports.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=f'https://{payload["domain"]}:443/',
                        report_type=SSLChecksReporter.BAD_CERTIFICATE_NAMES,
                        additional_data={"names_string": names_string},
                        timestamp=task_result["created_at"],
                    )
                )
        if result.get("expired", False):
            reports.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{payload["domain"]}:443/',
                    report_type=SSLChecksReporter.EXPIRED_SSL_CERTIFICATE,
                    additional_data={"expiry_date": result["expiry_date"]},
                    timestamp=task_result["created_at"],
                )
            )
        return reports

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_expired_ssl_certificate.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_certificate_authority_invalid.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_bad_certificate_names.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                str(Path(__file__).parents[0] / "template_no_https_redirect.jinja2"), priority=1
            ),
        ]

    @staticmethod
    def get_scoring_rules() -> Dict[ReportType, Callable[[Report], List[int]]]:
        """See the docstring in the parent class."""
        return {report_type: SSLChecksReporter.scoring_rule for report_type in SSLChecksReporter.get_report_types()}

    @staticmethod
    def get_normal_form_rules() -> Dict[ReportType, Callable[[Report], NormalForm]]:
        """See the docstring in the Reporter class."""
        return {report_type: SSLChecksReporter.normal_form_rule for report_type in SSLChecksReporter.get_report_types()}

    @staticmethod
    def scoring_rule(report: Report) -> List[int]:
        return [get_url_score(report.target)]

    @staticmethod
    def normal_form_rule(report: Report) -> NormalForm:
        return Reporter.dict_to_tuple({"type": report.report_type, "target": get_url_normal_form(report.target)})
