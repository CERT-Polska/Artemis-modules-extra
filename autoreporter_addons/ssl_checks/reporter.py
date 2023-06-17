import os
import urllib.parse
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List

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
from artemis.reporting.utils import get_top_level_target
from bs4 import BeautifulSoup

from extra_modules_config import ExtraModulesConfig

from .http_requests import cached_get

logger = utils.build_logger(__name__)


with open(os.path.join(os.path.dirname(__file__), "filtered_website_fragments.txt"), "r") as f:
    FILTERED_WEBSITE_FRAGMENTS = [line.strip() for line in f.readlines() if line]

with open(os.path.join(os.path.dirname(__file__), "filtered_website_fragments_for_bad_redirect.txt"), "r") as f:
    # These fragments, if occur, mean that we shouldn't treat this website as containing a bad redirect.
    # For instance, if Cloudflare returned HTTP 200 with a message "Please wait while your request is being verified...",
    # that doesn't meant that the original website doesn't redirect to https:// - that means only, that our request
    # got intercepted via Cloudflare.
    FILTERED_WEBSITE_FRAGMENTS_FOR_BAD_REDIRECT = [line.strip() for line in f.readlines() if line]


class SSLChecksReporter(Reporter):  # type: ignore
    CERTIFICATE_AUTHORITY_INVALID = ReportType("certificate_authority_invalid")
    NO_HTTPS_REDIRECT = ReportType("no_https_redirect")
    BAD_CERTIFICATE_NAMES = ReportType("bad_certificate_names")
    ALMOST_EXPIRED_SSL_CERTIFICATE = ReportType("almost_expired_ssl_certificate")
    EXPIRED_SSL_CERTIFICATE = ReportType("expired_ssl_certificate")

    @staticmethod
    def create_reports(task_result: Dict[str, Any], language: Language) -> List[Report]:
        if task_result["headers"]["receiver"] != "ssl_checks":
            return []

        domain = task_result["payload"]["domain"]
        domain_parts = [part for part in domain.split(".") if part]
        # We do the filtering both in the scanning module and in the reporter so that after changing this setting
        # the user wouldn't need to wait for the next scan for the configuration to take effect.
        if domain_parts[0] in ExtraModulesConfig.SUBDOMAINS_TO_SKIP_SSL_CHECKS:
            return []

        if not isinstance(task_result["result"], dict):
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

        if "response_status_code" in task_result["result"] and "response_content_prefix" in task_result["result"]:
            response_status_code = task_result["result"]["response_status_code"]
            response_content_prefix = task_result["result"]["response_content_prefix"]

            if (
                response_status_code == 404
                or response_status_code == 403
                # This one is important - sometimes we reported false positives after getting a 5xx error (and thus no redirect)
                or (response_status_code >= 500 and response_status_code <= 599)
                or "<html" not in response_content_prefix.lower()
                or any([fragment in response_content_prefix for fragment in FILTERED_WEBSITE_FRAGMENTS])
            ):
                # Not something actually usable, won't be reported
                return []

            # We have systems in our constituency where a redirect is performed from http://domain to a different domain and https://domain is not used
            # and is misconfigured/the certificate expires. For now let's treat this as a false positive.
            if not task_result["result"].get("bad_redirect", False) and "redirect_url" in task_result["result"]:
                redirect_url_parsed = urllib.parse.urlparse(task_result["result"]["redirect_url"])
                if redirect_url_parsed.hostname != task_result["payload"]["domain"]:
                    return []

        result = []
        if task_result["result"].get("certificate_authority_invalid", False):
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{task_result["payload"]["domain"]}:443/',
                    report_type=SSLChecksReporter.CERTIFICATE_AUTHORITY_INVALID,
                    additional_data={},
                    timestamp=task_result["created_at"],
                )
            )
        if task_result["result"].get("bad_redirect", False):
            response_content_prefix = task_result["result"].get("response_content_prefix", "")
            if not any(
                [fragment in response_content_prefix for fragment in FILTERED_WEBSITE_FRAGMENTS_FOR_BAD_REDIRECT]
            ):
                # If there is some kind of HTML redirect, let's better not report that, as it might be
                # a proper SSL redirect - here, we want to decrease the number of false positives at the
                # cost of true positives.
                try:
                    soup = BeautifulSoup(response_content_prefix.lower(), "html.parser")
                except Exception:  # parsing errors
                    logger.exception("Unable to parse HTML from %s", task_result["payload"]["domain"])
                    soup = None

                if not soup or not soup.find_all("meta", attrs={"http-equiv": "refresh"}):
                    result.append(
                        Report(
                            top_level_target=get_top_level_target(task_result),
                            target=f'http://{task_result["payload"]["domain"]}:80/',
                            report_type=SSLChecksReporter.NO_HTTPS_REDIRECT,
                            additional_data={},
                            timestamp=task_result["created_at"],
                        )
                    )

        if task_result["result"].get("cn_different_from_hostname", False):
            # If the domain starts with www. but the version without www. is in the names list,
            # let's assume just the version without www. is advertised and used by the users.
            if not (
                task_result["payload"]["domain"].startswith("www.")
                and task_result["payload"]["domain"][4:] in task_result["result"]["names"]
            ):
                result.append(
                    Report(
                        top_level_target=get_top_level_target(task_result),
                        target=f'https://{task_result["payload"]["domain"]}:443/',
                        report_type=SSLChecksReporter.BAD_CERTIFICATE_NAMES,
                        additional_data={"names_string": ", ".join(sorted(set(task_result["result"]["names"])))},
                        timestamp=task_result["created_at"],
                    )
                )
        if task_result["result"].get("almost_expired", False):
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{task_result["payload"]["domain"]}:443/',
                    report_type=SSLChecksReporter.ALMOST_EXPIRED_SSL_CERTIFICATE,
                    additional_data={"expiry_date": task_result["result"]["expiry_date"]},
                    timestamp=task_result["created_at"],
                )
            )
        if task_result["result"].get("expired", False):
            result.append(
                Report(
                    top_level_target=get_top_level_target(task_result),
                    target=f'https://{task_result["payload"]["domain"]}:443/',
                    report_type=SSLChecksReporter.EXPIRED_SSL_CERTIFICATE,
                    additional_data={"expiry_date": task_result["result"]["expiry_date"]},
                    timestamp=task_result["created_at"],
                )
            )
        return result

    @staticmethod
    def get_email_template_fragments() -> List[ReportEmailTemplateFragment]:
        return [
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_expired_ssl_certificate.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_certificate_authority_invalid.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_bad_certificate_names.jinja2"), priority=2
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_no_https_redirect.jinja2"), priority=1
            ),
            ReportEmailTemplateFragment.from_file(
                os.path.join(os.path.dirname(__file__), "template_almost_expired_ssl_certificate.jinja2"), priority=1
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
