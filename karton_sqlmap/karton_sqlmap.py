#!/usr/bin/env python3
import copy
import dataclasses
import os
import random
import re
import shutil
import subprocess
import urllib
from typing import List, Optional, Tuple

import timeout_decorator
from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_url
from bs4 import BeautifulSoup
from karton.core import Task

from extra_modules_config import ExtraModulesConfig

OUTPUT_PATH = "/root/.local/share/sqlmap/output"
SQLI_ADDITIONAL_DATA_TIMEOUT = 600


@dataclasses.dataclass
class SQLmapCallResult:
    output: Optional[str]
    used_tamper_script: Optional[str]


@dataclasses.dataclass
class FoundSQLInjection:
    message: str
    target: str
    log: str
    extracted_version: Optional[str] = None
    extracted_user: Optional[str] = None
    used_tamper_script: Optional[str] = None


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class SQLmap(ArtemisBase):  # type: ignore
    """
    Runs sqlmap
    """

    identity = "sqlmap"
    filters = [
        # We run on all HTTP services, as even if it's a known CMS, it may contain custom plugins
        # and therefore it's worth scanning.
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _call_sqlmap(
        self, url: str, arguments: List[str], find_in_output: str, timeout_seconds: Optional[int] = None
    ) -> SQLmapCallResult:
        def _run() -> SQLmapCallResult:
            if Config.Miscellaneous.CUSTOM_USER_AGENT:
                additional_configuration = ["-A", Config.Miscellaneous.CUSTOM_USER_AGENT]
            else:
                additional_configuration = []

            for tamper_script in [None] + ExtraModulesConfig.SQLMAP_TAMPER_SCRIPTS:
                cmd = (
                    [
                        "sqlmap",
                        "--delay",
                        str(1.0 / self.requests_per_second_for_current_tasks)
                        if self.requests_per_second_for_current_tasks
                        else "0",
                        "-u",
                        url,
                        "--batch",
                        "-v",
                        "1",
                    ]
                    + arguments
                    + ExtraModulesConfig.SQLMAP_COMMAND_LINE_OPTIONS
                    + additional_configuration
                )

                if tamper_script:
                    cmd.append(f"--tamper={tamper_script}")

                data = subprocess.check_output(cmd)
                data_str = data.decode("ascii", errors="ignore")
                self.log.info("url %s, cmd %s, output %s", url, cmd, data_str)

                if "try a switch '--no-cast'" in data_str:
                    cmd += ["--no-cast"]
                    data = subprocess.check_output(cmd)
                    data_str = data.decode("ascii", errors="ignore")
                    self.log.info("url %s, cmd %s, output %s", url, cmd, data_str)

                for line in data_str.split("\n"):
                    match_result = re.compile(f"^{re.escape(find_in_output)}[^:]*: '(.*)'$").fullmatch(line)
                    if match_result:
                        return SQLmapCallResult(match_result.group(1), tamper_script)
            return SQLmapCallResult(None, None)

        if timeout_seconds:
            try:
                return timeout_decorator.timeout(timeout_seconds)(_run)()  # type: ignore
            except TimeoutError:
                return SQLmapCallResult(None, None)
        else:
            return _run()

    def _run_on_single_url(self, url: str) -> Optional[FoundSQLInjection]:
        number1 = random.randint(10, 99)
        number2 = random.randint(10, 99)
        number3 = random.randint(10, 99)

        try:
            shutil.rmtree(OUTPUT_PATH)
        except FileNotFoundError:
            pass

        # The logic here is as follows: we want SQLmap to blind the value of number1*number2*number3, therefore
        # making sure we have an actual SQL database behind, not a false positive. We make sure the value blinded
        # by SQLmap is equal to the actual product of these numbers.
        query = f"SELECT {number1}*{number2}*{number3}"

        result = self._call_sqlmap(url, ["--sql-query", query], query)
        if result.output == f"{number1 * number2 * number3}":
            for item in os.listdir(os.path.join(OUTPUT_PATH)):
                log_path = os.path.join(OUTPUT_PATH, item, "log")
                target_path = os.path.join(OUTPUT_PATH, item, "target.txt")

                if os.path.exists(log_path):
                    with open(target_path) as f:
                        # The format of the target is:
                        # url (METHOD)  # sqlmap_command
                        # e.g. http://127.0.0.1:8000/vuln.php?id=4 (GET)  # sqlmap.py --technique B -v 4 -u http://127.0.0.1:8000/
                        target, _ = f.read().split("#", 1)
                        target = target.strip()

                    with open(log_path) as f:
                        log = f.read().strip()

                    found_sql_injection = FoundSQLInjection(
                        message=f"Found SQL Injection in {target}",
                        target=target,
                        log=log,
                        used_tamper_script=result.used_tamper_script,
                    )

                    version_query = "SELECT SUBSTR(VERSION(), 1, 15)"
                    for information_name, sqlmap_options, find_in_output in [
                        ("extracted_version", ["--sql-query", version_query], version_query),
                        ("extracted_user", ["--current-user"], "current user"),
                    ]:
                        try:
                            setattr(
                                found_sql_injection,
                                information_name,
                                self._call_sqlmap(
                                    url, sqlmap_options, find_in_output, timeout_seconds=SQLI_ADDITIONAL_DATA_TIMEOUT
                                ).output,
                            )
                        except Exception:  # Whatever happens, we prefer to report SQLi without additional data than no SQLi
                            self.log.exception(f"Unable to obtain {information_name} via blind SQL injection")
                    return found_sql_injection
        return None

    @staticmethod
    def _expand_query_parameters_for_scanning(url: str) -> List[Tuple[str, str]]:
        """
        This converts a URL to a list of pairs:
            - URL with query string injection point,
            - original injection point value.

        For example, 'https://example.com/?id=1&q=2' would be converted to a list of:

        [
            ('https://example.com/?id=1&q=*', '2'),
            ('https://example.com/?id=*&q=2', '1'),
        ]
        """
        url_parsed = urllib.parse.urlparse(url)
        # let's keep only the first value of a parameter
        query = {
            key: value[0] for key, value in urllib.parse.parse_qs(url_parsed.query, keep_blank_values=True).items()
        }

        results = []
        for key in query:
            new_query = copy.copy(query)
            token = "__sqlmap_injection_point__"
            original_value = new_query[key]
            new_query[key] = token

            # We replace token with * after building the URL, so that the asterisk is passed to sqlmap unescaped
            new_query_encoded = urllib.parse.urlencode(new_query)
            new_url_parsed = url_parsed._replace(query=new_query_encoded)
            new_url = urllib.parse.urlunparse(new_url_parsed)
            new_url_with_injection_point = new_url.replace(token, "*")
            results.append((new_url_with_injection_point, original_value))
        return results

    @staticmethod
    def _expand_path_segments_for_scanning(url: str) -> List[Tuple[str, str]]:
        """
        This converts a URL to a list of pairs:
            - URL with path injection point,
            - original injection point value.

        For example, 'https://example.com/path/file' would be converted to a list of:

        [
            ('https://example.com/path/*', 'file'),
            ('https://example.com/*/file', 'path'),
        ]
        """
        url_parsed = urllib.parse.urlparse(url)
        num_commas = len([c for c in url_parsed.path[1:] if c == ","])
        num_slashes = len([c for c in url_parsed.path[1:] if c == "/"])

        if num_commas > num_slashes:
            separator = ","
        else:
            separator = "/"

        extension_re = r"\.[A-Za-z]{2,}$"
        if m := re.search(extension_re, url_parsed.path):
            extension = m.group(0)
            path_segments = url_parsed.path[1 : -len(extension)].split(separator)
        else:
            extension = ""
            path_segments = url_parsed.path[1:].split(separator)

        # Heuristic: if the path ends with .php, it's most probably not a clean URL but a file name.
        if extension == ".php":
            return []

        results = []
        for i, path_segment in enumerate(path_segments):
            new_path_segments = copy.copy(path_segments)
            original_value = new_path_segments[i]
            new_path_segments[i] = "*"
            results.append(
                (
                    urllib.parse.urlunparse(
                        url_parsed._replace(path="/" + separator.join(new_path_segments) + extension)
                    ),
                    original_value,
                )
            )

        return results

    @staticmethod
    def _expand_urls_for_scanning(url: str) -> List[Tuple[str, str]]:
        """
        This converts a URL to a list of pairs:
            - URL with injection point,
            - original injection point value.

        For example, 'https://example.com/path/file.html?id=1&q=2' would be converted to a list of:

        [
            ('https://example.com/path/file.html?id=1&q=*', '2'),
            ('https://example.com/path/file.html?id=*&q=2', '1'),
            ('https://example.com/path/*.html?id=1&q=2', 'file'),
            ('https://example.com/*/file.html?id=1&q=2', 'path'),
        ]
        """
        return sorted(
            set(SQLmap._expand_query_parameters_for_scanning(url) + SQLmap._expand_path_segments_for_scanning(url))
        )

    def run(self, current_task: Task) -> None:
        if not self.check_connection_to_base_url_and_save_error(current_task):
            return

        url = get_target_url(current_task)
        self.log.info("Requested to crawl and test SQL injection on %s", url)
        url_parsed = urllib.parse.urlparse(url)

        results = []

        # Let's just try injecting example.com/[injection point]
        root_injection_result = self._run_on_single_url(url + "*" if url.endswith("/") else url + "/*")
        if root_injection_result:
            results.append(root_injection_result)

        response = http_requests.get(url)

        # Unfortunately, crawling of clean URLs is not a feature that would get merged to sqlmap
        # (https://github.com/sqlmapproject/sqlmap/issues/5561) so it is done here.
        soup = BeautifulSoup(response.text)
        urls_with_injection_points = set()
        expanded_urls_with_example_values_dict = {}
        for tag in soup.find_all():
            new_url = None
            for attribute in ["src", "href"]:
                if attribute not in tag.attrs:
                    continue

                new_url = urllib.parse.urljoin(url, tag[attribute])

                new_url = new_url.split("#")[0]

                if any(new_url.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS):
                    # Let's not inject image/style paths
                    continue

                new_url_parsed = urllib.parse.urlparse(new_url)

                if url_parsed.netloc == new_url_parsed.netloc:
                    expanded_url = SQLmap._expand_urls_for_scanning(new_url)
                    self.log.info("Found link %s, expanding to %s", new_url, expanded_url)

                    for url_with_injection_point, example_value in expanded_url:
                        if url_with_injection_point in urls_with_injection_points:
                            continue

                        urls_with_injection_points.add(url_with_injection_point)
                        expanded_urls_with_example_values_dict[url_with_injection_point] = example_value

        expanded_urls_with_example_values = list(expanded_urls_with_example_values_dict.items())
        random.shuffle(expanded_urls_with_example_values)
        expanded_urls_with_example_values = expanded_urls_with_example_values[
            : ExtraModulesConfig.SQLMAP_MAX_URLS_TO_CRAWL
        ]

        for url_with_injection_point, example_value in expanded_urls_with_example_values:
            self.log.info("Checking %s, example value=%s", url_with_injection_point, example_value)

            result = self._run_on_single_url(url_with_injection_point.replace("*", example_value + "*"))

            if result:
                # We try to inject https://example.com/?id=4* (where '4' is taken from crawling)
                # but we report https://example.com/?id=* to avoid duplicates (e.g. when
                # https://example.com/?id=4*, https://example.com/?id=5*, and https://example.com/?id=*
                # are reported).
                result.target = url_with_injection_point

                results.append(result)

        results_as_dict = [dataclasses.asdict(result) for result in results]

        if results:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join([result.message for result in results])
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=results_as_dict)


if __name__ == "__main__":
    SQLmap().loop()
