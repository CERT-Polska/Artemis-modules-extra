#!/usr/bin/env python3
import io
import subprocess
import urllib.parse
import zipfile
from collections import deque
from typing import Any, Callable, Dict, List, Set, Tuple

import requests
import xray  # type: ignore
from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import check_output_log_on_error
from bs4 import BeautifulSoup
from karton.core import Task

from extra_modules_config import ExtraModulesConfig

# Document extensions to scan. This list will grow as more check types
# are added (e.g. .docx, .xlsx, .pptx for metadata leaks).
DOCUMENT_EXTENSIONS = [".pdf"]

# Archive extensions to download and unpack. The documents inside are scanned
# with the same checks as standalone documents.
ARCHIVE_EXTENSIONS = [".zip"]

# Type for a check function: takes file bytes, returns list of findings.
CheckFunction = Callable[[bytes], List[Dict[str, Any]]]


def _check_bad_redaction(file_bytes: bytes) -> List[Dict[str, Any]]:
    """Check a PDF for improperly redacted/censored content using x-ray."""
    findings = xray.inspect(file_bytes)
    leaked_items: List[Dict[str, Any]] = []
    if findings:
        for page_num, items in findings.items():
            for item in items:
                leaked_items.append(
                    {
                        "page": page_num,
                        "bbox": list(item["bbox"]),
                        "text": item["text"],
                    }
                )
    return leaked_items


# Registry of checks to run against downloaded documents.
# Each entry is (check_name, applicable_extensions, check_function).
# To add a new check, append to this list.
DOCUMENT_CHECKS: List[Tuple[str, List[str], CheckFunction]] = [
    ("bad_redaction", [".pdf"], _check_bad_redaction),
]


def _is_document_url(url: str) -> bool:
    """Check if a URL points to a document (or an archive of documents) we want to scan."""
    path_lower = urllib.parse.urlparse(url).path.lower()
    return any(path_lower.endswith(ext) for ext in DOCUMENT_EXTENSIONS + ARCHIVE_EXTENSIONS)


def _is_archive_path(path: str) -> bool:
    path_lower = path.lower()
    return any(path_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class LeakScanner(ArtemisBase):  # type: ignore[misc]
    """
    Scans websites for documents with data leaks such as bad censorship/redaction
    attempts (e.g. black rectangles that can be removed to reveal hidden text).
    Crawls the website up to a configurable depth to discover document URLs.
    """

    identity = "leak_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _discover_documents_via_crawl(self, base_url: str, max_documents: int) -> List[str]:
        """BFS crawl the website to discover document URLs.

        Follows same-domain links up to LEAK_SCANNER_CRAWL_DEPTH levels,
        visiting at most LEAK_SCANNER_MAX_PAGES_TO_CRAWL pages.
        """
        max_depth = ExtraModulesConfig.LEAK_SCANNER_CRAWL_DEPTH
        max_pages = ExtraModulesConfig.LEAK_SCANNER_MAX_PAGES_TO_CRAWL

        base_hostname = urllib.parse.urlparse(base_url).hostname

        if _is_document_url(base_url):
            return []

        visited: Set[str] = set()
        document_urls: List[str] = []
        queue: deque[Tuple[str, int]] = deque([(base_url, 0)])
        visited.add(base_url)
        pages_crawled = 0

        while queue and pages_crawled < max_pages and len(document_urls) < max_documents:
            current_url, depth = queue.popleft()
            pages_crawled += 1

            try:
                response = http_requests.get(current_url)
            except requests.exceptions.RequestException:
                continue

            if response.status_code != 200:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all():
                for attribute in ["src", "href"]:
                    if attribute not in tag.attrs:
                        continue

                    new_url = urllib.parse.urljoin(current_url, tag[attribute])
                    new_url = new_url.split("#")[0]
                    new_url_parsed = urllib.parse.urlparse(new_url)

                    if new_url_parsed.hostname != base_hostname or new_url in visited:
                        continue
                    visited.add(new_url)

                    if _is_document_url(new_url):
                        document_urls.append(new_url)
                        if len(document_urls) >= max_documents:
                            return document_urls
                    elif depth + 1 <= max_depth:
                        queue.append((new_url, depth + 1))

        return document_urls

    def _discover_documents_via_gau(self, domain: str) -> Set[str]:
        """Query gau for archived document URLs from Wayback Machine and Common Crawl."""
        try:
            result = check_output_log_on_error(["gau"], self.log, input=domain.encode("idna"))
            urls: Set[str] = set()
            for line in result.decode().splitlines():
                line = line.strip()
                if line and _is_document_url(line):
                    urls.add(line)
            return urls
        except (OSError, subprocess.SubprocessError):
            self.log.exception(f"Unable to obtain document URLs from gau for {domain}")
            return set()

    def _discover_document_urls(self, base_url: str) -> List[str]:
        """Discover document URLs using both BFS crawling and gau."""
        max_documents = ExtraModulesConfig.LEAK_SCANNER_MAX_DOCUMENTS_TO_CHECK
        base_hostname = urllib.parse.urlparse(base_url).hostname

        crawl_urls = self._discover_documents_via_crawl(base_url, max_documents)
        seen: Set[str] = set(crawl_urls)
        document_urls = list(crawl_urls)

        if base_hostname:
            gau_urls = self._discover_documents_via_gau(base_hostname)
            for url in gau_urls:
                if url not in seen and len(document_urls) < max_documents:
                    parsed = urllib.parse.urlparse(url)
                    if parsed.hostname == base_hostname:
                        document_urls.append(url)
                        seen.add(url)

        return document_urls

    def _run_checks(self, file_bytes: bytes, path: str, description: str) -> Dict[str, List[Dict[str, Any]]]:
        """Run all checks applicable to the extension of `path` against `file_bytes`."""
        path_lower = path.lower()
        all_findings: Dict[str, List[Dict[str, Any]]] = {}
        for check_name, applicable_extensions, check_fn in DOCUMENT_CHECKS:
            if not any(path_lower.endswith(ext) for ext in applicable_extensions):
                continue
            try:
                findings = check_fn(file_bytes)
            except Exception as e:
                self.log.warning(f"Check '{check_name}' failed on {description}: {e}")
                continue
            if findings:
                all_findings[check_name] = findings
        return all_findings

    def _scan_archive(self, archive_bytes: bytes, archive_url: str) -> Dict[str, List[Dict[str, Any]]]:
        """Unpack a ZIP archive in memory and run the document checks on the documents inside.

        Each finding gets a "file" key with the path of the document inside the archive.
        Nested archives, encrypted members and members larger than
        LEAK_SCANNER_MAX_DOCUMENT_SIZE_BYTES are skipped, and at most
        LEAK_SCANNER_MAX_ARCHIVE_MEMBERS_TO_CHECK documents are checked per archive.
        """
        max_size = ExtraModulesConfig.LEAK_SCANNER_MAX_DOCUMENT_SIZE_BYTES
        max_members = ExtraModulesConfig.LEAK_SCANNER_MAX_ARCHIVE_MEMBERS_TO_CHECK

        try:
            archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as e:
            self.log.info(f"Skipping {archive_url}: not a readable ZIP archive ({e})")
            return {}

        all_findings: Dict[str, List[Dict[str, Any]]] = {}
        members_checked = 0
        with archive:
            for member in archive.infolist():
                if member.is_dir() or not any(member.filename.lower().endswith(ext) for ext in DOCUMENT_EXTENSIONS):
                    continue
                if members_checked >= max_members:
                    self.log.info(f"Checked {max_members} documents in {archive_url}, skipping the rest")
                    break
                if member.flag_bits & 0x1:
                    self.log.info(f"Skipping encrypted {member.filename} in {archive_url}")
                    continue
                if member.file_size > max_size:
                    self.log.info(f"Skipping {member.filename} in {archive_url}: {member.file_size} bytes")
                    continue

                description = f"{member.filename} in {archive_url}"
                try:
                    with archive.open(member) as f:
                        # Don't trust the size in the header: read at most one byte more than allowed.
                        file_bytes = f.read(max_size + 1)
                except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError, OSError) as e:
                    self.log.info(f"Unable to unpack {description}: {e}")
                    continue
                if len(file_bytes) > max_size:
                    self.log.info(f"Skipping {description}: larger than {max_size} bytes")
                    continue

                members_checked += 1
                for check_name, findings in self._run_checks(file_bytes, member.filename, description).items():
                    all_findings.setdefault(check_name, []).extend(
                        {**finding, "file": member.filename} for finding in findings
                    )
        return all_findings

    def _scan_document(self, document_url: str) -> Dict[str, Any]:
        """Download a document (or an archive of documents) and run all applicable checks against it."""
        response = self.http_get(
            document_url,
            max_size=ExtraModulesConfig.LEAK_SCANNER_MAX_DOCUMENT_SIZE_BYTES,
        )

        if response.status_code != 200:
            self.log.info(f"Skipping {document_url}: HTTP {response.status_code}")
            return {}

        file_bytes = response.content_bytes
        path = urllib.parse.urlparse(document_url).path

        if _is_archive_path(path):
            all_findings = self._scan_archive(file_bytes, document_url)
        else:
            all_findings = self._run_checks(file_bytes, path, document_url)

        if all_findings:
            return {"url": document_url, "findings": all_findings}
        return {}

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"LeakScanner scanning {url}")

        document_urls = self._discover_document_urls(url)
        self.log.info(f"Found {len(document_urls)} document URL(s) on {url}")

        documents_with_findings: List[Dict[str, Any]] = []
        for document_url in document_urls:
            self.log.info(f"Scanning document: {document_url}")
            result = self._scan_document(document_url)
            if result:
                documents_with_findings.append(result)

        if documents_with_findings:
            status = TaskStatus.INTERESTING
            num_total_findings = sum(
                len(items) for doc in documents_with_findings for items in doc["findings"].values()
            )
            status_reason = (
                f"Found {num_total_findings} leaked sensitive data item(s) "
                f"in {len(documents_with_findings)} document(s) with issues"
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "documents_checked": len(document_urls),
                "documents_with_findings": documents_with_findings,
            },
        )


if __name__ == "__main__":
    LeakScanner.parallel_loop()
