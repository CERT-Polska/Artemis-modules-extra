import io
import zipfile
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.leak_scanner import LeakScanner
from karton.core import Task

from extra_modules_config import ExtraModulesConfig

TEST_DATA_DIR = "/opt/test/data/leak_scanner"
LEAKED_TEXT = "SECRET: John Doe SSN 123-45-6789"


def _read_test_file(name: str) -> bytes:
    with open(f"{TEST_DATA_DIR}/{name}", "rb") as f:
        return f.read()


def _make_zip(members: dict[str, bytes], encrypted: tuple[str, ...] = ()) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    result = bytearray(buffer.getvalue())
    # zipfile can't write encrypted archives, so mark members as encrypted (as `zip -e` would) by
    # setting bit 0 of the general purpose flags in their local and central directory headers.
    for signature, flags_offset, name_length_offset, name_offset in (
        (b"PK\x03\x04", 6, 26, 30),
        (b"PK\x01\x02", 8, 28, 46),
    ):
        position = result.find(signature)
        while position != -1:
            name_length = int.from_bytes(
                result[position + name_length_offset : position + name_length_offset + 2], "little"
            )
            name = result[position + name_offset : position + name_offset + name_length].decode()
            if name in encrypted:
                result[position + flags_offset] |= 0x1
            position = result.find(signature, position + 1)
    return bytes(result)


class LeakScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = LeakScanner

    def test_bad_redaction_detected(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={
                "host": "test-leak-scanner-service",
                "port": 80,
                "ssl": False,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("leaked sensitive data", call.kwargs["status_reason"].lower())

        data = call.kwargs["data"]
        self.assertEqual(data["documents_checked"], 3)
        self.assertEqual(len(data["documents_with_findings"]), 2)
        results = {doc["url"].rsplit("/", 1)[-1]: doc for doc in data["documents_with_findings"]}
        self.assertEqual(set(results), {"bad_redaction.pdf", "documents.zip"})

        leaked_items = results["bad_redaction.pdf"]["findings"]["bad_redaction"]
        self.assertEqual(len(leaked_items), 1)
        self.assertEqual(leaked_items[0]["text"], LEAKED_TEXT)
        self.assertNotIn("file", leaked_items[0])

        # documents.zip contains reports/bad_redaction.pdf, clean.pdf and notes.txt
        archive_items = results["documents.zip"]["findings"]["bad_redaction"]
        self.assertEqual(len(archive_items), 1)
        self.assertEqual(archive_items[0]["text"], LEAKED_TEXT)
        self.assertEqual(archive_items[0]["file"], "reports/bad_redaction.pdf")

    def test_archive_documents_are_checked(self) -> None:
        archive = _make_zip(
            {
                "a/bad.PDF": _read_test_file("bad_redaction.pdf"),
                "b/bad.pdf": _read_test_file("bad_redaction.pdf"),
                "clean.pdf": _read_test_file("clean.pdf"),
                "bad.pdf.txt": _read_test_file("bad_redaction.pdf"),
            }
        )
        findings = self.karton._scan_archive(archive, "http://example.com/a.zip")
        self.assertEqual(
            [(item["file"], item["text"]) for item in findings["bad_redaction"]],
            [("a/bad.PDF", LEAKED_TEXT), ("b/bad.pdf", LEAKED_TEXT)],
        )

    def test_archive_skips_what_it_cannot_check(self) -> None:
        bad_pdf = _read_test_file("bad_redaction.pdf")
        self.assertEqual(self.karton._scan_archive(b"not a zip file", "http://example.com/a.zip"), {})
        self.assertEqual(self.karton._scan_archive(bad_pdf, "http://example.com/a.zip"), {})
        self.assertEqual(
            self.karton._scan_archive(_make_zip({"nested.zip": _make_zip({"bad.pdf": bad_pdf})}), "http://e.com/a.zip"),
            {},
        )

        archive = _make_zip({"secret.pdf": bad_pdf, "public.pdf": bad_pdf}, encrypted=("secret.pdf",))
        findings = self.karton._scan_archive(archive, "http://example.com/a.zip")
        self.assertEqual([item["file"] for item in findings["bad_redaction"]], ["public.pdf"])

    def test_archive_limits(self) -> None:
        bad_pdf = _read_test_file("bad_redaction.pdf")
        archive = _make_zip({f"{i}.pdf": bad_pdf for i in range(3)})

        with patch.object(ExtraModulesConfig, "LEAK_SCANNER_MAX_ARCHIVE_MEMBERS_TO_CHECK", 2):
            findings = self.karton._scan_archive(archive, "http://example.com/a.zip")
        self.assertEqual([item["file"] for item in findings["bad_redaction"]], ["0.pdf", "1.pdf"])

        with patch.object(ExtraModulesConfig, "LEAK_SCANNER_MAX_DOCUMENT_SIZE_BYTES", len(bad_pdf) - 1):
            self.assertEqual(self.karton._scan_archive(archive, "http://example.com/a.zip"), {})
