from test.base import ArtemisModuleTestCase
from karton.core import Task
from artemis.modules.xss_scanner import XssScanner, prepare_crawling_result
from artemis.binds import Service, TaskType


class XssScannerTestCase(ArtemisModuleTestCase):
    karton_class = XssScanner

    def test_prepare_crawling_result(self) -> None:
        with open("test_output.log") as f:
            mock_output_str = f.read()
        vectors = set(prepare_crawling_result(output_str=mock_output_str))

        vectors_expected = set(['https://mocktest.pl/kupuje?a={xss}', 'http://mockdomain.pl/index.php?searchword={xss}', 'http://testdomain.pl/test.php?searchword={xss}', 'http://testdomain.gov.pl/test.php?searchword={xss}', 'https://mocktest.gov.pl/kupuje?a={xss}', 'http://mockdomain.gov.pl/index.php?searchword={xss}'])
        self.assertEqual(len(vectors), 6)
        self.assertEqual(vectors, vectors_expected)

    def test_xss_scanner_on_index_page(self) -> None:
        url = "http://test-apache-with-xss/index.php?username=abc&password=abc"
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": url},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        expected_status_reason = "Detected XSS vulnerabilities: ['http://test-apache-with-xss/index.php?username={xss}', 'http://test-apache-with-xss/index.php?password={xss}']"
        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status_reason"], expected_status_reason)
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertTrue(len(call.kwargs["data"]["result"]) == 2)
        self.assertEqual(call.kwargs["task"].payload["url"], url)
