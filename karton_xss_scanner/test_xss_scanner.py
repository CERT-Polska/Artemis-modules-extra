import os
from test.base import ArtemisModuleTestCase

from artemis.binds import Service, TaskType
from artemis.modules.karton_xss_scanner import (
    XssScanner,
    add_params,
    logger,
    prepare_crawling_result,
)
from karton.core import Task


class XssScannerTestCase(ArtemisModuleTestCase):
    karton_class = XssScanner

    def test_prepare_crawling_result(self) -> None:
        with open("test_output.log") as f:
            mock_output_str = f.read()
        vectors = set(prepare_crawling_result(output_str=mock_output_str))

        vectors_expected = set(
            [
                "https://mocktest.pl/kupuje?a={xss}",
                "http://mockdomain.pl/index.php?searchword={xss}",
                "http://testdomain.pl/test.php?searchword={xss}",
                "http://testdomain.gov.pl/test.php?searchword={xss}",
                "https://mocktest.gov.pl/kupuje?a={xss}",
                "http://mockdomain.gov.pl/index.php?searchword={xss}",
            ]
        )
        self.assertEqual(len(vectors), 6)
        self.assertEqual(vectors, vectors_expected)

    def test_add_common_xss_params(self) -> None:
        url = "http://example.com/test?param1=value1"
        modified_url = add_params(logger, url)
        xss_params_file = os.path.join(os.path.dirname(__file__), "xss_params.txt")
        with open(xss_params_file, "r") as file:
            params = file.read().splitlines()
            params = [param.strip() for param in params if param.strip() and not param.startswith("#")]

        expected_url = "http://example.com/test?param1=value1&" + "&".join(f"{param}=testvalue" for param in params)

        self.assertEqual(modified_url, expected_url)

    def test_xss_scanner_on_index_page(self) -> None:
        url = "http://test-apache-with-xss/index.php?username=abc&password=abc"
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": url},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        expected_result = {
            "http://test-apache-with-xss/index.php?username={xss}",
            "http://test-apache-with-xss/index.php?search={xss}",
            "http://test-apache-with-xss/index.php?password={xss}",
        }
        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertEqual(set(call.kwargs["data"].get("result")), expected_result)
        self.assertTrue(len(call.kwargs["data"]["result"]) == 3)
        self.assertEqual(call.kwargs["task"].payload["url"], url)
