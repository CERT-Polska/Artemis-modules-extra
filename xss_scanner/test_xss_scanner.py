from test.base import ArtemisModuleTestCase
from karton.core import Task
from artemis.modules.xss_scanner import XssScanner
from artemis.binds import Service, TaskType


class XssScannerTestCase(ArtemisModuleTestCase):
    karton_class = XssScanner

    def test_xss_scanner_on_index_page(self) -> None:
        url = "http://test-apache-with-xss/index.php?username=abc&password=abc"
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": url},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertTrue(len(call.kwargs["data"]["result"]) == 2)
        self.assertEqual(call.kwargs["task"].payload["url"], url)
