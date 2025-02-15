from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.karton_moodle_scanner import MoodleScanner
from karton.core import Task


class MoodleScannerTestCase(ArtemisModuleTestCase):
    karton_class = MoodleScanner

    def test_moodle_detection(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-moodle:8080"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"][0]["extracted_version"], "4.2")
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found Moodle 4.2 installation at http://test-service-moodle:8080",
        )

    def test_moodle_vulnerabilities(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
            payload={"url": "http://test-service-moodle:8080"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        # Here we expect no vulnerabilities since we're using latest version
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(
            call.kwargs["status_reason"],
            "No vulnerabilities found in Moodle installation",
        )
