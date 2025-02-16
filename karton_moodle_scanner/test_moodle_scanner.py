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
        
        # Verify status and reason
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found Moodle 4.2 installation at http://test-service-moodle:8080",
        )
        
        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertEqual(data[0]["extracted_version"], "4.2")
        self.assertIsNone(data[0]["error"])
        self.assertIn("raw_output", data[0])
        self.assertFalse(data[0]["is_version_obsolete"])
        self.assertEqual(len(data[0]["vulnerabilities"]), 0)

    def test_moodle_vulnerabilities(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
            payload={"url": "http://test-service-moodle:8080"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        
        # Verify status and reason
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(
            call.kwargs["status_reason"],
            "No vulnerabilities found in Moodle installation",
        )
        
        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertIsNotNone(data["version"])
        self.assertIsNone(data["error"])
        self.assertIn("raw_output", data)
        self.assertFalse(data["is_version_obsolete"])
        self.assertEqual(len(data["vulnerabilities"]), 0)
        self.assertIsNotNone(data["server"])
