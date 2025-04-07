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
            "Found: Moodle version 3.5.12 is obsolete",
        )

        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertEqual(data["version"], "3.5.12")
        self.assertIsNone(data["error"])
        self.assertIn("raw_output", data)
        self.assertTrue(data["is_version_obsolete"])
        self.assertEqual(len(data["vulnerabilities"]), 0)
        self.assertIsNotNone(data["server"])

    def test_moodle_detection_3_11(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-moodle-3-11:8081"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        # Verify status and reason
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found: Moodle version 3.11.4 is obsolete",
        )

        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertEqual(data["version"], "3.11.4")
        self.assertIsNone(data["error"])
        self.assertIn("raw_output", data)
        self.assertTrue(data["is_version_obsolete"])
        self.assertEqual(len(data["vulnerabilities"]), 0)
        self.assertIsNotNone(data["server"])

    def test_moodle_vulnerabilities(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
            payload={"url": "http://test-service-moodle:8080"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        # Verify status and reason
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found: Moodle version 3.5.12 is obsolete",
        )

        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertEqual(data["version"], "3.5.12")
        self.assertIsNone(data["error"])
        self.assertIn("raw_output", data)
        self.assertTrue(data["is_version_obsolete"])
        self.assertEqual(len(data["vulnerabilities"]), 0)
        self.assertIsNotNone(data["server"])

    def test_moodle_vulnerabilities_3_11(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
            payload={"url": "http://test-service-moodle-3-11:8080"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        # Verify status and reason
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found: Moodle version 3.11.4 is obsolete",
        )

        # Verify complete data structure
        data = call.kwargs["data"]
        self.assertEqual(data["version"], "3.11.4")
        self.assertIsNone(data["error"])
        self.assertIn("raw_output", data)
        self.assertTrue(data["is_version_obsolete"])
        self.assertEqual(len(data["vulnerabilities"]), 0)
        self.assertIsNotNone(data["server"])
