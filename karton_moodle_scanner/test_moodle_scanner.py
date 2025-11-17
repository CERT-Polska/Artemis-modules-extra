from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.moodle_scanner import MoodleScanner
from karton.core import Task


class MoodleScannerTestCase(ArtemisModuleTestCase):
    karton_class = MoodleScanner

    def test_moodle_obsolete_version(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.MOODLE.value},
            payload={"url": "http://test-service-with-obsolete-moodle:80"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Moodle version: 4.5 is obsolete.",
        )
