from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType
from artemis.modules.karton_testssl import TestSSL
from karton.core import Task


class TestSSLTestCase(ArtemisModuleTestCase):
    karton_class = TestSSL

    def test_ok(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "sha256.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

    def test_poodle(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "test-service-with-poodle"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["poodle"], True)
        self.assertIn(
            "test-service-with-poodle: POODLE vulnerable",
            call.kwargs["status_reason"],
        )
