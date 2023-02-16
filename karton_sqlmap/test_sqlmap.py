from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.karton_sqlmap import SQLmap
from karton.core import Task


class SQLmapTestCase(ArtemisModuleTestCase):
    karton_class = SQLmap

    def test_mysql(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-with-sql-injection-mysql:80"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found SQL Injection in http://test-service-with-sql-injection-mysql:80/vuln.php?id=4 (GET)",
        )

    def test_postgres(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-with-sql-injection-postgres:80"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found SQL Injection in http://test-service-with-sql-injection-postgres:80/vuln.php?id=4 (GET)",
        )
