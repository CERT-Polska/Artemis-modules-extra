from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.karton_sqlmap import SQLmap
from karton.core import Task


class SQLmapTestCase(ArtemisModuleTestCase):
    karton_class = SQLmap

    def test_url_expansion(self) -> None:
        self.assertEqual(
            set(SQLmap._expand_urls_for_scanning("https://example.com/path/file.html?id=1&q=2")),
            {
                "https://example.com/path/file.html?id=1&q=2*",
                "https://example.com/path/file.html?id=1&q=*",
                "https://example.com/path/file.html?id=1*&q=2",
                "https://example.com/path/file.html?id=*&q=2",
                "https://example.com/path/file*.html?id=1&q=2",
                "https://example.com/path/*.html?id=1&q=2",
                "https://example.com/path*/file.html?id=1&q=2",
                "https://example.com/*/file.html?id=1&q=2",
            },
        )
        self.assertEqual(
            set(SQLmap._expand_urls_for_scanning("https://example.com/path/file")),
            {
                "https://example.com/path/file*",
                "https://example.com/path/*",
                "https://example.com/path*/file",
                "https://example.com/*/file",
            },
        )
        self.assertEqual(
            set(SQLmap._expand_urls_for_scanning("https://example.com/path,file")),
            {
                "https://example.com/path,file*",
                "https://example.com/path,*",
                "https://example.com/path*,file",
                "https://example.com/*,file",
            },
        )

    def test_mysql_clean_urls(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-with-sql-injection-mysql-clean-urls:80"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["version"], "5.6.51")
        self.assertEqual(call.kwargs["data"]["user"], "root@%")
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found SQL Injection in http://test-service-with-sql-injection-mysql:80/vuln/4 (GET)",
        )

    def test_mysql(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP.value, "webapp": WebApplication.UNKNOWN.value},
            payload={"url": "http://test-service-with-sql-injection-mysql:80"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["version"], "5.6.51")
        self.assertEqual(call.kwargs["data"]["user"], "root@%")
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
        self.assertEqual(call.kwargs["data"]["version"], "PostgreSQL 14.1")
        self.assertEqual(call.kwargs["data"]["user"], "root")
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found SQL Injection in http://test-service-with-sql-injection-postgres:80/vuln.php?id=4 (GET)",
        )
