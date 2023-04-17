from test.base import ArtemisModuleTestCase

from artemis.binds import TaskStatus, TaskType
from artemis.modules.karton_ssl_checks import SSLChecks
from karton.core import Task


class SSLChecksTestCase(ArtemisModuleTestCase):
    karton_class = SSLChecks

    def test_self_signed(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "self-signed.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "self-signed.badssl.com: certificate authority invalid")

    def test_untrusted_root(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "untrusted-root.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["status_reason"], "untrusted-root.badssl.com: certificate authority invalid")

    def test_expired(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "expired.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "expired.badssl.com : Certificate expired.",
            call.kwargs["status_reason"],
        )

    def test_wrong_host(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "wrong-host.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "wrong-host.badssl.com: certificate CN doesn't match hostname",
            call.kwargs["status_reason"],
        )

    def test_no_http_redirect(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "http.badssl.com"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn(
            "No https redirect from http://http.badssl.com to https detected, final url: http://http.badssl.com/",
            call.kwargs["status_reason"],
        )
