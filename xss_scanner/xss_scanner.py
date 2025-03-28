import subprocess
from splinter import Browser
from fuzzywuzzy import fuzz

from artemis import load_risk_class, utils
from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host
from karton.core import Task

from extra_modules_config import ExtraModulesConfig

logger = utils.build_logger(__name__)

# Ignore for now
PAYLOADS = {"test_payload"}
FUZZY_LEVEL = 95
CRAWLING_LEVEL = 1


class XssScanner(ArtemisBase):  # type: ignore
    identity = "xss-scanner"

    def prepare_crawling_result(self, output_str: str) -> set:
        lines = output_str.splitlines()
        vectors = set()

        for line in lines:
            line = line.lower().replace(' ', '')

            if 'vulnerablewebpage:' in line:
                webpage = 0
                webpage = line.split('vulnerablewebpage:')[1]
                if webpage.count('http') == 2:
                    webpage = webpage[
                        :webpage[webpage.index('http') + 4:].index('http') + 4]

                elif webpage.count('http') > 2:
                    continue

                webpage = webpage[:-1] if webpage[-1] == '/' else webpage

            elif 'vectorfor' in line:
                vector = "?" + line.split('vectorfor')[1].split(':')[0] + "={xss}"
                if webpage:
                    vectors.add(webpage + vector)

        return vectors

    def test_vectors(self, vectors: set, payloads: set, fuzzy_level: int = 95) -> set:
        payload_present = False
        results = set()
        for vector in vectors:
            print(vector)

        for vector in vectors:
            for payload in payloads:
                print(vector, payload)
                link = vector.replace('{xss}', payload)

                browser = Browser('phantomjs')
                browser.visit(link)

                partial_score = fuzz.token_set_ratio(
                    payload.lower(), browser.html.lower())

                if payload.lower() in browser.html.lower():
                    payload_present = True

                elif fuzzy_level and partial_score > fuzzy_level:
                    payload_present = True

                if payload_present:
                    results.add(link)

        return results

    def _process(self, current_task: Task, host: str) -> None:
        output = subprocess.run(['sh', 'run_crawler.sh', host, CRAWLING_LEVEL], capture_output=True)
        output_str = output.stdout.decode("utf-8")
        vectors = self.prepare_crawling_result(output_str)
        results = self.test_vectors(vectors, PAYLOADS, FUZZY_LEVEL)
        results = ",".join(results)

        error_messages = ["error", "timeout"]
        if results:
            status = 'Interesting'
            status_reason = "Detected {} XSS vulnerabilities".format(len(results))

        elif any(msg in output_str for msg in error_messages):
            status = 'ERROR'
            status_reason = "Error or timeout occurred"

        else:
            status = 'OK'
            status_reason = "Could not identify any XSS Vulnerability"

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=results,
        )

    def run(self, current_task: Task) -> None:
        target_host = get_target_host(current_task)

        self.log.info("Requested to check if %s has XSS Vulnerabilities", target_host)
        self._process(current_task, target_host)


if __name__ == "__main__":
    XssScanner().loop()
