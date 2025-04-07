import logging
import tempfile
import subprocess
import os
from typing import List, Dict, Any

from artemis_base.artemis_base import ArtemisBase
from artemis_base.models import TaskType, Task
from karton.core import Task


class PurednsModule(ArtemisBase):
    """
    Puredns karton module
    """

    identity = "puredns"
    filters = [
        {"type": TaskType.DOMAIN.value},
        {"type": TaskType.DOMAIN_LIST.value},
        {"type": TaskType.SUBDOMAIN_BRUTEFORCE.value},
    ]

    def run(self, current_task: Task) -> None:
        task_type = TaskType(current_task.headers["type"])
        payload = current_task.get_payload("payload")
        self.log.info(f"Received task of type {task_type} with payload {payload}")

        if task_type == TaskType.DOMAIN:
            self.process_domain(current_task)
        elif task_type == TaskType.DOMAIN_LIST:
            self.process_domain_list(current_task)
        elif task_type == TaskType.SUBDOMAIN_BRUTEFORCE:
            self.perform_subdomain_bruteforce(current_task)
        else:
            self.log.error(f"Unsupported task type: {task_type}")

    def process_domain(self, task: Task) -> None:
        """
        Resolves subdomains for a single domain using puredns.
        Sends results as a new DOMAIN task.
        """
        domain = task.get_payload(TaskType.DOMAIN)
        self.log.info(f"Processing single domain task for: {domain}")

        temp_domain_file = None
        output_file = None
        wildcards_file = None
        massdns_file = None

        # Assume config is accessible via self.config (adjust if needed)
        puredns_path = os.environ.get("PUREDNS_PATH", "puredns")
        resolvers_file = os.environ.get("RESOLVERS_FILE", "resolvers.txt")

        if not os.path.exists(resolvers_file):
            self.log.error(f"Resolvers file not found at {resolvers_file}. Skipping puredns.")
            return

        try:
            # 1. Create temporary input file
            temp_domain_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
            temp_domain_file.write(domain + "\n")
            temp_domain_file.close()

            # 2. Create temporary output files
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-output.txt")
            output_file.close()
            wildcards_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-wildcards.txt")
            wildcards_file.close()
            massdns_file = tempfile.NamedTemporaryFile(delete=False, suffix="-puredns-massdns.txt")
            massdns_file.close()

            # 3. Execute puredns
            cmd = [
                puredns_path,
                "resolve",
                temp_domain_file.name,
                "--resolvers", resolvers_file,
                "--write", output_file.name,
                "--write-wildcards", wildcards_file.name,
                "--write-massdns", massdns_file.name,
            ]
            self.log.info(f"Running puredns command: {' '.join(cmd)}")

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            if process.returncode != 0:
                self.log.error(f"Puredns failed for {domain} with return code {process.returncode}")
                self.log.error(f"Puredns stdout: {process.stdout}")
                self.log.error(f"Puredns stderr: {process.stderr}")
                return # Stop processing if puredns fails

            self.log.info(f"Puredns completed successfully for {domain}")

            # 5. Read results
            valid_domains_list = self._read_file(output_file.name)
            wildcard_domains_list = self._read_file(wildcards_file.name)

            # 6. Create new task with results
            result_payload = {
                "domain": domain,
                "valid_domains": valid_domains_list,
                "wildcard_domains": wildcard_domains_list,
                "massdns_file": massdns_file.name # Path to massdns output
            }

            new_task = Task(
                {
                    "type": TaskType.DOMAIN,
                    "origin": self.identity,
                },
                payload=result_payload,
            )
            self.send_task(new_task)
            self.log.info(f"Sent {len(valid_domains_list)} valid domains found for {domain}")

        except FileNotFoundError as e:
             self.log.error(f"Puredns executable not found at '{puredns_path}'. Please ensure it's installed and in PATH or configure the correct path. Error: {e}")
        except Exception as e:
            self.log.exception(f"An error occurred during puredns processing for {domain}: {e}")
        finally:
            # 7. Cleanup temporary files
            for f in [temp_domain_file, output_file, wildcards_file, massdns_file]:
                if f and hasattr(f, 'name') and os.path.exists(f.name):
                    try:
                        os.remove(f.name)
                        self.log.debug(f"Removed temporary file: {f.name}")
                    except OSError as e:
                        self.log.error(f"Error removing temporary file {f.name}: {e}")

    def process_domain_list(self, task: Task) -> None:
        # Placeholder for processing domain list
        self.log.info("Processing domain list task...")
        pass

    def perform_subdomain_bruteforce(self, task: Task) -> None:
        # Placeholder for subdomain bruteforce
        self.log.info("Performing subdomain bruteforce task...")
        pass

    def _read_file(self, file_path: str) -> list[str]:
        """Helper method to read lines from a file."""
        try:
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log.error(f"File not found: {file_path}")
            return []
        except Exception as e:
            self.log.error(f"Error reading file {file_path}: {e}")
            return []

if __name__ == "__main__":
    PurednsModule().loop()
