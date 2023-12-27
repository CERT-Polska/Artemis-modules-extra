#!/usr/bin/env python3
import json
import subprocess

from artemis.binds import TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from karton.core import Task


def process_json_data(result):
    messages = []

    # Iterate through key-value pairs in the result
    for key, value in result.items():
        # Split the key to extract the relevant part
        key_parts = key.replace("[", "").replace("]", "").split(". ")

        # Check if the key has the expected structure
        if len(key_parts) >= 2:
            category = key_parts[1].capitalize()

            # Check if the key is not in the excluded categories and there are relevant values
            if (key_parts[1].lower() != "info" and
                    key not in ["[2. Fingerprint HTTP Response Headers]",
                                "[3. Deprecated HTTP Response Headers/Protocols and Insecure Values]",
                                "[4. Empty HTTP Response Headers Values]",
                                "[5. Browser Compatibility for Enabled HTTP Security Headers]"]
                    and (isinstance(value, dict) or (isinstance(value, list)
                                                     and any(subvalue for subvalue in value
                                                             if subvalue and subvalue not in [
                                                                "Nothing to report, all seems OK!",
                                                                "No HTTP security headers are enabled."])))):
                messages.append(f"{category}:")

                # If the value is a dictionary, iterate through subkey-value pairs
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        # Add subkeys and subvalues to messages
                        if subvalue and subvalue not in ["Nothing to report, all seems OK!",
                                                         "No HTTP security headers are enabled."]:
                            messages.append(f"  {subkey}: {subvalue}")

                # If the value is a list, iterate through list items
                elif isinstance(value, list):
                    for item in value:
                        # Add list items to messages
                        if item and item not in ["Nothing to report, all seems OK!",
                                                 "No HTTP security headers are enabled."]:
                            messages.append(f"  {item}")

    return messages


class Humble(ArtemisBase):  # type: ignore
    """
    Runs humble -> A HTTP Headers Analyzer
    """

    identity = "humble"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]

    def run(self, current_task: Task) -> None:
        domain = current_task.payload["domain"]

        data = subprocess.check_output(
            [
                "python3",
                "humble.py",
                "-u",
                domain,
                "-b",
                "-o",
                "json",
            ],
            cwd="/humble",
            stderr=subprocess.DEVNULL,
        )

        # strip the first 74 and the last characters from the output to get the location and filename of the output file
        filename = data.decode("ascii", errors="ignore")[74:-1]
        data_str = open(filename, "r").read()

        # cleanup file
        subprocess.run(["rm", filename])

        # Check if the input string is empty
        if data_str.strip():
            result = json.loads(data_str)
        else:
            result = []

        # Parse the JSON data
        messages = process_json_data(result)

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=result)


if __name__ == "__main__":
    Humble().loop()
