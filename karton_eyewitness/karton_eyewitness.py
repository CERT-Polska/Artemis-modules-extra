#!/usr/bin/env python3
import dataclasses
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List
from bs4 import BeautifulSoup

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@dataclasses.dataclass
class Message:
    category: str
    problems: List[str]

    @property
    def message(self) -> str:
        return f"{self.category}: {', '.join(self.problems)}"


def parse_http(html_content: str) -> List[str]:
    soup = BeautifulSoup(html_content, 'html.parser')

    table = soup.find('table')
    extracted_content = []
    if table:
        rows = table.find_all('tr')
        for row in rows:
            cells = row.find_all(['th', 'td'])
            if cells:
                first_column_content = cells[0].text.strip()
                # Extracting content separated by <br> tags
                extracted_content = [content.strip().rstrip('\n') for content in first_column_content.split('<br>')]
    
        return extracted_content
    return []

class EyeWitness(ArtemisBase):
    """
    Runs EyeWitness -> EyeWitness is designed to take screenshots of websites provide some server header info,
    and identify default credentials if known.
    """

    identity = "eyewitness"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def run(self, current_task: Task) -> None:

        base_url = get_target_url(current_task)
        result_location = "/eyewitness/results/"

        data = subprocess.check_output(
            [
                "python3",
                "Python/EyeWitness.py",
                "--web",
                "--single",
                base_url,
                "--no-prompt",
                "--delay",
                str(1.0 / Config.Limits.REQUESTS_PER_SECOND) if Config.Limits.REQUESTS_PER_SECOND else "0",
                # ("--user-agent" + str(Config.Miscellaneous.CUSTOM_USER_AGENT)) if Config.Miscellaneous.CUSTOM_USER_AGENT else " ",
                "-d",
                result_location   
            ],
            cwd="/eyewitness",
            stderr=subprocess.DEVNULL,
        )

        data = open(result_location + "report.html", "r").read()

        # Check if the input string is empty
        if data.strip():
            result = data
        else:
            result = []

        messages = parse_http(data)
        
        # cleanup files
        try:
            shutil.rmtree(result_location)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join([message for message in messages])
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "original_result": result,
                "message_data": messages,
                "messages": messages,
            },
        )


if __name__ == "__main__":
    EyeWitness().loop()