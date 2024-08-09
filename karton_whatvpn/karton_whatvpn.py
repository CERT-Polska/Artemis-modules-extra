import subprocess

from artemis import utils
from artemis.binds import TaskStatus, TaskType, Service
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url, get_target_host
from karton.core import Task


from extra_modules_config import ExtraModulesConfig

logger = utils.build_logger(__name__)

class WhatVPN(ArtemisBase):
    """ 
    Runs what-vpn -> SSL VPN identifier
    """
    
    identity = "what-vpn"
    filters = [
        # {"type": TaskType.IP.value}, #czy service:http nie zawiera też IPków?
        {"type": TaskType.DOMAIN.value}
        # {"type": TaskType.SERVICE.value, "service": Service.HTTP.value}
    ]

    def run(self, current_task: Task) -> None:
        target_host = get_target_host(current_task)
        
        logger.info("Requested to check if %s is a VPN gateway", target_host)
        data = subprocess.run( #print?
            [
                "what-vpn",
                target_host

            ],
            capture_output=True
        )

        status = TaskStatus.OK
        status_reason = None
        result = data.stdout.decode("utf-8")
        if "no match" in result:
            result = {"error": "Could not identify a VPN gateway"}
        else:
            result = result.split(' ', 1)[1]
            status = TaskStatus.INTERESTING
            status_reason = f"Detected {result}"

        # Save the task result to the database
        self.db.save_task_result(
            task=current_task,
            status = status,
            status_reason=status_reason,
            data={"result": result},
        )

if __name__ == "__main__":
    WhatVPN().loop()