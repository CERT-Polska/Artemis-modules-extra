from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class WhatVPNRreporter(Reporter):
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "what-vpn":
            return []

        return [
            Asset(
                asset_type=AssetType.VPN,
                name=task_result["target_string"],
                additional_type=task_result["result"].strip(),
            )
        ]
