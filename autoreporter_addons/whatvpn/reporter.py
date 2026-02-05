from typing import Any, Dict, List

from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter


class WhatVPNRreporter(Reporter):  # type: ignore
    @staticmethod
    def get_assets(task_result: Dict[str, Any]) -> List[Asset]:
        if task_result["headers"]["receiver"] != "what-vpn":
            return []

        if task_result.get("status") != "INTERESTING":
            return []

        result = task_result.get("result")

        if not result:
            return []

        hostname = task_result["target_string"]

        vpn, port = (result.split(":") + [None])[:2]

        if port:
            hostname = f"{hostname}:{port}"

        return [
            Asset(
                asset_type=AssetType.VPN,
                name=hostname.strip(),
                additional_type=vpn.strip(),
            )
        ]
