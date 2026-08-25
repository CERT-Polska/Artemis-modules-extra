from typing import Any, Dict, List

from artemis.cpe_tools.cpe_utils import lookup_cpe
from artemis.reporting.base.asset import Asset
from artemis.reporting.base.asset_type import AssetType
from artemis.reporting.base.reporter import Reporter

_WHATVPN_TO_TITLE: dict[str, str] = {
    "Cisco AnyConnect": "Cisco AnyConnect Secure Mobility Client",
    "Pulse Secure": "Ivanti Connect Secure",
    "Juniper NC": "Juniper Network Connect",
    "PAN GlobalProtect": "Palo Alto Networks GlobalProtect",
    "Check Point": "Check Point Endpoint Connect",
    "Fortinet": "Fortinet FortiOS",
    "Array Networks": "ArrayNetworks SSL VPN Client",
    "SonixWall NX": "SonicWall Secure Mobile Access",
}


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

        if isinstance(result, str):
            vpn = result
            port = None
        else:
            vpn = result.get("vpn")
            port = result.get("port")

        title = _WHATVPN_TO_TITLE.get(vpn.strip(), vpn.strip())
        cpe = lookup_cpe(title) if title else None

        if port:
            hostname = f"{hostname}:{port}"

        return [
            Asset(
                asset_type=AssetType.VPN,
                name=hostname.strip(),
                additional_type=vpn.strip(),
                cpe=cpe,
            )
        ]
