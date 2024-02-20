from typing import Any, Dict


def tamper(payload: str, **kwargs: Dict[Any, Any]) -> str:
    return payload.replace("'", '"')
