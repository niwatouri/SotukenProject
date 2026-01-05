import json
from typing import Any, Dict, Optional


def normalize_report(report_payload: Any) -> Optional[Dict[str, Any]]:
    if isinstance(report_payload, dict):
        return report_payload
    if isinstance(report_payload, str):
        try:
            return json.loads(report_payload)
        except json.JSONDecodeError:
            return None
    return None


def scan_type_from_scan_types(scan_types: Any) -> str:
    if isinstance(scan_types, list) and scan_types and "all" not in scan_types:
        return "detailed"
    return "bulk"
