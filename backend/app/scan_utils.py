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


def normalize_scan_types(scan_types: Any) -> list[str]:
    if not isinstance(scan_types, list):
        return []
    normalized: list[str] = []
    for item in scan_types:
        if isinstance(item, (str, bytes)):
            value = str(item).lower().strip()
            if value and value not in normalized:
                normalized.append(value)
    if "all" in normalized and len(normalized) > 1:
        normalized = [value for value in normalized if value != "all"]
    return normalized


def scan_type_from_scan_types(scan_types: Any) -> str:
    normalized = normalize_scan_types(scan_types)
    if normalized == ["all"] or not normalized:
        return "bulk"
    return "detailed"
