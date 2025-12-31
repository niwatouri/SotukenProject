# backend/app/tasks.py
import httpx
import json
import os
from psycopg2.extras import Json
from app.db import get_db_connection
from app.report_parser import parse_zap_report

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")


def _normalize_report(report_payload):
    if isinstance(report_payload, dict):
        return report_payload
    if isinstance(report_payload, str):
        try:
            return json.loads(report_payload)
        except json.JSONDecodeError:
            return None
    return None


def _scan_type_from_scan_types(scan_types):
    if isinstance(scan_types, list) and scan_types and "all" not in scan_types:
        return "detailed"
    return "bulk"


def _update_scan_status(scan_id, user_id, status, error=None, raw_report=None, parsed_report=None):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s,
                    started_at = CASE
                        WHEN %s = 'running' THEN COALESCE(started_at, NOW())
                        ELSE started_at
                    END,
                    completed_at = CASE
                        WHEN %s IN ('finished', 'failed') THEN NOW()
                        ELSE completed_at
                    END,
                    error = %s,
                    raw_report = %s,
                    parsed_report = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    status,
                    status,
                    status,
                    error,
                    Json(raw_report) if raw_report is not None else None,
                    Json(parsed_report) if parsed_report is not None else None,
                    scan_id,
                    user_id,
                ),
            )


def zap_scan_task(scan_id: int, url: str, scan_types: list[str] | None, user_id: int):
    """
    Kick off a ZAP scan via the scanner service. Returns raw response data for later parsing.
    """
    payload_scan_types = scan_types or ["all"]
    try:
        _update_scan_status(scan_id, user_id, "running", error=None)
        response = httpx.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={"url": url, "scan_types": payload_scan_types},
            timeout=1200,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        _update_scan_status(scan_id, user_id, "failed", error=str(exc))
        # Propagate a concise error so the worker marks the job as failed.
        raise Exception(f"ZAP scan failed: {exc}") from exc

    raw_report = _normalize_report(data.get("report"))
    if raw_report is None:
        _update_scan_status(scan_id, user_id, "failed", error="Report payload missing or invalid")
        raise Exception("ZAP scan failed: report payload missing or invalid")

    parsed_report = parse_zap_report(
        raw_report,
        default_scan_type=_scan_type_from_scan_types(payload_scan_types),
        default_target_url=url,
    )
    _update_scan_status(
        scan_id,
        user_id,
        "finished",
        error=None,
        raw_report=raw_report,
        parsed_report=parsed_report,
    )

    return {
        "scan_id": scan_id,
        "url": url,
        "scan_types": payload_scan_types,
        "response": data,
        "report": data.get("report"),
    }
