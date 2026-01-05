# backend/app/tasks.py
import httpx
import os
import time
from psycopg2.extras import Json
from app.db import get_db_connection
from app.report_parser import parse_zap_report
from app.scan_utils import normalize_report, scan_type_from_scan_types

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
ZAP_SCANNER_API_KEY = os.getenv("ZAP_SCANNER_API_KEY")
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))
RETRY_BACKOFF_SECONDS = [2, 4, 8, 12, 20, 30]


def _update_scan_status(
    scan_id,
    user_id,
    status,
    error=None,
    raw_report=None,
    parsed_report=None,
    progress_percent=None,
):
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
                    parsed_report = %s,
                    progress_percent = COALESCE(%s, progress_percent)
                WHERE id = %s AND user_id = %s
                """,
                (
                    status,
                    status,
                    status,
                    error,
                    Json(raw_report) if raw_report is not None else None,
                    Json(parsed_report) if parsed_report is not None else None,
                    progress_percent,
                    scan_id,
                    user_id,
                ),
            )


def zap_scan_task(
    scan_id: int,
    url: str,
    scan_types: list[str] | None,
    user_id: int,
    auth: dict | None = None,
):
    """
    Kick off a ZAP scan via the scanner service. Returns raw response data for later parsing.
    """
    payload_scan_types = scan_types or ["all"]
    try:
        headers = {"X-API-Key": ZAP_SCANNER_API_KEY} if ZAP_SCANNER_API_KEY else {}
        _update_scan_status(scan_id, user_id, "running", error=None, progress_percent=5)
        response = httpx.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={
                "url": url,
                "scan_types": payload_scan_types,
                "auth": auth,
                "scan_id": scan_id,
            },
            headers=headers,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            for wait_seconds in RETRY_BACKOFF_SECONDS:
                time.sleep(wait_seconds)
                response = httpx.post(
                    f"{ZAP_SCANNER_URL}/scan",
                    json={
                        "url": url,
                        "scan_types": payload_scan_types,
                        "auth": auth,
                        "scan_id": scan_id,
                    },
                    headers=headers,
                    timeout=SCAN_TIMEOUT_SECONDS,
                )
                if response.status_code != 429:
                    break
        if response.status_code != 200:
            error_message = (
                "ZAP scanner busy after retries"
                if response.status_code == 429
                else f"ZAP scan failed with status {response.status_code}"
            )
            raise RuntimeError(error_message)
        data = response.json()
    except Exception as exc:
        _update_scan_status(scan_id, user_id, "failed", error=str(exc), progress_percent=100)
        # Propagate a concise error so the worker marks the job as failed.
        raise Exception(f"ZAP scan failed: {exc}") from exc

    raw_report = normalize_report(data.get("report"))
    auth_status = data.get("auth_status") if isinstance(data, dict) else None
    if raw_report is None:
        _update_scan_status(
            scan_id,
            user_id,
            "failed",
            error="Report payload missing or invalid",
            progress_percent=100,
        )
        raise Exception("ZAP scan failed: report payload missing or invalid")

    parsed_report = parse_zap_report(
        raw_report,
        default_scan_type=scan_type_from_scan_types(payload_scan_types),
        default_target_url=url,
    )
    if isinstance(auth_status, dict):
        parsed_report["authStatus"] = auth_status
    _update_scan_status(
        scan_id,
        user_id,
        "finished",
        error=None,
        raw_report=raw_report,
        parsed_report=parsed_report,
        progress_percent=100,
    )

    return {
        "scan_id": scan_id,
        "url": url,
        "scan_types": payload_scan_types,
        "response": data,
        "report": data.get("report"),
        "auth_status": auth_status,
    }
