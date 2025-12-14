# backend/app/tasks.py
import httpx
import os

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")


def zap_scan_task(url: str, scan_types: list[str] | None = None):
    """
    Kick off a ZAP scan via the scanner service. Returns raw response data for later parsing.
    """
    payload_scan_types = scan_types or ["all"]
    try:
        response = httpx.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={"url": url, "scan_types": payload_scan_types},
            timeout=1200,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        # Propagate a concise error so the worker marks the job as failed.
        raise Exception(f"ZAP scan failed: {exc}") from exc

    return {
        "url": url,
        "scan_types": payload_scan_types,
        "response": data,
        "report": data.get("report"),
    }
