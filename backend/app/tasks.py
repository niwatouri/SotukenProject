# backend/app/tasks.py
import httpx
import os

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")

def zap_scan_task(url: str):
    import time
    time.sleep(2)  # デバッグ用
    response = httpx.post(f"{ZAP_SCANNER_URL}/scan", json={"url": url})
    if response.status_code != 200:
        raise Exception(f"ZAP scan failed: {response.text}")
    return response.json()
