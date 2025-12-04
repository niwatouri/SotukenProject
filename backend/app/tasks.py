# backend/app/tasks.py
import httpx
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ZAP Scanner URL
ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
print("[tasks.py] Loaded ZAP_SCANNER_URL =", ZAP_SCANNER_URL)

def zap_scan_task(url: str):
    """
    Background scan task executed by RQ Worker.
    Calls ZAP Scanner API and returns JSON result.
    """

    # --- optional: small delay for debugging ---
    import time
    time.sleep(1)

    # Timeout (e.g., 20 minutes)
    timeout = httpx.Timeout(1200.0)

    try:
        response = httpx.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={"url": url},
            timeout=timeout,
        )
    except httpx.RequestError as e:
        raise Exception(f"ZAP scan request error: {str(e)}")

    # Handle non-200 response
    if response.status_code != 200:
        raise Exception(f"ZAP scan failed: {response.status_code} {response.text}")

    return response.json()
