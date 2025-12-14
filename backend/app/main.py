from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from rq import Queue
import httpx
import os
import json
from typing import Any, Dict, Optional
from app.report_parser import parse_zap_report
from app.tasks import zap_scan_task
from rq.job import Job

app = FastAPI()

# Redis接続
redis_conn = Redis(host="redis", port=6379)
# 長時間スキャンに耐えるよう、デフォルトタイムアウトを伸ばしてキューを作成
q = Queue(connection=redis_conn, default_timeout=1200)

# --- ✅ CORS設定 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000", "*"],  # 必要に応じて制限
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
REPORT_PATH = "/reports/zap_report.json"


# --- ✅ /scan エンドポイント ---
@app.post("/scan")
async def scan(request: Request):
    """
    Deprecated: use /start-scan/ and /scan-result/{job_id} for async scans instead.
    """
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # scan_types が配列でない/空の場合は全スキャン扱いにフォールバック
    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]

    async with httpx.AsyncClient(timeout=httpx.Timeout(1200)) as client:
        resp = await client.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={"url": url, "scan_types": scan_types}
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()


# --- レポート取得 ---
@app.get("/report")
def get_report():
    try:
        with open(REPORT_PATH, "r") as f:
            raw_report = json.load(f)
        return parse_zap_report(raw_report, default_scan_type="bulk")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")


# --- AIアドバイス仮実装 ---
@app.post("/advice")
async def get_advice(request: Request):
    data = await request.json()
    return {
        "advice": "これはAIによる仮のアドバイスです",
        "based_on": data
    }


# --- RQタスク登録 ---
@app.post("/start-scan/")
async def start_scan(request: Request):
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]
    
    # 600秒タイムアウトのhttpx呼び出しより余裕を持たせてジョブタイムアウトを設定
    job = q.enqueue(zap_scan_task, url, scan_types, job_timeout=1200)
    return {"job_id": job.get_id()}


def _parse_job_result(job_result: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(job_result, dict):
        return None

    report_payload = job_result.get("report")
    if report_payload is None and isinstance(job_result.get("response"), dict):
        report_payload = job_result["response"].get("report")

    if isinstance(report_payload, str):
        try:
            raw_report = json.loads(report_payload)
        except json.JSONDecodeError:
            return None
    elif isinstance(report_payload, dict):
        raw_report = report_payload
    else:
        return None

    scan_types = job_result.get("scan_types") or (job_result.get("response") or {}).get("scan_types")
    default_scan_type = "bulk"
    if isinstance(scan_types, list) and scan_types and "all" not in scan_types:
        default_scan_type = "detailed"

    target_url = job_result.get("url") or (job_result.get("response") or {}).get("url")
    return parse_zap_report(raw_report, default_scan_type=default_scan_type, default_target_url=target_url)


# --- RQ結果取得 ---
@app.get("/scan-result/{job_id}")
def get_scan_result(job_id: str):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    status = job.get_status()

    if status == "failed":
        error_message = "Scan job failed"
        if job.exc_info:
            error_message = job.exc_info.strip().splitlines()[-1]
        return {"status": status, "error": error_message}

    if status == "finished":
        try:
            parsed = _parse_job_result(job.result)
        except Exception as exc:
            return {"status": status, "error": f"Failed to parse scan result: {exc}"}

        if parsed is None:
            return {"status": status, "error": "Scan result unavailable"}

        return {"status": status, "result": parsed}

    return {"status": status, "result": None}
