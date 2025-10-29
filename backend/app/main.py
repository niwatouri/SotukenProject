from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from rq import Queue
import httpx
import os
import json
from app.tasks import zap_scan_task
from rq.job import Job

app = FastAPI()

# Redis接続
redis_conn = Redis(host="redis", port=6379)
q = Queue(connection=redis_conn)

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
    data = await request.json()
    url = data.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{ZAP_SCANNER_URL}/scan", json={"url": url})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()


# --- レポート取得 ---
@app.get("/report")
def get_report():
    try:
        with open(REPORT_PATH, "r") as f:
            report = json.load(f)
        return report
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
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    job = q.enqueue(zap_scan_task, url)
    return {"job_id": job.get_id()}


# --- RQ結果取得 ---
@app.get("/scan-result/{job_id}")
def get_scan_result(job_id: str):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "status": job.get_status(),
        "result": job.result if job.is_finished else None
    }
