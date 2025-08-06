from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from rq import Queue
import httpx
import os
import json
from app.tasks import zap_scan_task

app = FastAPI()

redis_conn = Redis(host="redis", port=6379)
q = Queue(connection=redis_conn)


# CORS設定（開発時のみ。必要に応じて制限してください）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # 本番は必要に応じて制限推奨
    allow_methods=["*"],
    allow_headers=["*"],
)

ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
REPORT_PATH = "/reports/zap_report.json"

@app.api_route("/scan", methods=["POST", "OPTIONS"])
async def scan(request: Request):
    if request.method == "OPTIONS":
        # CORSプリフライトの応答として空を返す
        return {}

    # POSTリクエストの処理
    data = await request.json()
    url = data.get("url") 

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{ZAP_SCANNER_URL}/scan", json={"url": url})
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()

@app.get("/report")
def get_report():
    try:
        with open(REPORT_PATH, "r") as f:
            report = json.load(f)
        return report
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")

@app.post("/advice")
async def get_advice(request: Request):
    data = await request.json()
    # ここは仮実装です
    return {
        "advice": "これはAIによる仮のアドバイスです",
        "based_on": data
    }

from rq.job import Job

@app.post("/start-scan/")
def start_scan(request: Request):
    import asyncio
    async def get_url():
        data = await request.json()
        return data.get("url")

    url = asyncio.run(get_url())
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    job = q.enqueue(zap_scan_task, url)
    return {"job_id": job.get_id()}

@app.get("/scan-result/{job_id}")
def get_scan_result(job_id: str):
    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "status": job.get_status(),  # queued, started, finished, failed
        "result": job.result if job.is_finished else None
    }
