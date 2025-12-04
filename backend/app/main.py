# backend/main.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from rq import Queue
import httpx
import os
import json
from app.tasks import zap_scan_task
from rq.job import Job
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()

# ZAP Scanner URL
ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
print("Loaded ZAP_SCANNER_URL =", ZAP_SCANNER_URL)

# --- FastAPI app ---
app = FastAPI()

# --- Redis Queue ---
redis_conn = Redis(host="redis", port=6379)
q = Queue(connection=redis_conn)

# --- CORS settings ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Report path
REPORT_PATH = "/reports/zap_report.json"


# --- Direct ZAP scan ---
@app.post("/scan")
async def scan(request: Request):
    data = await request.json()
    url = data.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    timeout = httpx.Timeout(600.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(f"{ZAP_SCANNER_URL}/scan", json={"url": url})
        except httpx.ReadTimeout:
            raise HTTPException(status_code=504, detail="ZAP scan timeout")

        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

        return resp.json()


# --- Read Report File ---
@app.get("/report")
def get_report():
    try:
        with open(REPORT_PATH, "r") as f:
            report = json.load(f)
        return report
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")


# --- Dummy AI Advice ---
@app.post("/advice")
async def get_advice(request: Request):
    data = await request.json()
    return {
        "advice": "これはAIによる仮のアドバイスです",
        "based_on": data
    }


# --- Start background scan using RQ ---
@app.post("/start-scan/")
async def start_scan(request: Request):
    data = await request.json()
    url = data.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # ジョブを enqueue
    job = q.enqueue(zap_scan_task, url)
    return {"job_id": job.get_id()}


# --- Check background scan result ---
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
