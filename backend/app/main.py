from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from rq import Queue
import httpx
import os
import json
from typing import Any, Dict, Optional
import jwt
from psycopg2.extras import Json
from app.db import get_db_connection, init_scan_schema
from app.report_parser import parse_zap_report
from app.tasks import zap_scan_task
from rq.job import Job

app = FastAPI()


@app.on_event("startup")
def _init_schema() -> None:
    init_scan_schema()

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
JWT_SECRET = os.getenv("JWT_SECRET") or "dev-secret"
JWT_ALGORITHM = "HS256"


def _extract_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token

    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token

    return None


def _verify_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


async def require_auth(request: Request) -> Dict[str, Any]:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _verify_token(token)


def _normalize_report(report_payload: Any) -> Optional[Dict[str, Any]]:
    if isinstance(report_payload, dict):
        return report_payload
    if isinstance(report_payload, str):
        try:
            return json.loads(report_payload)
        except json.JSONDecodeError:
            return None
    return None


def _scan_type_from_scan_types(scan_types: Any) -> str:
    if isinstance(scan_types, list) and scan_types and "all" not in scan_types:
        return "detailed"
    return "bulk"


def _create_scan_record(user_id: int, url: str, scan_types: list[str], status: str) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (user_id, target_url, scan_types, status, started_at)
                VALUES (%s, %s, %s, %s, CASE WHEN %s = 'running' THEN NOW() ELSE NULL END)
                RETURNING id
                """,
                (user_id, url, Json(scan_types), status, status),
            )
            row = cur.fetchone()
            return int(row["id"])


def _update_scan_job_id(scan_id: int, user_id: int, job_id: str) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET job_id = %s
                WHERE id = %s AND user_id = %s
                """,
                (job_id, scan_id, user_id),
            )


def _update_scan_result(scan_id: int, user_id: int, status: str,
                        raw_report: Optional[Dict[str, Any]],
                        parsed_report: Optional[Dict[str, Any]],
                        error: Optional[str]) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s,
                    completed_at = NOW(),
                    error = %s,
                    raw_report = %s,
                    parsed_report = %s
                WHERE id = %s AND user_id = %s
                """,
                (
                    status,
                    error,
                    Json(raw_report) if raw_report is not None else None,
                    Json(parsed_report) if parsed_report is not None else None,
                    scan_id,
                    user_id,
                ),
            )


def _fetch_scan_by_job_id(user_id: int, job_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, target_url, scan_types, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report
                FROM scans
                WHERE user_id = %s AND job_id = %s
                """,
                (user_id, job_id),
            )
            return cur.fetchone()


def _fetch_scan_by_id(user_id: int, scan_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, user_id, target_url, scan_types, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report
                FROM scans
                WHERE user_id = %s AND id = %s
                """,
                (user_id, scan_id),
            )
            return cur.fetchone()


def _fetch_scans(user_id: int, limit: int, offset: int) -> list[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_url, scan_types, status, job_id, created_at,
                       started_at, completed_at, error
                FROM scans
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user_id, limit, offset),
            )
            return cur.fetchall()


def _fetch_latest_report(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT parsed_report
                FROM scans
                WHERE user_id = %s
                  AND status = 'finished'
                  AND parsed_report IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
            return row["parsed_report"] if row else None


# --- ✅ /scan エンドポイント ---
@app.post("/scan")
async def scan(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    """
    Deprecated: use /start-scan/ and /scan-result/{job_id} for async scans instead.
    """
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # scan_types が配列でない/空の場合は全スキャン扱いにフォールバック
    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]

    scan_id = _create_scan_record(user_id, url, scan_types, "running")

    async with httpx.AsyncClient(timeout=httpx.Timeout(1200)) as client:
        resp = await client.post(
            f"{ZAP_SCANNER_URL}/scan",
            json={"url": url, "scan_types": scan_types}
        )
        if resp.status_code != 200:
            _update_scan_result(scan_id, user_id, "failed", None, None, resp.text)
            raise HTTPException(status_code=resp.status_code, detail=resp.text)

        data = resp.json()
        raw_report = _normalize_report(data.get("report"))
        if raw_report is None:
            _update_scan_result(scan_id, user_id, "failed", None, None, "Report payload missing or invalid")
            raise HTTPException(status_code=500, detail="Report payload missing or invalid")

        parsed_report = parse_zap_report(
            raw_report,
            default_scan_type=_scan_type_from_scan_types(scan_types),
            default_target_url=url,
        )
        _update_scan_result(scan_id, user_id, "finished", raw_report, parsed_report, None)
        return data


# --- レポート取得 ---
@app.get("/report")
def get_report(user: Dict[str, Any] = Depends(require_auth)):
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    latest_report = _fetch_latest_report(user_id)
    if latest_report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return latest_report


@app.get("/scans")
def list_scans(limit: int = 20, offset: int = 0, user: Dict[str, Any] = Depends(require_auth)):
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    safe_limit = max(1, min(limit, 100))
    safe_offset = max(0, offset)
    scans = _fetch_scans(user_id, safe_limit, safe_offset)
    return {"scans": scans, "limit": safe_limit, "offset": safe_offset}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int, user: Dict[str, Any] = Depends(require_auth)):
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    scan = _fetch_scan_by_id(user_id, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan": scan}


# --- AIアドバイス仮実装 ---
@app.post("/advice")
async def get_advice(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    data = await request.json()
    return {
        "advice": "これはAIによる仮のアドバイスです",
        "based_on": data
    }


# --- RQタスク登録 ---
@app.post("/start-scan/")
async def start_scan(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]
    
    scan_id = _create_scan_record(user_id, url, scan_types, "queued")

    try:
        # 600秒タイムアウトのhttpx呼び出しより余裕を持たせてジョブタイムアウトを設定
        job = q.enqueue(zap_scan_task, scan_id, url, scan_types, user_id, job_timeout=1200)
    except Exception as exc:
        _update_scan_result(scan_id, user_id, "failed", None, None, f"Queue enqueue failed: {exc}")
        raise HTTPException(status_code=500, detail="Failed to queue scan") from exc

    _update_scan_job_id(scan_id, user_id, job.get_id())
    return {"job_id": job.get_id(), "scan_id": scan_id}


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


def _extract_raw_report(job_result: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(job_result, dict):
        return None

    report_payload = job_result.get("report")
    if report_payload is None and isinstance(job_result.get("response"), dict):
        report_payload = job_result["response"].get("report")

    return _normalize_report(report_payload)


# --- RQ結果取得 ---
@app.get("/scan-result/{job_id}")
def get_scan_result(job_id: str, user: Dict[str, Any] = Depends(require_auth)):
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    scan = _fetch_scan_by_job_id(user_id, job_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    if scan.get("status") == "failed":
        return {"status": "failed", "error": scan.get("error") or "Scan failed"}

    if scan.get("status") == "finished" and scan.get("parsed_report"):
        return {"status": "finished", "result": scan["parsed_report"]}

    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    status = job.get_status()

    if status == "failed":
        error_message = "Scan job failed"
        if job.exc_info:
            error_message = job.exc_info.strip().splitlines()[-1]
        _update_scan_result(scan["id"], user_id, "failed", None, None, error_message)
        return {"status": status, "error": error_message}

    if status == "finished":
        try:
            parsed = _parse_job_result(job.result)
        except Exception as exc:
            return {"status": status, "error": f"Failed to parse scan result: {exc}"}

        if parsed is None:
            return {"status": status, "error": "Scan result unavailable"}

        raw_report = _extract_raw_report(job.result)
        _update_scan_result(scan["id"], user_id, "finished", raw_report, parsed, None)
        return {"status": status, "result": parsed}

    return {"status": status, "result": None}
