import json
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from psycopg2.extras import Json
from redis import Redis
from rq import Queue
from rq.job import Job

from app.config import (
    JWT_SECRET,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    REDIS_HOST,
    REDIS_PORT,
    SCAN_TIMEOUT_SECONDS,
    ZAP_SCANNER_API_KEY,
)
from app.db import get_db_connection, init_scan_schema
from app.report_parser import parse_zap_report
from app.scan_utils import normalize_report, scan_type_from_scan_types
from app.tasks import zap_scan_task

app = FastAPI()


@app.on_event("startup")
def _init_schema() -> None:
    if not JWT_SECRET or not JWT_SECRET.strip():
        raise RuntimeError("JWT_SECRET is required and must be non-empty.")
    init_scan_schema()

# Redis接続
redis_conn = Redis(host=REDIS_HOST, port=REDIS_PORT)
# 長時間スキャンに耐えるよう、デフォルトタイムアウトを伸ばしてキューを作成
q = Queue(connection=redis_conn, default_timeout=SCAN_TIMEOUT_SECONDS)

# --- ✅ CORS設定 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000", "*"],  # 必要に応じて制限
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


def _verify_scanner_key(x_api_key: Optional[str]) -> None:
    if not ZAP_SCANNER_API_KEY:
        return
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing scanner API key")
    if x_api_key != ZAP_SCANNER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid scanner API key")


def _create_scan_record(user_id: int, url: str, scan_types: list[str], status: str) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (user_id, target_url, scan_types, status, started_at, progress_percent)
                VALUES (%s, %s, %s, %s, CASE WHEN %s = 'running' THEN NOW() ELSE NULL END, %s)
                RETURNING id
                """,
                (user_id, url, Json(scan_types), status, status, 0),
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
                        error: Optional[str],
                        progress_percent: Optional[int] = None) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s,
                    completed_at = NOW(),
                    error = %s,
                    raw_report = %s,
                    parsed_report = %s,
                    progress_percent = COALESCE(%s, progress_percent)
                WHERE id = %s AND user_id = %s
                """,
                (
                    status,
                    error,
                    Json(raw_report) if raw_report is not None else None,
                    Json(parsed_report) if parsed_report is not None else None,
                    progress_percent,
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
                       started_at, completed_at, error, parsed_report, progress_percent
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
                       started_at, completed_at, error, parsed_report, progress_percent
                FROM scans
                WHERE user_id = %s AND id = %s
                """,
                (user_id, scan_id),
            )
            return cur.fetchone()


def _normalize_vulnerabilities(raw_vulns: Any) -> list[Dict[str, Any]]:
    if not isinstance(raw_vulns, list):
        return []
    normalized: list[Dict[str, Any]] = []
    for vuln in raw_vulns:
        if not isinstance(vuln, dict):
            continue
        vuln_id = vuln.get("id") or vuln.get("vulnId")
        if not vuln_id:
            continue
        port_value = vuln.get("port")
        try:
            port_value = int(port_value) if port_value is not None else None
        except (TypeError, ValueError):
            port_value = None
        normalized.append({
            "id": str(vuln_id),
            "type": str(vuln.get("type") or ""),
            "severity": str(vuln.get("severity") or ""),
            "port": port_value,
            "description": str(vuln.get("description") or ""),
            "impact": str(vuln.get("impact") or ""),
            "solution": str(vuln.get("solution") or ""),
            "cveId": vuln.get("cveId") or None,
        })
    return normalized


def _generate_ai_advice(vulnerabilities: list[Dict[str, Any]]) -> Dict[str, Any]:
    if not OPENAI_API_KEY or not OPENAI_API_KEY.strip():
        raise HTTPException(status_code=503, detail="OPENAI_API_KEY is not configured")
    client = OpenAI(api_key=OPENAI_API_KEY)
    payload = json.dumps(vulnerabilities, ensure_ascii=False)
    system_message = (
        "あなたはセキュリティアナリストです。入力された脆弱性ごとに、"
        "日本語で分かりやすい解説と改善アドバイスを生成してください。"
        "出力はJSONのみで、余計な説明やMarkdownは不要です。"
    )
    user_message = (
        "以下の脆弱性一覧に対して、必ず同じ件数分のitemsを返してください。\n"
        "出力形式:\n"
        '{"items":[{"vulnId":"<id>","title":"短いタイトル","summary":"概要(1-2文)",'
        '"impact":"影響","steps":["対策手順1","対策手順2"],"analogy":"わかりやすい例え"}]}\n'
        "vulnIdは入力のidをそのまま使用してください。\n"
        "脆弱性一覧:\n"
        f"{payload}"
    )
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="AIアドバイス生成に失敗しました") from exc

    if not response.choices:
        raise HTTPException(status_code=503, detail="AIアドバイスの生成結果が空です")

    content = response.choices[0].message.content or ""
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="AIアドバイスの解析に失敗しました") from exc

    if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
        raise HTTPException(status_code=503, detail="AIアドバイスの形式が不正です")

    return parsed


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


def _fetch_latest_scan(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_url, scan_types, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report
                FROM scans
                WHERE user_id = %s
                  AND status = 'finished'
                  AND parsed_report IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            return cur.fetchone()


def _update_scan_progress(scan_id: int, progress_percent: int) -> None:
    progress_percent = max(0, min(99, int(progress_percent)))
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET progress_percent = GREATEST(progress_percent, %s),
                    started_at = COALESCE(started_at, NOW())
                WHERE id = %s AND status NOT IN ('finished', 'failed')
                """,
                (progress_percent, scan_id),
            )


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


@app.get("/scans/latest")
def get_latest_scan(user: Dict[str, Any] = Depends(require_auth)):
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    scan = _fetch_latest_scan(user_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan": scan}


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
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    if "vulnerabilities" in data:
        raw_vulns = data.get("vulnerabilities")
        if not isinstance(raw_vulns, list):
            raise HTTPException(status_code=400, detail="vulnerabilities must be a list")
        vulnerabilities = _normalize_vulnerabilities(raw_vulns)
        if not vulnerabilities:
            return {"items": []}
        return _generate_ai_advice(vulnerabilities)

    scan_id = data.get("scan_id")
    if scan_id is None:
        raise HTTPException(status_code=400, detail="scan_id or vulnerabilities are required")
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id must be numeric") from exc

    scan = _fetch_scan_by_id(user_id, scan_id)
    if not scan or not scan.get("parsed_report"):
        raise HTTPException(status_code=404, detail="Scan not found")
    vulnerabilities = _normalize_vulnerabilities(scan["parsed_report"].get("vulnerabilities"))
    if not vulnerabilities:
        return {"items": []}
    return _generate_ai_advice(vulnerabilities)


@app.post("/scan-progress")
async def update_scan_progress(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _verify_scanner_key(x_api_key)
    data = await request.json()
    scan_id = data.get("scan_id")
    progress = data.get("progress_percent")
    if scan_id is None or progress is None:
        raise HTTPException(status_code=400, detail="scan_id and progress_percent are required")
    try:
        scan_id = int(scan_id)
        progress = int(progress)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id/progress_percent must be numeric") from exc
    _update_scan_progress(scan_id, progress)
    return {"status": "ok"}


# --- RQタスク登録 ---
@app.post("/start-scan/")
async def start_scan(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")
    auth = data.get("auth")
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]
    
    scan_id = _create_scan_record(user_id, url, scan_types, "queued")

    try:
        # httpx タイムアウト (SCAN_TIMEOUT_SECONDS) に合わせてジョブタイムアウトを設定
        job = q.enqueue(
            zap_scan_task,
            scan_id,
            url,
            scan_types,
            user_id,
            auth,
            job_timeout=SCAN_TIMEOUT_SECONDS,
            description=f"zap_scan_task(scan_id={scan_id}, user_id={user_id})",
        )
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

    raw_report = normalize_report(report_payload)
    if raw_report is None:
        return None

    scan_types = job_result.get("scan_types") or (job_result.get("response") or {}).get("scan_types")
    default_scan_type = scan_type_from_scan_types(scan_types)

    target_url = job_result.get("url") or (job_result.get("response") or {}).get("url")
    return parse_zap_report(raw_report, default_scan_type=default_scan_type, default_target_url=target_url)


def _extract_raw_report(job_result: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(job_result, dict):
        return None

    report_payload = job_result.get("report")
    if report_payload is None and isinstance(job_result.get("response"), dict):
        report_payload = job_result["response"].get("report")

    return normalize_report(report_payload)


def _extract_auth_status(job_result: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(job_result, dict):
        return None
    status = job_result.get("auth_status")
    if status is None and isinstance(job_result.get("response"), dict):
        status = job_result["response"].get("auth_status")
    return status if isinstance(status, dict) else None


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
        return {
            "status": "failed",
            "error": scan.get("error") or "Scan failed",
            "progress": scan.get("progress_percent"),
        }

    if scan.get("status") == "finished" and scan.get("parsed_report"):
        return {
            "status": "finished",
            "result": scan["parsed_report"],
            "progress": scan.get("progress_percent", 100),
        }

    try:
        job = Job.fetch(job_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found")

    status = job.get_status()

    if status == "failed":
        error_message = "Scan job failed"
        if job.exc_info:
            error_message = job.exc_info.strip().splitlines()[-1]
        _update_scan_result(scan["id"], user_id, "failed", None, None, error_message, progress_percent=100)
        return {"status": status, "error": error_message, "progress": 100}

    if status == "finished":
        try:
            parsed = _parse_job_result(job.result)
        except Exception as exc:
            error_message = f"Failed to parse scan result: {exc}"
            _update_scan_result(scan["id"], user_id, "failed", None, None, error_message, progress_percent=100)
            return {"status": "failed", "error": error_message, "progress": 100}

        if parsed is None:
            error_message = "Scan result unavailable"
            _update_scan_result(scan["id"], user_id, "failed", None, None, error_message, progress_percent=100)
            return {"status": "failed", "error": error_message, "progress": 100}

        raw_report = _extract_raw_report(job.result)
        auth_status = _extract_auth_status(job.result)
        if isinstance(auth_status, dict):
            parsed["authStatus"] = auth_status
        _update_scan_result(scan["id"], user_id, "finished", raw_report, parsed, None, progress_percent=100)
        return {"status": status, "result": parsed, "progress": 100}

    return {
        "status": status,
        "result": None,
        "progress": scan.get("progress_percent"),
    }
