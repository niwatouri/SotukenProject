import logging
from typing import Any, Dict, Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from psycopg2.extras import Json
from redis import Redis
from rq import Queue
from rq.job import Job

from app.ai_summary_store import (
    ensure_ai_summary,
    fetch_ai_summaries,
    fetch_ai_summary,
    upsert_ai_summary,
)
from app.config import (
    JWT_SECRET,
    REDIS_HOST,
    REDIS_PORT,
    SCAN_TIMEOUT_SECONDS,
    ZAP_SCANNER_API_KEY,
)
from app.db import get_db_connection, init_scan_schema
from app.report_parser import parse_zap_report
from app.scan_utils import normalize_report, scan_type_from_scan_types, validate_target_url
from app.scan_presets import build_scan_config, get_presets_payload
from app.tasks import ai_summary_task, zap_scan_task

app = FastAPI()
logger = logging.getLogger(__name__)


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


def _fetch_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email
                FROM users
                WHERE email = %s
                """,
                (email,),
            )
            return cur.fetchone()


def _validate_user_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid user payload")
    user = _fetch_user_by_email(str(email))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    payload["userId"] = int(user["id"])
    payload["email"] = user["email"]
    return payload


async def require_auth(request: Request) -> Dict[str, Any]:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = _verify_token(token)
    return _validate_user_payload(payload)


def _verify_scanner_key(x_api_key: Optional[str]) -> None:
    if not ZAP_SCANNER_API_KEY:
        return
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing scanner API key")
    if x_api_key != ZAP_SCANNER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid scanner API key")


def _create_scan_record(
    user_id: int,
    url: str,
    scan_types: list[str],
    status: str,
    scan_config: Optional[Dict[str, Any]] = None,
) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (user_id, target_url, scan_types, scan_config, status, started_at, progress_percent, progress_phase)
                VALUES (%s, %s, %s, %s, %s, CASE WHEN %s = 'running' THEN NOW() ELSE NULL END, %s, %s)
                RETURNING id
                """,
                (user_id, url, Json(scan_types), Json(scan_config) if scan_config else None, status, status, 0, "starting"),
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
                SELECT id, user_id, target_url, scan_types, scan_config, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report, progress_percent, progress_phase
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
                SELECT id, user_id, target_url, scan_types, scan_config, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report, progress_percent, progress_phase
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
            "alertKey": str(vuln.get("alertKey") or vuln_id),
            "type": str(vuln.get("type") or ""),
            "severity": str(vuln.get("severity") or ""),
            "port": port_value,
            "description": str(vuln.get("description") or ""),
            "impact": str(vuln.get("impact") or ""),
            "solution": str(vuln.get("solution") or ""),
            "cveId": vuln.get("cveId") or None,
            "evidence": vuln.get("evidence") or None,
        })
    return normalized


def _build_ai_targets(parsed_report: Dict[str, Any]) -> list[Dict[str, Any]]:
    raw_vulns = parsed_report.get("vulnerabilities")
    vulnerabilities = _normalize_vulnerabilities(raw_vulns)
    targets: list[Dict[str, Any]] = []
    for vuln in vulnerabilities:
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue
        evidence = vuln.get("evidence") if isinstance(vuln.get("evidence"), dict) else {}
        alert_key = vuln.get("alertKey") or vuln_id
        plugin_id = str(vuln_id).split("-", 1)[0] if vuln_id else None
        targets.append({
            "vuln": vuln,
            "vuln_id": str(vuln_id),
            "alert_key": str(alert_key),
            "plugin_id": plugin_id,
            "affected_url": evidence.get("affected_url"),
            "parameter": evidence.get("parameter"),
        })
    return targets


def _fetch_scans(user_id: int, limit: int, offset: int) -> list[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_url, scan_types, scan_config, status, job_id, created_at,
                       started_at, completed_at, error, progress_phase
                FROM scans
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (user_id, limit, offset),
            )
            return cur.fetchall()


def _fetch_latest_scan(user_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_url, scan_types, scan_config, status, job_id, created_at,
                       started_at, completed_at, error, parsed_report, progress_phase
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


def _update_scan_progress(scan_id: int, progress_percent: int, progress_phase: Optional[str] = None) -> None:
    progress_percent = max(0, min(99, int(progress_percent)))
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET progress_percent = GREATEST(progress_percent, %s),
                    progress_phase = COALESCE(%s, progress_phase),
                    started_at = COALESCE(started_at, NOW())
                WHERE id = %s AND status NOT IN ('finished', 'failed', 'stopped')
                """,
                (progress_percent, progress_phase, scan_id),
            )


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

    scan_id = data.get("scan_id")
    if scan_id is None:
        raise HTTPException(status_code=400, detail="scan_id is required")
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id must be numeric") from exc

    scan = _fetch_scan_by_id(user_id, scan_id)
    if not scan or not scan.get("parsed_report"):
        raise HTTPException(status_code=404, detail="Scan not found")

    targets = _build_ai_targets(scan["parsed_report"])
    if not targets:
        return {"items": [], "summaries": []}

    for target in targets:
        ensure_ai_summary(
            scan_id,
            target["alert_key"],
            target["plugin_id"],
            target["affected_url"],
            target["parameter"],
            status="pending",
        )

    stored = fetch_ai_summaries(scan_id)
    if stored:
        statuses = {row.get("status") for row in stored if row.get("status")}
        needs_enqueue = ("processing" not in statuses) and ("pending" in statuses)
        if needs_enqueue:
            try:
                q.enqueue(
                    ai_summary_task,
                    scan_id,
                    job_timeout=SCAN_TIMEOUT_SECONDS,
                    description=f"ai_summary_task(scan_id={scan_id})",
                )
            except Exception as exc:
                logger.warning("Failed to enqueue ai_summary_task scan_id=%s error=%s", scan_id, exc)
    stored_by_key = {row["alert_key"]: row for row in stored}

    summaries: list[Dict[str, Any]] = []
    items: list[Dict[str, Any]] = []
    for target in targets:
        vuln_id = target["vuln_id"]
        alert_key = target["alert_key"]
        stored_row = stored_by_key.get(alert_key)
        status = stored_row.get("status") if stored_row else "pending"

        payload = {
            "vulnId": vuln_id,
            "alertKey": alert_key,
            "status": status,
            "title": stored_row.get("title") if stored_row else None,
            "summary": stored_row.get("summary") if stored_row else None,
            "impact": stored_row.get("impact") if stored_row else None,
            "steps": stored_row.get("steps") if stored_row else None,
            "analogy": stored_row.get("analogy") if stored_row else None,
            "error_reason": stored_row.get("error_reason") if stored_row else None,
        }
        summaries.append(payload)
        if status == "completed":
            items.append({
                "vulnId": vuln_id,
                "alertKey": alert_key,
                "title": payload["title"],
                "summary": payload["summary"],
                "impact": payload["impact"],
                "steps": payload["steps"],
                "analogy": payload["analogy"],
            })

    return {"items": items, "summaries": summaries}


@app.post("/advice/retry")
async def retry_advice(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")

    scan_id = data.get("scan_id")
    alert_key = data.get("alert_key")
    if scan_id is None or not alert_key:
        raise HTTPException(status_code=400, detail="scan_id and alert_key are required")
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id must be numeric") from exc

    scan = _fetch_scan_by_id(user_id, scan_id)
    if not scan or not scan.get("parsed_report"):
        raise HTTPException(status_code=404, detail="Scan not found")

    targets = _build_ai_targets(scan["parsed_report"])
    target = next(
        (
            item for item in targets
            if item["alert_key"] == str(alert_key) or item["vuln_id"] == str(alert_key)
        ),
        None,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Alert not found")

    ensure_ai_summary(
        scan_id,
        target["alert_key"],
        target["plugin_id"],
        target["affected_url"],
        target["parameter"],
        status="pending",
    )

    existing = fetch_ai_summary(scan_id, target["alert_key"])
    if existing and existing.get("status") == "processing":
        raise HTTPException(status_code=409, detail="Already processing")

    upsert_ai_summary(scan_id, target["alert_key"], status="processing")

    try:
        q.enqueue(
            ai_summary_task,
            scan_id,
            target["alert_key"],
            job_timeout=SCAN_TIMEOUT_SECONDS,
            description=f"ai_summary_task(scan_id={scan_id}, alert_key={target['alert_key']})",
        )
    except Exception as exc:
        upsert_ai_summary(
            scan_id,
            target["alert_key"],
            status="failed",
            error_reason=str(exc),
        )
        raise HTTPException(status_code=500, detail="Failed to queue AI summary") from exc

    return {"status": "queued"}


@app.post("/scan-progress")
async def update_scan_progress(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _verify_scanner_key(x_api_key)
    data = await request.json()
    scan_id = data.get("scan_id")
    progress = data.get("progress_percent")
    phase = data.get("phase")
    if scan_id is None or progress is None:
        raise HTTPException(status_code=400, detail="scan_id and progress_percent are required")
    try:
        scan_id = int(scan_id)
        progress = int(progress)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="scan_id/progress_percent must be numeric") from exc
    _update_scan_progress(scan_id, progress, phase)
    return {"status": "ok"}


@app.get("/scan-presets")
def get_scan_presets(user: Dict[str, Any] = Depends(require_auth)):
    return get_presets_payload()


# --- RQタスク登録 ---
@app.post("/start-scan/")
async def start_scan(request: Request, user: Dict[str, Any] = Depends(require_auth)):
    data = await request.json()
    url = data.get("url")
    scan_types = data.get("scan_types")
    auth = data.get("auth")
    scan_config_payload = data.get("scan_config")
    user_id = user.get("userId")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user payload")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    is_allowed, blocked_ip, error_code = validate_target_url(url)
    if not is_allowed:
        if blocked_ip:
            logger.warning("blocked_target ip=%s url=%s user_id=%s", blocked_ip, url, user_id)
            raise HTTPException(status_code=403, detail="禁止されたターゲットです")
        raise HTTPException(status_code=400, detail="Invalid URL")

    if not isinstance(scan_types, list) or len(scan_types) == 0:
        scan_types = ["all"]
    
    scan_config = build_scan_config(scan_config_payload)
    scan_id = _create_scan_record(user_id, url, scan_types, "queued", scan_config)

    try:
        max_duration = scan_config.get("max_duration_seconds") if isinstance(scan_config, dict) else None
        job_timeout = max_duration if isinstance(max_duration, int) and max_duration > 0 else SCAN_TIMEOUT_SECONDS
        job = q.enqueue(
            zap_scan_task,
            scan_id,
            url,
            scan_types,
            user_id,
            auth,
            scan_config,
            job_timeout=job_timeout,
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
    scan_config = job_result.get("scan_config") or (job_result.get("response") or {}).get("scan_config")
    include_risks = None
    scope_same_host_only = False
    if isinstance(scan_config, dict):
        alert_fetch = scan_config.get("alert_fetch") if isinstance(scan_config.get("alert_fetch"), dict) else {}
        include_risks = alert_fetch.get("include_risks") if isinstance(alert_fetch, dict) else None
        scope_same_host_only = bool(scan_config.get("scope_same_host_only"))
    return parse_zap_report(
        raw_report,
        default_scan_type=default_scan_type,
        default_target_url=target_url,
        include_risks=include_risks,
        scope_same_host_only=scope_same_host_only,
    )


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


def _attach_scan_meta(parsed: Optional[Dict[str, Any]], scan: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(parsed, dict) or not isinstance(scan, dict):
        return parsed
    merged = dict(parsed)
    merged["scanStatus"] = scan.get("status")
    if scan.get("error"):
        merged["scanError"] = scan.get("error")
    if scan.get("progress_phase"):
        merged["progressPhase"] = scan.get("progress_phase")
    if scan.get("scan_config") is not None:
        merged["scanConfig"] = scan.get("scan_config")
    return merged


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

    if scan.get("status") in {"finished", "stopped"} and scan.get("parsed_report"):
        result = _attach_scan_meta(scan["parsed_report"], scan)
        return {
            "status": "finished",
            "result": result,
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
        scan_status = job.result.get("scan_status") if isinstance(job.result, dict) else None
        scan_error = job.result.get("error") if isinstance(job.result, dict) else None
        final_status = "stopped" if scan_status == "stopped" else "finished"
        final_error = "stopped_by_timeout" if final_status == "stopped" else None
        if scan_error and final_status == "stopped":
            final_error = scan_error
        parsed_with_meta = _attach_scan_meta(parsed, {**scan, "status": final_status, "error": final_error})
        _update_scan_result(scan["id"], user_id, final_status, raw_report, parsed_with_meta, final_error, progress_percent=100)
        return {"status": "finished", "result": parsed_with_meta, "progress": 100}

    return {
        "status": status,
        "result": None,
        "progress": scan.get("progress_percent"),
    }
