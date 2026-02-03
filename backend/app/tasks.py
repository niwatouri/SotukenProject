# backend/app/tasks.py
import httpx
import json
import logging
import re
import time
from typing import Any, Dict, Optional

from openai import OpenAI
from psycopg2.extras import Json
from redis import Redis
from rq import Queue

from app.config import (
    OPENAI_API_KEY,
    OPENAI_MODEL,
    REDIS_HOST,
    REDIS_PORT,
    SCAN_TIMEOUT_SECONDS,
    ZAP_SCANNER_API_KEY,
    ZAP_SCANNER_URL,
)
from app.ai_summary_store import ensure_ai_summary, fetch_ai_summary, upsert_ai_summary
from app.db import get_db_connection
from app.report_parser import parse_zap_report
from app.scan_utils import (
    normalize_report,
    normalize_scan_types,
    scan_type_from_scan_types,
    validate_target_url,
)

logger = logging.getLogger(__name__)

AI_TECH_TERM_REPLACEMENTS: list[tuple[str, str]] = [
    (r"\bJDBC\b", "DB接続"),
    (r"\bPreparedStatement\b", "プレースホルダ/バインド変数"),
    (r"\bCallableStatement\b", "ストアドプロシージャ呼び出し"),
    (r"\bJPA\b", "ORM"),
    (r"\bHibernate\b", "ORM"),
]

# AI要約タスク用のキュー（default）
redis_conn = Redis(host=REDIS_HOST, port=REDIS_PORT)
ai_queue = Queue(connection=redis_conn, default_timeout=SCAN_TIMEOUT_SECONDS)


def _build_retry_backoff(total_wait_seconds: int) -> list[int]:
    # Spread retries across the provided wait window.
    target_total = max(2, int(total_wait_seconds))
    backoff_seconds: list[int] = []
    wait_seconds = 2
    total_wait = 0
    while total_wait + wait_seconds < target_total:
        backoff_seconds.append(wait_seconds)
        total_wait += wait_seconds
        wait_seconds = min(wait_seconds * 2, 300)
    remaining = target_total - total_wait
    if remaining > 0:
        backoff_seconds.append(remaining)
    return backoff_seconds


# Keep busy retries within a smaller window so the scan itself can still finish.
BUSY_RETRY_WINDOW_SECONDS = max(10, min(int(SCAN_TIMEOUT_SECONDS * 0.2), 900))
RETRY_BACKOFF_SECONDS = _build_retry_backoff(BUSY_RETRY_WINDOW_SECONDS)


def _post_scan_request(url, payload, headers, on_before_request=None, on_busy=None):
    last_response = None
    last_exception = None
    for wait_seconds in [0, *RETRY_BACKOFF_SECONDS]:
        if wait_seconds:
            time.sleep(wait_seconds)
        if on_before_request:
            on_before_request()
        try:
            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_exception = exc
            continue
        last_response = response
        if response.status_code == 429:
            if on_busy:
                on_busy()
            continue
        return response
    if last_response is not None and last_response.status_code == 429:
        raise RuntimeError("ZAP scanner busy after retries")
    if last_exception is not None:
        raise last_exception
    raise RuntimeError("ZAP scan failed before response")


def _update_scan_status(
    scan_id,
    user_id,
    status,
    error=None,
    raw_report=None,
    parsed_report=None,
    progress_percent=None,
    reset_started_at=False,
):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = %s,
                    started_at = CASE
                        WHEN %s = 'running' THEN COALESCE(started_at, NOW())
                        WHEN %s = 'queued' AND %s THEN NULL
                        ELSE started_at
                    END,
                    completed_at = CASE
                        WHEN %s IN ('finished', 'failed', 'stopped') THEN NOW()
                        ELSE completed_at
                    END,
                    error = %s,
                    raw_report = %s,
                    parsed_report = %s,
                    progress_percent = COALESCE(%s, progress_percent)
                WHERE id = %s AND user_id = %s
                """,
                (
                    status,
                    status,
                    status,
                    reset_started_at,
                    status,
                    error,
                    Json(raw_report) if raw_report is not None else None,
                    Json(parsed_report) if parsed_report is not None else None,
                    progress_percent,
                    scan_id,
                    user_id,
                ),
            )


def _fetch_parsed_report(scan_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT parsed_report
                FROM scans
                WHERE id = %s
                """,
                (scan_id,),
            )
            row = cur.fetchone()
            return row.get("parsed_report") if row else None


def _normalize_ai_steps(steps: Any) -> Optional[list[str]]:
    if not isinstance(steps, list):
        return None
    return [str(step) for step in steps if step is not None]


def _sanitize_ai_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    for pattern, replacement in AI_TECH_TERM_REPLACEMENTS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text.strip()


def _sanitize_ai_steps(steps: Optional[list[str]]) -> Optional[list[str]]:
    if not steps:
        return steps
    sanitized = []
    for step in steps:
        text = _sanitize_ai_text(step)
        if text:
            sanitized.append(text)
    return sanitized


def _call_ai_for_vulnerability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    if not OPENAI_API_KEY or not OPENAI_API_KEY.strip():
        raise RuntimeError("OPENAI_API_KEY is not configured")
    client = OpenAI(api_key=OPENAI_API_KEY)
    payload = json.dumps(vulnerability, ensure_ascii=False)
    system_message = (
        "あなたはセキュリティアナリストです。入力された脆弱性に対して、"
        "日本語で分かりやすい解説と改善アドバイスを生成してください。"
        "特定言語・特定フレームワーク・特定ライブラリ・特定製品名は出さず、"
        "技術非依存の一般的な対策のみを書いてください。"
        "禁止語: JDBC, PreparedStatement, CallableStatement, JPA, Hibernate。"
        "SQLi対策は「プレースホルダ/バインド変数」「ORMの安全API」「入力値の型チェック/バリデーション」"
        "「DB最小権限」「エラーメッセージ抑制」「WAFは補助」を優先して使ってください。"
        "XSS対策は「出力エスケープ」「テンプレートエンジンの自動エスケープ」"
        "「CSP」「HttpOnly/SameSite」「入力検証は補助（本質は出力）」を優先して使ってください。"
        "まず確認すべきことを1〜2行書き、その後に対策を列挙してください。"
        "冗長にせず、各項目は6〜12行程度に収めてください。"
        "出力はJSONのみで、余計な説明やMarkdownは不要です。"
    )
    user_message = (
        "以下の脆弱性に対して、必ず1件のitemsを返してください。\n"
        "出力形式:\n"
        '{"items":[{"vulnId":"<id>","title":"短いタイトル","summary":"概要(1-2文)",'
        '"impact":"影響(1-2文)","steps":["確認: ...","確認: ...","対策: ...","対策: ..."],'
        '"analogy":"わかりやすい例え"}]}\n'
        "stepsは4〜8件。最初の1〜2件は「確認:」で始め、残りは「対策:」で始めてください。\n"
        "vulnIdは入力のidをそのまま使用してください。\n"
        "脆弱性:\n"
        f"{payload}"
    )
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    if not response.choices:
        raise RuntimeError("AI response empty")
    content = response.choices[0].message.content or ""
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI response invalid JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
        raise RuntimeError("AI response invalid")
    if not parsed["items"]:
        raise RuntimeError("AI response empty items")
    item = parsed["items"][0]
    if not isinstance(item, dict):
        raise RuntimeError("AI response item invalid")
    return item


def _should_skip_vulnerability(vulnerability: Dict[str, Any]) -> bool:
    return not vulnerability.get("type") and not vulnerability.get("description")


def ai_summary_task(scan_id: int, target_alert_key: Optional[str] = None) -> None:
    parsed_report = _fetch_parsed_report(scan_id)
    if not isinstance(parsed_report, dict):
        logger.warning("ai_summary_task: parsed_report missing scan_id=%s", scan_id)
        return

    raw_vulns = parsed_report.get("vulnerabilities")
    if not isinstance(raw_vulns, list) or not raw_vulns:
        return

    targets: list[Dict[str, Any]] = []
    for vuln in raw_vulns:
        if not isinstance(vuln, dict):
            continue
        vuln_id = vuln.get("id") or vuln.get("vulnId")
        if not vuln_id:
            continue
        vuln_id_str = str(vuln_id)
        alert_key = vuln.get("alertKey") or vuln_id_str
        alert_key = str(alert_key)
        if target_alert_key and str(target_alert_key) not in {alert_key, vuln_id_str}:
            continue

        evidence = vuln.get("evidence") if isinstance(vuln.get("evidence"), dict) else {}
        plugin_id = vuln_id_str.split("-", 1)[0] if vuln_id_str else None
        affected_url = evidence.get("affected_url")
        parameter = evidence.get("parameter")

        ensure_ai_summary(
            scan_id,
            alert_key,
            plugin_id,
            affected_url,
            parameter,
            status="pending",
        )
        targets.append({
            "alert_key": alert_key,
            "vulnerability": vuln,
        })

    if not targets:
        return

    for target in targets:
        alert_key = target["alert_key"]
        vulnerability = target["vulnerability"]
        existing = fetch_ai_summary(scan_id, alert_key)
        if existing and not target_alert_key:
            existing_status = existing.get("status")
            if existing_status in {"completed", "failed", "skipped"}:
                continue
        if _should_skip_vulnerability(vulnerability):
            upsert_ai_summary(scan_id, alert_key, status="skipped")
            continue

        try:
            upsert_ai_summary(scan_id, alert_key, status="processing")
            item = _call_ai_for_vulnerability(vulnerability)
            steps = _normalize_ai_steps(item.get("steps"))
            steps = _sanitize_ai_steps(steps)
            upsert_ai_summary(
                scan_id,
                alert_key,
                status="completed",
                title=_sanitize_ai_text(item.get("title")),
                summary=_sanitize_ai_text(item.get("summary")),
                impact=_sanitize_ai_text(item.get("impact")),
                steps=steps,
                analogy=_sanitize_ai_text(item.get("analogy")),
            )
        except Exception as exc:
            reason = str(exc)
            upsert_ai_summary(
                scan_id,
                alert_key,
                status="failed",
                error_reason=reason,
            )
            continue


def zap_scan_task(
    scan_id: int,
    url: str,
    scan_types: list[str] | None,
    user_id: int,
    auth: dict | None = None,
    scan_config: dict | None = None,
):
    """
    Kick off a ZAP scan via the scanner service. Returns raw response data for later parsing.
    """
    payload_scan_types = normalize_scan_types(scan_types)
    if not payload_scan_types:
        payload_scan_types = ["all"]

    is_allowed, blocked_ip, error_code = validate_target_url(url)
    if not is_allowed:
        if blocked_ip:
            logger.warning("blocked_target ip=%s url=%s scan_id=%s user_id=%s", blocked_ip, url, scan_id, user_id)
            _update_scan_status(
                scan_id,
                user_id,
                "failed",
                error="Blocked target",
                progress_percent=100,
            )
            raise RuntimeError("Blocked target")
        _update_scan_status(
            scan_id,
            user_id,
            "failed",
            error="Invalid URL",
            progress_percent=100,
        )
        raise RuntimeError(f"Invalid URL: {error_code}")

    try:
        headers = {"X-API-Key": ZAP_SCANNER_API_KEY} if ZAP_SCANNER_API_KEY else {}
        payload = {
            "url": url,
            "scan_types": payload_scan_types,
            "auth": auth,
            "scan_id": scan_id,
            "scan_config": scan_config,
        }

        def mark_running():
            _update_scan_status(scan_id, user_id, "running", error=None, progress_percent=1)

        def mark_queued():
            _update_scan_status(
                scan_id,
                user_id,
                "queued",
                error=None,
                progress_percent=0,
                reset_started_at=True,
            )

        response = _post_scan_request(
            f"{ZAP_SCANNER_URL}/scan",
            payload,
            headers,
            on_before_request=mark_running,
            on_busy=mark_queued,
        )
        if response.status_code != 200:
            error_message = f"ZAP scan failed with status {response.status_code}"
            raise RuntimeError(error_message)
        data = response.json()
    except Exception as exc:
        _update_scan_status(scan_id, user_id, "failed", error=str(exc), progress_percent=100)
        # Propagate a concise error so the worker marks the job as failed.
        raise Exception(f"ZAP scan failed: {exc}") from exc

    raw_report = normalize_report(data.get("report"))
    auth_status = data.get("auth_status") if isinstance(data, dict) else None
    if raw_report is None:
        _update_scan_status(
            scan_id,
            user_id,
            "failed",
            error="Report payload missing or invalid",
            progress_percent=100,
        )
        raise Exception("ZAP scan failed: report payload missing or invalid")

    include_risks = None
    scope_same_host_only = False
    if isinstance(scan_config, dict):
        alert_fetch = scan_config.get("alert_fetch") if isinstance(scan_config.get("alert_fetch"), dict) else {}
        include_risks = alert_fetch.get("include_risks") if isinstance(alert_fetch, dict) else None
        scope_same_host_only = bool(scan_config.get("scope_same_host_only"))
    parsed_report = parse_zap_report(
        raw_report,
        default_scan_type=scan_type_from_scan_types(payload_scan_types),
        default_target_url=url,
        include_risks=include_risks,
        scope_same_host_only=scope_same_host_only,
    )
    if isinstance(auth_status, dict):
        parsed_report["authStatus"] = auth_status
    scan_status = data.get("scan_status") if isinstance(data, dict) else None
    scan_error = data.get("error") if isinstance(data, dict) else None
    final_status = "stopped" if scan_status == "stopped" else "finished"
    final_error = "stopped_by_timeout" if final_status == "stopped" else None
    if scan_error and final_status == "stopped":
        final_error = scan_error
    parsed_report["scanStatus"] = final_status
    if final_error:
        parsed_report["scanError"] = final_error
    _update_scan_status(
        scan_id,
        user_id,
        final_status,
        error=final_error,
        raw_report=raw_report,
        parsed_report=parsed_report,
        progress_percent=100,
    )

    try:
        ai_queue.enqueue(
            ai_summary_task,
            scan_id,
            job_timeout=SCAN_TIMEOUT_SECONDS,
            description=f"ai_summary_task(scan_id={scan_id})",
        )
    except Exception as exc:
        logger.warning("Failed to enqueue ai_summary_task scan_id=%s error=%s", scan_id, exc)

    return {
        "scan_id": scan_id,
        "url": url,
        "scan_types": payload_scan_types,
        "response": data,
        "report": data.get("report"),
        "auth_status": auth_status,
        "scan_config": scan_config,
        "scan_status": final_status,
        "error": final_error,
    }
