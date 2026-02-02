from typing import Any, Dict, Optional

from psycopg2.extras import Json

from app.db import get_db_connection


def ensure_ai_summary(
    scan_id: int,
    alert_key: str,
    plugin_id: Optional[str],
    affected_url: Optional[str],
    parameter: Optional[str],
    status: str = "pending",
) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ai_summaries
                    (scan_id, alert_key, plugin_id, affected_url, parameter, status)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id, alert_key) DO NOTHING
                """,
                (scan_id, alert_key, plugin_id, affected_url, parameter, status),
            )


def upsert_ai_summary(
    scan_id: int,
    alert_key: str,
    status: str,
    title: Optional[str] = None,
    summary: Optional[str] = None,
    impact: Optional[str] = None,
    steps: Optional[list[str]] = None,
    analogy: Optional[str] = None,
    error_reason: Optional[str] = None,
) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ai_summaries
                    (scan_id, alert_key, status, title, summary, impact, steps, analogy, error_reason, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (scan_id, alert_key) DO UPDATE SET
                    status = EXCLUDED.status,
                    title = EXCLUDED.title,
                    summary = EXCLUDED.summary,
                    impact = EXCLUDED.impact,
                    steps = EXCLUDED.steps,
                    analogy = EXCLUDED.analogy,
                    error_reason = EXCLUDED.error_reason,
                    updated_at = NOW()
                """,
                (
                    scan_id,
                    alert_key,
                    status,
                    title,
                    summary,
                    impact,
                    Json(steps) if steps is not None else None,
                    analogy,
                    error_reason,
                ),
            )


def update_ai_summary_status(scan_id: int, alert_keys: list[str], status: str) -> None:
    if not alert_keys:
        return
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ai_summaries
                SET status = %s,
                    updated_at = NOW()
                WHERE scan_id = %s
                  AND alert_key = ANY(%s)
                """,
                (status, scan_id, alert_keys),
            )


def fetch_ai_summaries(scan_id: int) -> list[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT alert_key, status, title, summary, impact, steps, analogy, error_reason,
                       plugin_id, affected_url, parameter, updated_at
                FROM ai_summaries
                WHERE scan_id = %s
                """,
                (scan_id,),
            )
            return cur.fetchall()


def fetch_ai_summary(scan_id: int, alert_key: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT alert_key, status, title, summary, impact, steps, analogy, error_reason
                FROM ai_summaries
                WHERE scan_id = %s AND alert_key = %s
                """,
                (scan_id, alert_key),
            )
            return cur.fetchone()
