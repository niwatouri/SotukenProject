import os
import time
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_NAME = os.getenv("DB_NAME", "mydb")

SCAN_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      target_url TEXT NOT NULL,
      scan_types JSONB NOT NULL,
      status TEXT NOT NULL,
      job_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      progress_percent INTEGER NOT NULL DEFAULT 0,
      error TEXT,
      raw_report JSONB,
      parsed_report JSONB
    )
    """,
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_percent INTEGER NOT NULL DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_scans_user_created_at ON scans(user_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scans_job_id ON scans(job_id)",
]


@contextmanager
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
        cursor_factory=RealDictCursor,
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_scan_schema(retries: int = 5, delay_seconds: float = 1.0) -> None:
    for attempt in range(retries):
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    for statement in SCAN_SCHEMA_STATEMENTS:
                        cur.execute(statement)
            return
        except Exception:
            if attempt >= retries - 1:
                raise
            time.sleep(delay_seconds)
