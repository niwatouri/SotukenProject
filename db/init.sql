-- db/init.sql

-- （PostgreSQLイメージ起動時に自動的に mydb が作成されているので、ここでデータベースを作る必要はありません）

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

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
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created_at ON scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_job_id ON scans(job_id);
