# SotukenProject
vulnerability scanner

## Setup
フロントは `/api` 経由でバックエンドに接続します。外部APIに切り替える場合は、到達可能な絶対URLを使用してください。
※ `OPENAI_API_KEY` は環境変数で設定（`.env` はローカル専用・リポジトリに含めない）。漏洩したキーは必ず再発行/ローテーションしてください。
1) `.env` に `JWT_SECRET` を必ず設定（`login` と `backend` で共通。未設定/空は起動失敗、`dev-secret` フォールバックなし）  
   例: `openssl rand -hex 32`
2) `ZAP_SCANNER_API_KEY` を設定（設定時は backend→zap-scanner のみ許可）
3) `docker compose up --build`
4) フロントから認証APIの向き先を変える場合は `VITE_AUTH_URL` を設定（未設定時は `http://localhost:3000`）
5) フロントのバックエンドAPIの向き先を変える場合は `VITE_API_URL` を設定（未設定時は `/api` プロキシを利用）
6) `login` の依存追加後は `docker compose up --build login` で再作成
7) 既存のDBボリュームを使っている場合は、以下で新しいテーブルを反映  
   `docker compose exec db psql -U postgres -d mydb -f /docker-entrypoint-initdb.d/init.sql`
8) Docker外で `login` / `backend` を動かす場合は、同一の `JWT_SECRET` と `DB_*` を設定してください

注意: `VITE_API_URL` はビルド時に埋め込まれるため、Dockerビルド時に値を渡してください。絶対URLを指定する場合は、バックエンドのCORS許可も必要です。

## Docker外で個別起動する場合
`JWT_SECRET` は `login` と `backend` で必ず同一値にしてください。
例 (値はプレースホルダ):
```bash
export JWT_SECRET="replace-with-same-secret"
export JWT_EXPIRES_IN="1h"
export DB_HOST="localhost"
export DB_USER="postgres"
export DB_PASSWORD="postgres"
export DB_NAME="mydb"
export DB_PORT="5432"
```

## Scaling (zap-scanner)
- 同時実行は `zap-scanner` のスケール数に依存します（1インスタンス=1スキャン）
- 例: 最大5件まで同時処理したい場合
  `docker compose up --build --scale zap-scanner=5 --scale worker=5`
- 1インスタンスに複数リクエストが来た場合は `429 (scanner busy)` を返します

## Auth / API
- `POST /register` / `POST /login` は `{ token, user: { userId, email } }` を返します
- `GET /me` は `Authorization: Bearer <token>` でログイン状態を確認します
- バックエンドの以下エンドポイントは認証必須です  
  `/start-scan/`, `/scan-result/{job_id}`, `/report`, `/advice`
- スキャン履歴API  
  `GET /scans` / `GET /scans/{scan_id}`

### curl 例
```bash
# login
curl -s http://localhost:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"password123"}'

# backend (token を Authorization にセット)
curl -s http://localhost:8000/start-scan/ \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"url":"https://example.com","scan_type":"bulk","scan_types":["all"]}'
```
