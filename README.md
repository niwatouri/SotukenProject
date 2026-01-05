# SotukenProject
vulnerability scanner

## Setup
1) `.env` に `JWT_SECRET` を設定（`login` と `backend` で共有）
2) `ZAP_SCANNER_API_KEY` を設定（設定時は backend→zap-scanner のみ許可）
3) `docker compose up --build`
4) フロントから認証APIの向き先を変える場合は `VITE_AUTH_URL` を設定（未設定時は `http://localhost:3000`）
5) `login` の依存追加後は `docker compose up --build login` で再作成
6) 既存のDBボリュームを使っている場合は、以下で新しいテーブルを反映  
   `docker compose exec db psql -U postgres -d mydb -f /docker-entrypoint-initdb.d/init.sql`
7) Docker外で `login` を動かす場合は `DB_HOST=localhost` などの `DB_*` を設定してください

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
