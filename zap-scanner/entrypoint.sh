#!/bin/bash
set -e

echo "Starting ZAP daemon..."
zap.sh -daemon \
    -host 0.0.0.0 \
    -port 8090 \
    -config api.key="${ZAP_API_KEY}" \
    -config api.addrs.addr.name="*" \
    -config api.addrs.addr.regex=true &

echo "Waiting for ZAP to be available..."
until curl -s "http://127.0.0.1:8090/JSON/core/view/status/?apikey=${ZAP_API_KEY}" >/dev/null; do
  sleep 1
done
echo "ZAP is ready."

# Flask API起動
source ./venv/bin/activate
python scanner.py
