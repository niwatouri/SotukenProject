#!/bin/bash
set -e

echo "Starting ZAP daemon..."
/zap/zap.sh -daemon \
    -host 0.0.0.0 \
    -port 8090 \
    -config api.addrs.addr.name=".*" \
    -config api.addrs.addr.regex=true \
    -config api.disablekey=true \
    > /zap/logs/zap.out 2>&1 &

# Wait for ZAP
echo "Waiting for ZAP to become ready..."
until curl -s http://127.0.0.1:8090/JSON/core/view/version/ >/dev/null; do
  sleep 1
done
echo "ZAP is ready."

# Start Flask
source ./venv/bin/activate
python scanner.py
