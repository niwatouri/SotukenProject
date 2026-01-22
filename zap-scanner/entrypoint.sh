#!/bin/bash
set -e

echo "Starting ZAP daemon..."
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS} -Djdk.tls.client.protocols=TLSv1,TLSv1.1,TLSv1.2,TLSv1.3 -Dhttps.protocols=TLSv1,TLSv1.1,TLSv1.2,TLSv1.3"
zap.sh -daemon \
    -host 0.0.0.0 \
    -port 8090 \
    -config api.key="${ZAP_API_KEY}" \
    -config api.addrs.addr.name=".*" \
    -config api.addrs.addr.regex=true &

echo "Waiting for ZAP to be available..."
until curl -s "http://127.0.0.1:8090/JSON/core/view/status/?apikey=${ZAP_API_KEY}" >/dev/null; do
  sleep 1
done
echo "ZAP is ready."

# Flask API起動
source ./venv/bin/activate
python scanner.py
