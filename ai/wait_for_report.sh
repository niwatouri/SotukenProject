#!/usr/bin/env bash
set -euo pipefail

REPORT_PATH="${REPORT_PATH:-}"
REPORT_PATHS="${REPORT_PATHS:-}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

paths=()

if [ -n "${REPORT_PATH}" ]; then
  paths+=("${REPORT_PATH}")
elif [ -n "${REPORT_PATHS}" ]; then
  IFS=',' read -r -a paths <<< "${REPORT_PATHS}"
else
  paths+=("/reports/zap_report.json" "/reports/zap_report.xml" "/reports/zap_report.html")
fi

echo "AI container started. Waiting for report..."
start_ts=$(date +%s)

while true; do
  for path in "${paths[@]}"; do
    if [ -f "${path}" ]; then
      echo "Report found: ${path}"
      REPORT_PATH="${path}" python3 /app/chat_to_gpt.py
      exit 0
    fi
  done

  now_ts=$(date +%s)
  elapsed=$((now_ts - start_ts))
  if [ "${elapsed}" -ge "${WAIT_TIMEOUT}" ]; then
    echo "Timed out waiting for report after ${WAIT_TIMEOUT} seconds." >&2
    exit 2
  fi

  sleep "${POLL_INTERVAL}"
done
