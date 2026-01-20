#!/usr/bin/env bash
set -euo pipefail

REPORT_PATH="${REPORT_PATH:-}"
REPORT_PATHS="${REPORT_PATHS:-}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

shopt -s nullglob

patterns=()
if [ -n "${REPORT_PATH}" ]; then
  patterns+=("${REPORT_PATH}")
elif [ -n "${REPORT_PATHS}" ]; then
  IFS=',' read -r -a patterns <<< "${REPORT_PATHS}"
else
  patterns+=("/reports/zap_report_*.json" "/reports/zap_report_*.xml" "/reports/zap_report_*.html")
fi

echo "AI container started. Waiting for report..."
start_ts=$(date +%s)

while true; do
  newest_path=""
  newest_mtime=0

  for pattern in "${patterns[@]}"; do
    for path in ${pattern}; do
      [ -f "${path}" ] || continue
      mtime=$(stat -c %Y "${path}" 2>/dev/null || echo 0)
      if [ "${mtime}" -lt "${start_ts}" ]; then
        continue
      fi
      if [ "${mtime}" -gt "${newest_mtime}" ]; then
        newest_mtime="${mtime}"
        newest_path="${path}"
      fi
    done
  done

  if [ -n "${newest_path}" ]; then
    echo "Report found: ${newest_path}"
    REPORT_PATH="${newest_path}" python3 /app/chat_to_gpt.py
    exit 0
  fi

  now_ts=$(date +%s)
  elapsed=$((now_ts - start_ts))
  if [ "${elapsed}" -ge "${WAIT_TIMEOUT}" ]; then
    echo "Timed out waiting for report after ${WAIT_TIMEOUT} seconds." >&2
    exit 2
  fi

  sleep "${POLL_INTERVAL}"
done
