#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${ROOT_DIR}/.pids/don-workers.pid"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "[workers] pid file not found: ${PID_FILE}"
  exit 0
fi

while read -r node_id pid port operator; do
  if [[ -z "${pid:-}" ]]; then
    continue
  fi

  if kill -0 "${pid}" 2>/dev/null; then
    # Stop children first in case the launcher spawned a worker child process.
    pkill -TERM -P "${pid}" 2>/dev/null || true
    kill "${pid}" || true
    echo "[workers] stopped ${node_id} pid=${pid} port=${port} operator=${operator}"
  else
    echo "[workers] already stopped ${node_id} pid=${pid}"
  fi
done < "${PID_FILE}"

rm -f "${PID_FILE}"

# Safety net: terminate any orphaned worker processes not tracked by pid file.
orphan_pids="$(ps -ef | awk '/src\/nodeWorker\.ts/ && !/awk/ {print $2}')"
if [[ -n "${orphan_pids}" ]]; then
  echo "${orphan_pids}" | xargs -r kill -TERM 2>/dev/null || true
  echo "[workers] cleaned orphan nodeWorker processes"
fi

echo "[workers] done"
