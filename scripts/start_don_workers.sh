#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORCH_DIR="${ROOT_DIR}/orchestrator"
PID_DIR="${ROOT_DIR}/.pids"
PID_FILE="${PID_DIR}/don-workers.pid"
LOG_DIR="/tmp/cre-don-workers"

mkdir -p "${PID_DIR}" "${LOG_DIR}"

if [[ -f "${PID_FILE}" ]]; then
  echo "[workers] existing pid file found: ${PID_FILE}"
  echo "[workers] run scripts/stop_don_workers.sh first if workers are already running"
  exit 1
fi

NODE_IDS=("gpt" "gemini" "claude" "grok")
MODEL_NAMES=("operator-gpt" "operator-gemini" "operator-claude" "operator-grok")
BASE_PORT="${DON_WORKER_BASE_PORT:-19001}"
if ! [[ "${BASE_PORT}" =~ ^[0-9]+$ ]]; then
  echo "[workers] DON_WORKER_BASE_PORT must be numeric: ${BASE_PORT}"
  exit 1
fi
PORTS=(
  "${BASE_PORT}"
  "$((BASE_PORT + 1))"
  "$((BASE_PORT + 2))"
  "$((BASE_PORT + 3))"
)
OPERATORS=(
  "0x9C7BC14e8a4B054e98C6DB99B9f1Ea2797BAee7B"
  "0x2Efa1f0a487Ebbcbc28b64C56BBfb235Bc66C267"
  "0xd816d4987b236C45C87B74c1964700fBb274B0E5"
  "0xc43D2aaA148ba4d5f5341c9ad4799ddE85545D38"
)
PRIVATE_KEYS=(
  "0x1000000000000000000000000000000000000000000000000000000000000001"
  "0x2000000000000000000000000000000000000000000000000000000000000002"
  "0x3000000000000000000000000000000000000000000000000000000000000003"
  "0x4000000000000000000000000000000000000000000000000000000000000004"
)

echo -n "" > "${PID_FILE}"

for i in "${!NODE_IDS[@]}"; do
  node_id="${NODE_IDS[$i]}"
  model_name="${MODEL_NAMES[$i]}"
  port="${PORTS[$i]}"
  operator="${OPERATORS[$i]}"
  private_key="${PRIVATE_KEYS[$i]}"
  log_path="${LOG_DIR}/${node_id}.log"

  (
    cd "${ORCH_DIR}"
    PORT="${port}" \
      WORKER_NODE_ID="${operator}" \
      WORKER_MODEL_FAMILY="${node_id}" \
      WORKER_MODEL_NAME="${model_name}" \
      WORKER_OPERATOR_ADDRESS="${operator}" \
      WORKER_PRIVATE_KEY="${private_key}" \
      bun run src/nodeWorker.ts > "${log_path}" 2>&1 &
    echo "$!" > "${LOG_DIR}/${node_id}.pid"
  )

  pid="$(cat "${LOG_DIR}/${node_id}.pid")"
  rm -f "${LOG_DIR}/${node_id}.pid"

  if ! kill -0 "${pid}" 2>/dev/null; then
    echo "[workers] failed to start ${node_id} worker (port=${port})"
    echo "[workers] last log:"
    tail -n 20 "${log_path}" || true
    rm -f "${PID_FILE}"
    exit 1
  fi

  echo "${node_id} ${pid} ${port} ${operator}" >> "${PID_FILE}"
  echo "[workers] started ${node_id}: pid=${pid} port=${port} operator=${operator}"
done

echo ""
echo "[workers] all workers started"
echo "[workers] pid file: ${PID_FILE}"
echo "[workers] logs: ${LOG_DIR}"
echo "[workers] base port: ${BASE_PORT}"
echo ""
echo "Suggested orchestrator env:"
echo -n "  NODE_ENDPOINT_URL_MAP_JSON='"
for i in "${!NODE_IDS[@]}"; do
  wallet="${OPERATORS[$i]}"
  port="${PORTS[$i]}"
  if [[ "$i" -gt 0 ]]; then
    echo -n ","
  fi
  echo -n "\"${wallet}\":\"http://127.0.0.1:${port}\""
done
echo "'"
echo -n "  NODE_ENDPOINT_URL_BY_FAMILY_JSON='"
for i in "${!NODE_IDS[@]}"; do
  family="${NODE_IDS[$i]}"
  port="${PORTS[$i]}"
  if [[ "$i" -gt 0 ]]; then
    echo -n ","
  fi
  echo -n "\"${family}\":\"http://127.0.0.1:${port}\""
done
echo "'"
echo ""
echo "Health checks:"
for i in "${!NODE_IDS[@]}"; do
  echo "  curl http://127.0.0.1:${PORTS[$i]}/healthz"
done
echo ""
echo "Register endpoints in Verify page as:"
for i in "${!NODE_IDS[@]}"; do
  echo "  ${OPERATORS[$i]} -> http://127.0.0.1:${PORTS[$i]}"
done
