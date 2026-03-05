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

DEFAULT_NODE_IDS=("gpt" "gemini" "claude" "grok")
BASE_PORT="${DON_WORKER_BASE_PORT:-19001}"
if ! [[ "${BASE_PORT}" =~ ^[0-9]+$ ]]; then
  echo "[workers] DON_WORKER_BASE_PORT must be numeric: ${BASE_PORT}"
  exit 1
fi

IFS=',' read -r -a NODE_IDS <<< "${DON_WORKER_MODEL_FAMILIES:-gpt,gemini,claude,grok}"
IFS=',' read -r -a OPERATORS <<< "${DON_WORKER_OPERATOR_ADDRESSES:-}"
IFS=',' read -r -a PRIVATE_KEYS <<< "${DON_WORKER_PRIVATE_KEYS:-}"

if [[ "${#OPERATORS[@]}" -lt 4 || "${#PRIVATE_KEYS[@]}" -lt 4 ]]; then
  echo "[workers] DON_WORKER_OPERATOR_ADDRESSES and DON_WORKER_PRIVATE_KEYS must include 4 comma-separated values."
  echo "[workers] example DON_WORKER_OPERATOR_ADDRESSES=0x...,0x...,0x...,0x..."
  echo "[workers] example DON_WORKER_PRIVATE_KEYS=0x...,0x...,0x...,0x..."
  exit 1
fi

if [[ "${#NODE_IDS[@]}" -lt 4 ]]; then
  NODE_IDS=("${DEFAULT_NODE_IDS[@]}")
fi
NODE_IDS=("${NODE_IDS[@]:0:4}")
OPERATORS=("${OPERATORS[@]:0:4}")
PRIVATE_KEYS=("${PRIVATE_KEYS[@]:0:4}")

MODEL_NAMES=()
for family in "${NODE_IDS[@]}"; do
  MODEL_NAMES+=("operator-${family}")
done

PORTS=(
  "${BASE_PORT}"
  "$((BASE_PORT + 1))"
  "$((BASE_PORT + 2))"
  "$((BASE_PORT + 3))"
)

echo -n "" > "${PID_FILE}"

for i in "${!NODE_IDS[@]}"; do
  node_id="$(echo "${NODE_IDS[$i]}" | xargs)"
  model_name="$(echo "${MODEL_NAMES[$i]}" | xargs)"
  port="${PORTS[$i]}"
  operator="$(echo "${OPERATORS[$i]}" | xargs)"
  private_key="$(echo "${PRIVATE_KEYS[$i]}" | xargs)"
  log_path="${LOG_DIR}/${node_id}.log"

  if ! [[ "${operator}" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "[workers] invalid operator address at index ${i}: ${operator}"
    rm -f "${PID_FILE}"
    exit 1
  fi
  if ! [[ "${private_key}" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "[workers] invalid private key at index ${i}"
    rm -f "${PID_FILE}"
    exit 1
  fi

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
