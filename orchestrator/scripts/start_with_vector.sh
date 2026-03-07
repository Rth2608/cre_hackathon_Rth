#!/usr/bin/env bash
set -euo pipefail

VECTOR_PORT="${VECTOR_SCREENING_PORT:-9888}"
export VECTOR_SCREENING_PORT="$VECTOR_PORT"
export REQUEST_VECTOR_SYNC_ENABLED="${REQUEST_VECTOR_SYNC_ENABLED:-true}"
export REQUEST_SCREENING_HTTP_URL="${REQUEST_SCREENING_HTTP_URL:-http://127.0.0.1:${VECTOR_PORT}/screen}"
export REQUEST_VECTOR_SYNC_HTTP_URL="${REQUEST_VECTOR_SYNC_HTTP_URL:-http://127.0.0.1:${VECTOR_PORT}/upsert}"

echo "[start_with_vector] vector_screening_port=${VECTOR_SCREENING_PORT}"
echo "[start_with_vector] screening_url=${REQUEST_SCREENING_HTTP_URL}"
echo "[start_with_vector] vector_sync_url=${REQUEST_VECTOR_SYNC_HTTP_URL}"

bun run src/vectorScreeningService.ts &
VECTOR_PID=$!

cleanup() {
  if kill -0 "${VECTOR_PID}" 2>/dev/null; then
    kill "${VECTOR_PID}" 2>/dev/null || true
    wait "${VECTOR_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

bun run src/server.ts
