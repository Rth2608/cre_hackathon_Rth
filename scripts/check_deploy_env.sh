#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORCH_ENV_FILE="${1:-$ROOT_DIR/orchestrator/.env.railway}"
DAPP_ENV_FILE="${2:-$ROOT_DIR/dapp/.env.vercel}"

declare -A ORCH_ENV=()
declare -A DAPP_ENV=()

ERROR_COUNT=0

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "$value"
}

strip_quotes() {
  local value="$1"
  if [[ "$value" =~ ^\".*\"$ ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" =~ ^\'.*\'$ ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf "%s" "$value"
}

load_env_file() {
  local file_path="$1"
  local map_name="$2"
  if [[ ! -f "$file_path" ]]; then
    echo "[env-check] missing file: $file_path"
    exit 1
  fi

  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    local line
    line="$(trim "$raw_line")"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue
    local key="${line%%=*}"
    local value="${line#*=}"
    key="$(trim "$key")"
    value="$(trim "$value")"
    value="$(strip_quotes "$value")"
    eval "$map_name[\"\$key\"]=\"\$value\""
  done < "$file_path"
}

get_env_value() {
  local map_name="$1"
  local key="$2"
  local value=""
  eval "value=\"\${$map_name[\"\$key\"]-}\""
  printf "%s" "$value"
}

require_key() {
  local map_name="$1"
  local key="$2"
  local label="$3"
  local value
  value="$(get_env_value "$map_name" "$key")"
  if [[ -z "$value" ]]; then
    echo "[env-check] FAIL ($label): $key is required"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

is_truthy() {
  local value="${1,,}"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "on" ]]
}

validate_positive_int() {
  local map_name="$1"
  local key="$2"
  local label="$3"
  local value
  value="$(get_env_value "$map_name" "$key")"
  if [[ ! "$value" =~ ^[0-9]+$ || "$value" -le 0 ]]; then
    echo "[env-check] FAIL ($label): $key must be a positive integer"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

validate_hex_address() {
  local map_name="$1"
  local key="$2"
  local label="$3"
  local value
  value="$(get_env_value "$map_name" "$key")"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "[env-check] FAIL ($label): $key must be a valid EVM address"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

validate_private_key() {
  local map_name="$1"
  local key="$2"
  local label="$3"
  local value
  value="$(get_env_value "$map_name" "$key")"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "[env-check] FAIL ($label): $key must be 0x + 64 hex chars"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

validate_https_url() {
  local map_name="$1"
  local key="$2"
  local label="$3"
  local value
  value="$(get_env_value "$map_name" "$key")"
  if [[ "$value" != https://* ]]; then
    echo "[env-check] FAIL ($label): $key must start with https://"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

validate_orchestrator_env() {
  local label="orchestrator"
  require_key ORCH_ENV PORT "$label"
  require_key ORCH_ENV RPC_URL "$label"
  require_key ORCH_ENV CHAIN_ID "$label"
  require_key ORCH_ENV CONTRACT_ADDRESS "$label"
  require_key ORCH_ENV COORDINATOR_PRIVATE_KEY "$label"
  require_key ORCH_ENV WORLD_ID_RP_ID "$label"
  require_key ORCH_ENV WORLD_ID_VERIFY_API_V4_BASE_URL "$label"

  validate_positive_int ORCH_ENV CHAIN_ID "$label"
  validate_hex_address ORCH_ENV CONTRACT_ADDRESS "$label"
  validate_private_key ORCH_ENV COORDINATOR_PRIVATE_KEY "$label"
  validate_https_url ORCH_ENV WORLD_ID_VERIFY_API_V4_BASE_URL "$label"

  local profiles
  profiles="$(get_env_value ORCH_ENV WORLD_ID_ALLOWED_PROFILES_JSON)"
  if [[ -z "$profiles" ]]; then
    require_key ORCH_ENV WORLD_ID_APP_ID "$label"
    require_key ORCH_ENV WORLD_ID_ACTION "$label"
  fi

  local distributed
  local signed_reports
  distributed="$(get_env_value ORCH_ENV DON_DISTRIBUTED_MODE)"
  signed_reports="$(get_env_value ORCH_ENV USE_DON_SIGNED_REPORTS)"
  if is_truthy "$distributed" || is_truthy "$signed_reports"; then
    require_key ORCH_ENV DON_DOMAIN_NAME "$label"
    require_key ORCH_ENV DON_DOMAIN_VERSION "$label"
    local verifier
    verifier="$(get_env_value ORCH_ENV DON_VERIFIER_CONTRACT)"
    if [[ -z "$verifier" ]]; then
      verifier="$(get_env_value ORCH_ENV CONTRACT_ADDRESS)"
    fi
    if [[ ! "$verifier" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
      echo "[env-check] FAIL ($label): DON_VERIFIER_CONTRACT (or CONTRACT_ADDRESS) must be a valid EVM address"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi
}

validate_dapp_env() {
  local label="dapp"
  require_key DAPP_ENV VITE_API_BASE_URL "$label"
  require_key DAPP_ENV VITE_THIRDWEB_CLIENT_ID "$label"

  validate_https_url DAPP_ENV VITE_API_BASE_URL "$label"

  local mini_app_id
  local mini_action
  mini_app_id="$(get_env_value DAPP_ENV VITE_WORLD_ID_MINI_APP_ID)"
  mini_action="$(get_env_value DAPP_ENV VITE_WORLD_ID_MINI_ACTION)"
  if [[ -z "$mini_app_id" ]]; then
    mini_app_id="$(get_env_value DAPP_ENV VITE_WORLD_ID_APP_ID)"
  fi
  if [[ -z "$mini_action" ]]; then
    mini_action="$(get_env_value DAPP_ENV VITE_WORLD_ID_ACTION)"
  fi
  if [[ -z "$mini_app_id" ]]; then
    echo "[env-check] FAIL ($label): VITE_WORLD_ID_MINI_APP_ID (or VITE_WORLD_ID_APP_ID) is required"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
  if [[ -z "$mini_action" ]]; then
    echo "[env-check] FAIL ($label): VITE_WORLD_ID_MINI_ACTION (or VITE_WORLD_ID_ACTION) is required"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi

  local chain_id
  chain_id="$(get_env_value DAPP_ENV VITE_WORLDCHAIN_SEPOLIA_CHAIN_ID)"
  if [[ -n "$chain_id" && ! "$chain_id" =~ ^[0-9]+$ ]]; then
    echo "[env-check] FAIL ($label): VITE_WORLDCHAIN_SEPOLIA_CHAIN_ID must be numeric when set"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

echo "[env-check] orchestrator file: $ORCH_ENV_FILE"
echo "[env-check] dapp file: $DAPP_ENV_FILE"

load_env_file "$ORCH_ENV_FILE" ORCH_ENV
load_env_file "$DAPP_ENV_FILE" DAPP_ENV

validate_orchestrator_env
validate_dapp_env

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  echo "[env-check] FAILED with $ERROR_COUNT issue(s)."
  exit 1
fi

echo "[env-check] PASS"
