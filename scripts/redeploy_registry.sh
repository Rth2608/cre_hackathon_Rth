#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/contracts"
DEFAULT_CONTRACTS_ENV="$CONTRACTS_DIR/.env"
DEFAULT_ORCH_ENV="$ROOT_DIR/orchestrator/.env"
DEAD_COORDINATOR_ADDRESS="0x000000000000000000000000000000000000dEaD"
DEFAULT_DON_ALLOWLIST_OPERATORS=(
  "0x9C7BC14e8a4B054e98C6DB99B9f1Ea2797BAee7B"
  "0x2Efa1f0a487Ebbcbc28b64C56BBfb235Bc66C267"
  "0xd816d4987b236C45C87B74c1964700fBb274B0E5"
  "0xc43D2aaA148ba4d5f5341c9ad4799ddE85545D38"
)

CONTRACTS_ENV_FILE="${CONTRACTS_ENV_FILE:-$DEFAULT_CONTRACTS_ENV}"
ORCHESTRATOR_ENV_FILE="${ORCHESTRATOR_ENV_FILE:-$DEFAULT_ORCH_ENV}"
DISABLE_OLD_CONTRACT="${DISABLE_OLD_CONTRACT:-true}"
OLD_CONTRACT_ADDRESS="${OLD_CONTRACT_ADDRESS:-}"
OLD_OWNER_PRIVATE_KEY="${OLD_OWNER_PRIVATE_KEY:-}"
DEPLOY_PROFILE="${DEPLOY_PROFILE:-legacy}" # legacy | don
AUTO_ALLOW_DON_OPERATORS="${AUTO_ALLOW_DON_OPERATORS:-true}"
DON_ALLOWLIST_OPERATORS="${DON_ALLOWLIST_OPERATORS:-}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_non_empty() {
  local key="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "Missing required value: $key" >&2
    exit 1
  fi
}

normalize_private_key() {
  local value="$1"
  if [[ "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    printf '%s' "$value"
    return
  fi
  if [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]]; then
    printf '0x%s' "$value"
    return
  fi
  echo "Invalid private key format. Use 64 hex (with or without 0x)." >&2
  exit 1
}

validate_address() {
  local key="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "Invalid address for $key: $value" >&2
    exit 1
  fi
}

address_has_code() {
  local rpc_url="$1"
  local contract_address="$2"
  local code
  code="$(cast code "$contract_address" --rpc-url "$rpc_url" 2>/dev/null || true)"
  [[ -n "$code" && "$code" != "0x" && "$code" != "0x0" ]]
}

normalize_bool() {
  local value="$1"
  case "${value,,}" in
    true|false) printf '%s' "${value,,}" ;;
    *)
      echo "Invalid boolean value: $value (use true/false)" >&2
      exit 1
      ;;
  esac
}

get_env_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    return
  fi
  sed -n "s/^${key}=//p" "$file" | head -n1
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[\\|&]/\\&/g')"

  if [[ ! -f "$file" ]]; then
    echo "${key}=${value}" >"$file"
    return
  fi

  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$file"
  fi
}

extract_contract_from_broadcast() {
  local file="$1"
  sed -n 's/.*"contractAddress":[[:space:]]*"\(0x[0-9a-fA-F]\{40\}\)".*/\1/p' "$file" | head -n1 | xargs
}

build_don_allowlist_array() {
  local raw="$1"
  local -n out_ref="$2"
  out_ref=()

  if [[ -z "$raw" ]]; then
    out_ref=("${DEFAULT_DON_ALLOWLIST_OPERATORS[@]}")
    return
  fi

  local normalized="${raw//$'\n'/,}"
  IFS=',' read -r -a maybe_addresses <<<"$normalized"
  for addr in "${maybe_addresses[@]}"; do
    local trimmed
    trimmed="$(echo "$addr" | xargs)"
    [[ -z "$trimmed" ]] && continue
    validate_address "DON_ALLOWLIST_OPERATORS" "$trimmed"
    out_ref+=("$trimmed")
  done

  if [[ "${#out_ref[@]}" -eq 0 ]]; then
    echo "DON_ALLOWLIST_OPERATORS did not contain any valid addresses." >&2
    exit 1
  fi
}

deploy_contract_with_forge() {
  local deploy_script="$1"
  local deploy_label="$2"
  local deploy_log
  deploy_log="$(mktemp)"
  local chain_id_for_rpc
  chain_id_for_rpc="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)"
  local -a forge_cmd
  forge_cmd=(
    forge script "$deploy_script"
    --rpc-url "$RPC_URL"
    --broadcast
    --private-key "$PRIVATE_KEY"
    -vvvv
  )

  # DonConsensusRegistrySkeleton has a large finalizeWithBundle signature.
  # Use via-ir for DON profile to avoid "stack too deep" compile failures.
  if [[ "$DEPLOY_PROFILE" == "don" ]]; then
    forge_cmd+=(--via-ir)
  fi

  echo "[redeploy] deploying $deploy_label" >&2
  pushd "$CONTRACTS_DIR" >/dev/null
  "${forge_cmd[@]}" | tee "$deploy_log" >&2
  popd >/dev/null

  local deployed_contract
  deployed_contract="$(sed -n -E 's/.*(Contract Address:|Deployed to:)[[:space:]]*(0x[0-9a-fA-F]{40}).*/\2/p' "$deploy_log" | tail -n1 | xargs)"

  if [[ -z "$deployed_contract" ]]; then
    local broadcast_script_dir
    broadcast_script_dir="$(basename "${deploy_script%%:*}")"
    local run_latest

    # Prefer the run-latest for the active RPC chain id to avoid mixing addresses
    # from previous deployments on other networks.
    if [[ -n "$chain_id_for_rpc" && -f "$CONTRACTS_DIR/broadcast/${broadcast_script_dir}/${chain_id_for_rpc}/run-latest.json" ]]; then
      run_latest="$CONTRACTS_DIR/broadcast/${broadcast_script_dir}/${chain_id_for_rpc}/run-latest.json"
    else
      # Fallback: pick the most recently modified run-latest.json.
      run_latest="$(
        find "$CONTRACTS_DIR/broadcast/${broadcast_script_dir}" -type f -name 'run-latest.json' \
          -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-
      )"
    fi

    if [[ -z "$run_latest" ]]; then
      rm -f "$deploy_log"
      echo "Cannot find deployment output for $deploy_script (run-latest.json)." >&2
      exit 1
    fi
    echo "[redeploy] using broadcast output: $run_latest" >&2
    deployed_contract="$(extract_contract_from_broadcast "$run_latest")"
  fi

  rm -f "$deploy_log"
  require_non_empty "NEW_CONTRACT_ADDRESS" "$deployed_contract"
  validate_address "NEW_CONTRACT_ADDRESS" "$deployed_contract"
  printf '%s' "$deployed_contract"
}

echo "[redeploy] loading env: $CONTRACTS_ENV_FILE"
if [[ ! -f "$CONTRACTS_ENV_FILE" ]]; then
  echo "contracts env not found: $CONTRACTS_ENV_FILE" >&2
  exit 1
fi

set -a
source "$CONTRACTS_ENV_FILE"
set +a

require_cmd forge
require_cmd cast

require_non_empty "RPC_URL" "${RPC_URL:-}"
require_non_empty "PRIVATE_KEY" "${PRIVATE_KEY:-}"
require_non_empty "COORDINATOR_ADDRESS" "${COORDINATOR_ADDRESS:-}"

PRIVATE_KEY="$(normalize_private_key "$PRIVATE_KEY")"
validate_address "COORDINATOR_ADDRESS" "$COORDINATOR_ADDRESS"
DEPLOY_PROFILE="${DEPLOY_PROFILE,,}"
if [[ "$DEPLOY_PROFILE" != "legacy" && "$DEPLOY_PROFILE" != "don" ]]; then
  echo "DEPLOY_PROFILE must be one of: legacy, don" >&2
  exit 1
fi
AUTO_ALLOW_DON_OPERATORS="$(normalize_bool "$AUTO_ALLOW_DON_OPERATORS")"

if [[ -z "$OLD_CONTRACT_ADDRESS" ]]; then
  OLD_CONTRACT_ADDRESS="$(get_env_value "$ORCHESTRATOR_ENV_FILE" "CONTRACT_ADDRESS")"
fi

if [[ -n "$OLD_OWNER_PRIVATE_KEY" ]]; then
  OLD_OWNER_PRIVATE_KEY="$(normalize_private_key "$OLD_OWNER_PRIVATE_KEY")"
else
  OLD_OWNER_PRIVATE_KEY="$PRIVATE_KEY"
fi

if [[ "$DISABLE_OLD_CONTRACT" == "true" && -n "$OLD_CONTRACT_ADDRESS" ]]; then
  validate_address "OLD_CONTRACT_ADDRESS" "$OLD_CONTRACT_ADDRESS"
  if address_has_code "$RPC_URL" "$OLD_CONTRACT_ADDRESS"; then
    echo "[redeploy] disabling old contract coordinator: $OLD_CONTRACT_ADDRESS"
    cast send "$OLD_CONTRACT_ADDRESS" "setCoordinator(address)" "$DEAD_COORDINATOR_ADDRESS" \
      --rpc-url "$RPC_URL" \
      --private-key "$OLD_OWNER_PRIVATE_KEY" >/dev/null
    NEW_OLD_COORDINATOR="$(cast call "$OLD_CONTRACT_ADDRESS" "coordinator()(address)" --rpc-url "$RPC_URL")"
    echo "[redeploy] old coordinator after disable: $NEW_OLD_COORDINATOR"
  else
    echo "[redeploy] skip disabling old contract: no code at $OLD_CONTRACT_ADDRESS on current RPC"
  fi
else
  echo "[redeploy] skip disabling old contract (DISABLE_OLD_CONTRACT=$DISABLE_OLD_CONTRACT)"
fi

NEW_CONTRACT_ADDRESS=""
if [[ "$DEPLOY_PROFILE" == "legacy" ]]; then
  NEW_CONTRACT_ADDRESS="$(deploy_contract_with_forge "script/Deploy.s.sol:Deploy" "MarketVerificationRegistry")"
else
  NEW_CONTRACT_ADDRESS="$(deploy_contract_with_forge "script/DeployDonConsensus.s.sol:DeployDonConsensus" "DonConsensusRegistrySkeleton")"
fi

CHAIN_ID_DETECTED="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)"

echo "[redeploy] updating orchestrator env: $ORCHESTRATOR_ENV_FILE"
set_env_value "$ORCHESTRATOR_ENV_FILE" "RPC_URL" "$RPC_URL"
set_env_value "$ORCHESTRATOR_ENV_FILE" "CONTRACT_ADDRESS" "$NEW_CONTRACT_ADDRESS"
if [[ -n "$CHAIN_ID_DETECTED" ]]; then
  set_env_value "$ORCHESTRATOR_ENV_FILE" "CHAIN_ID" "$CHAIN_ID_DETECTED"
fi
set_env_value "$ORCHESTRATOR_ENV_FILE" "ONCHAIN_READ_ENABLED" "true"
set_env_value "$ORCHESTRATOR_ENV_FILE" "ONCHAIN_READ_STRICT" "true"
set_env_value "$ORCHESTRATOR_ENV_FILE" "POR_ONCHAIN_READ_ENABLED" "true"
set_env_value "$ORCHESTRATOR_ENV_FILE" "POR_ONCHAIN_READ_STRICT" "false"
set_env_value "$ORCHESTRATOR_ENV_FILE" "POR_ONCHAIN_AUTO_RECORD_ENABLED" "true"
set_env_value "$ORCHESTRATOR_ENV_FILE" "POR_ONCHAIN_AUTO_RECORD_STRICT" "false"
if [[ "$DEPLOY_PROFILE" == "don" ]]; then
  set_env_value "$ORCHESTRATOR_ENV_FILE" "DON_VERIFIER_CONTRACT" "$NEW_CONTRACT_ADDRESS"
  set_env_value "$ORCHESTRATOR_ENV_FILE" "USE_DON_SIGNED_REPORTS" "true"
  set_env_value "$ORCHESTRATOR_ENV_FILE" "USE_DON_BUNDLE_FINALIZE" "true"
else
  set_env_value "$ORCHESTRATOR_ENV_FILE" "USE_DON_SIGNED_REPORTS" "false"
  set_env_value "$ORCHESTRATOR_ENV_FILE" "USE_DON_BUNDLE_FINALIZE" "false"
fi
set_env_value "$ORCHESTRATOR_ENV_FILE" "NODE_LIFECYCLE_ONCHAIN_ENABLED" "true"

if [[ "$DEPLOY_PROFILE" == "don" && "$AUTO_ALLOW_DON_OPERATORS" == "true" ]]; then
  declare -a DON_OPERATORS_TO_ALLOW=()
  build_don_allowlist_array "$DON_ALLOWLIST_OPERATORS" DON_OPERATORS_TO_ALLOW
  echo "[redeploy] allowing DON operators onchain (${#DON_OPERATORS_TO_ALLOW[@]}):"
  for op in "${DON_OPERATORS_TO_ALLOW[@]}"; do
    echo "  - $op"
    cast send "$NEW_CONTRACT_ADDRESS" "setOperatorPermission(address,bool)" "$op" true \
      --rpc-url "$RPC_URL" \
      --private-key "$PRIVATE_KEY" >/dev/null
  done
fi

echo
echo "[redeploy] done"
echo "DEPLOY_PROFILE=$DEPLOY_PROFILE"
echo "NEW_CONTRACT_ADDRESS=$NEW_CONTRACT_ADDRESS"
echo "COORDINATOR_ADDRESS=$COORDINATOR_ADDRESS"
echo
echo "Verify:"
echo "  cast call $NEW_CONTRACT_ADDRESS \"owner()(address)\" --rpc-url \"\$RPC_URL\""
echo "  cast call $NEW_CONTRACT_ADDRESS \"coordinator()(address)\" --rpc-url \"\$RPC_URL\""
if [[ "$DEPLOY_PROFILE" == "don" ]]; then
  echo "  cast call $NEW_CONTRACT_ADDRESS \"operatorAllowlist(address)(bool)\" ${DEFAULT_DON_ALLOWLIST_OPERATORS[0]} --rpc-url \"\$RPC_URL\""
fi
echo
echo "Reminder: orchestrator/.env 의 COORDINATOR_PRIVATE_KEY가 COORDINATOR_ADDRESS와 동일한 지갑인지 확인하세요."
