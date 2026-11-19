#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Read-only attach preflight for the designated owner's shared Ledger 9 stack.
# This script never starts, stops, or mutates Docker services.
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly manifest="$root/config/midnight-integration-compatibility.json"

fail() {
  printf 'Midnight attach: %s\n' "$1" >&2
  exit 1
}

for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

value() { jq -er "$1" "$manifest"; }
readonly node_rpc="$(value '.sharedStack.nodeRpcUrl')"
readonly indexer_http="$(value '.sharedStack.indexerHttpUrl')"
readonly indexer_ws="$(value '.sharedStack.indexerWsUrl')"
readonly prover="$(value '.sharedStack.proofServerUrl')"
readonly expected_node="$(value '.sharedStack.nodeRelease')"
readonly expected_protocol="$(value '.wallet.ledger.protocolVersion')"
readonly expected_prover="$(value '.sharedStack.proofServerRelease')"
readonly network_id="$(value '.sharedStack.networkId')"

request() {
  curl --noproxy '*' --fail --silent --show-error --max-time 4 "$@"
}

rpc() {
  local payload
  payload="$(jq -cn --arg method "$1" --argjson params "$2" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
  request -H 'Content-Type: application/json' --data "$payload" "$node_rpc" \
    | jq -er 'select(.error == null) | .result'
}

node_version="$(rpc system_version '[]')" || fail 'node RPC is unavailable'
[[ "$node_version" == "$expected_node" || "$node_version" == "$expected_node"-* ]] \
  || fail "unexpected node version: $node_version"
genesis="$(rpc chain_getBlockHash '[0]')" || fail 'node genesis is unavailable'
[[ "$genesis" =~ ^0x[[:xdigit:]]{64}$ ]] || fail 'invalid genesis hash'

indexed="$(request -H 'Content-Type: application/json' \
  --data '{"query":"{ block { height hash protocolVersion } }"}' "$indexer_http" \
  | jq -ce --argjson protocol "$expected_protocol" '
      select(.errors == null) | .data.block
      | select(.protocolVersion == $protocol
          and (.height | type == "number" and . > 0 and . == floor)
          and (.hash | test("^[0-9a-f]{64}$")))
    ')" || fail 'indexer has no current Ledger 9 block'
height="$(jq -r '.height' <<<"$indexed")"
hash="$(jq -r '.hash' <<<"$indexed")"
node_hash="$(rpc chain_getBlockHash "[$height]")" || fail 'node could not resolve the indexer block'
[[ "$node_hash" == "0x$hash" ]] || fail 'node and indexer disagree at the indexed height'

proof_version="$(request "$prover/version")" || fail 'proof server is unavailable'
[[ "$proof_version" == "$expected_prover" ]] || fail "unexpected proof server version: $proof_version"

jq -n \
  --arg networkId "$network_id" \
  --arg node "$node_rpc" \
  --arg indexer "$indexer_http" \
  --arg ws "$indexer_ws" \
  --arg prover "$prover" \
  --arg nodeVersion "$node_version" \
  --arg proofVersion "$proof_version" \
  --arg genesis "$genesis" \
  --arg hash "$node_hash" \
  --argjson protocolVersion "$expected_protocol" \
  --argjson height "$height" \
  '{schema:"oxid-midnight-ledger9-attach-v1",networkId:$networkId,
    releases:{node:$nodeVersion,proofServer:$proofVersion,protocolVersion:$protocolVersion},
    urls:{nodeRpcUrl:$node,indexerHttpUrl:$indexer,indexerWsUrl:$ws,proofServerUrl:$prover},
    genesisHash:$genesis,indexedBlock:{height:$height,hash:$hash}}'
