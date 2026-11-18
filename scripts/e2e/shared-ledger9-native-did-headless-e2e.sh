#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ "${OXID_ENABLE_LIVE_LEDGER9_DID_E2E:-}" != "1" ]]; then
  echo "Set OXID_ENABLE_LIVE_LEDGER9_DID_E2E=1 to authorize the shared Ledger 9 DID run." >&2
  exit 1
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
resolver_url="${OXID_MIDNIGHT_DID_RESOLVER_URL:-http://127.0.0.1:9092}"

if [ "$resolver_url" != "http://127.0.0.1:9092" ]; then
  echo "The local qualification accepts only the reviewed loopback DID resolver." >&2
  exit 1
fi

for command_name in cargo curl jq python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command '$command_name' is missing." >&2
    exit 1
  }
done

nix_bin="$(command -v nix 2>/dev/null || true)"
if [ -z "$nix_bin" ] && [ -x /nix/var/nix/profiles/default/bin/nix ]; then
  nix_bin=/nix/var/nix/profiles/default/bin/nix
fi
[ -n "$nix_bin" ] || {
  echo "Required command 'nix' is missing." >&2
  exit 1
}

"$repository_root/scripts/midnight-attach.sh" >/dev/null
curl --fail --silent --show-error --connect-timeout 2 --max-time 5 \
  "$resolver_url/health" >/dev/null

artifacts="${OXID_MIDNIGHT_DID_ARTIFACTS_DIR:-}"
if [ -z "$artifacts" ]; then
  artifacts="$(
    "$nix_bin" build "$repository_root#midnight-did-ledger9-zkir" \
      --no-link --print-out-paths
  )"
fi
if [[ "$artifacts" != /nix/store/* ]] || [ ! -d "$artifacts" ] \
  || [ -L "$artifacts" ] || [ ! -f "$artifacts/manifest.json" ]; then
  echo "Authenticated Ledger 9 DID artifacts are unavailable." >&2
  exit 1
fi

export OXID_ENABLE_LIVE_STANDALONE_FAUCET_E2E=1
export OXID_MIDNIGHT_DID_ARTIFACTS_DIR="$artifacts"
export OXID_MIDNIGHT_DID_RESOLVER_URL="$resolver_url"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
# This lane qualifies DID publication, not presentation proving. The Nix shell
# may carry a separately versioned presentation artifact closure; never let an
# unrelated ambient artifact participate in this exact qualification.
unset OXID_PRESENTATION_ARTIFACTS_DIR

python3 - \
  cargo test -p oxid-headless --features standalone-faucet \
  --test standalone_faucet_live \
  funded_wallet_deploys_and_resolves_a_native_holder_did \
  -- --ignored --exact --nocapture <<'PY'
import os
import signal
import subprocess
import sys

command = sys.argv[1:]
process = subprocess.Popen(command, start_new_session=True)
try:
    raise SystemExit(process.wait(timeout=2_100))
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    print("Ledger 9 DID qualification exceeded its 35-minute budget.", file=sys.stderr)
    raise SystemExit(124)
PY
