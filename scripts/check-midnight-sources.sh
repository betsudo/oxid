#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

for tool in cargo jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required; run this check from 'nix develop'." >&2
    exit 1
  }
done

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly manifest="$root/config/midnight-integration-compatibility.json"
source_for() {
  local component="$1"
  jq -er --arg component "$component" '
    .wallet[$component] | "git+\(.repository)?rev=\(.revision)"
  ' "$manifest"
}

readonly ledger_source="$(source_for ledger)"
readonly compact_source="$(source_for compact)"
readonly proofs_source="$(source_for proofs)"
readonly zkir_source="$(source_for zkir)"
readonly identity_source="$(source_for nativeIdentity)"
readonly -a reviewed_sources=(
  "$ledger_source"
  "$compact_source"
  "$proofs_source"
  "$zkir_source"
  "$identity_source"
)

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --locked --format-version 1 >"$metadata_file"

# Historical event decoders may coexist only under exact, optional aliases in
# the wallet adapter. They are not the native runtime, DID, or prover source.
if ! jq -e --slurpfile policy "$manifest" '
  $policy[0].wallet.historicalReplay as $legacy
  | ([.workspace_members[] as $member
       | .packages[] | select(.id == $member)
       | .name as $owner | .dependencies[]
       | select((.rename // "") | startswith("midnight-legacy-"))
       | . + { owner: $owner }]) as $dependencies
  | (($dependencies | map(.name) | sort) == ($legacy.packages | keys | sort))
    and all($dependencies[];
      .owner == $legacy.owner
      and .optional
      and .path == null
      and .source == $legacy.registry
      and .req == ("=" + $legacy.packages[.name])
      and .rename == ("midnight-legacy-" + (.name | ltrimstr("midnight-")))
    )
    and any(.packages[];
      .name == $legacy.owner
      and ((.features[$legacy.feature] | sort)
        == ($dependencies | map("dep:" + .rename) | sort))
      and ((.features.default // []) | index($legacy.feature) | not)
    )
' "$metadata_file" >/dev/null; then
  echo "Ledger 8 replay requires exact optional registry aliases scoped to the Midnight wallet adapter." >&2
  exit 1
fi

direct_count=0
while IFS=$'\t' read -r package rename source path; do
  [ -n "$package" ] || continue
  direct_count=$((direct_count + 1))
  case "$rename" in
    midnight-legacy-*) continue ;;
  esac
  case "$package" in
    midnight-ledger|midnight-storage-core)
      echo "$package may be used directly only through a reviewed historical replay alias." >&2
      exit 1
      ;;
    midnight-ledger-v9|midnight-zswap|midnight-onchain-runtime|midnight-serialize|\
      midnight-base-crypto|midnight-coin-structure|midnight-onchain-state|\
      midnight-storage|midnight-transient-crypto)
      expected_source="$ledger_source"
      ;;
    midnight-zkir)
      if [ "$rename" = midnight-zkir-v2 ]; then
        expected_source="$ledger_source"
      else
        expected_source="$zkir_source"
      fi
      ;;
    midnight-compact-runtime)
      expected_source="$compact_source"
      ;;
    midnight-did-domain|midnight-did-jubjub-schnorr|midnight-did-runtime|midnight-vc-proof)
      expected_source="$identity_source"
      ;;
    *)
      continue
      ;;
  esac
  if [ "$path" != "-" ]; then
    echo "$package must not use a local path dependency ($path)." >&2
    exit 1
  fi
  if [ "$source" != "$expected_source" ]; then
    echo "$package must use the reviewed immutable source $expected_source." >&2
    exit 1
  fi
  revision="${source#*?rev=}"
  revision="${revision%%&*}"
  if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "$package must pin a full 40-character Git commit (found '$revision')." >&2
    exit 1
  fi
  if [ "$package" = midnight-ledger-v9 ] && [ "$rename" != midnight-ledger ]; then
    echo "midnight-ledger-v9 must remain exposed through the midnight-ledger workspace alias." >&2
    exit 1
  fi
done < <(
  jq -r '
    [.workspace_members[] as $member | .packages[] | select(.id == $member) | .dependencies[]]
    | .[]
    | select(.name | startswith("midnight-"))
    | [.name, (.rename // "-"), (.source // "-"), (.path // "-")]
    | @tsv
  ' "$metadata_file"
)

# Check every Git-backed Midnight package, including transitive packages, so a
# second repository or revision cannot enter through an indirect dependency.
while IFS=$'\t' read -r package version source; do
  [ -n "$package" ] || continue
  admitted=false
  for reviewed in "${reviewed_sources[@]}"; do
    if [[ "$source" == "$reviewed"#* ]]; then
      admitted=true
      break
    fi
  done
  if [ "$admitted" != true ]; then
    echo "$package $version uses unreviewed Midnight Git source $source." >&2
    exit 1
  fi
done < <(jq -r '
  .packages[]
  | select((.name | startswith("midnight-")) and ((.source // "") | startswith("git+")))
  | [.name, .version, .source] | @tsv
' "$metadata_file")

for legacy_revision in \
  8655615e7c4cbf3a1187b3203bf72e69dc09b8dc \
  32e314770da10cc62dab30dcfeb340ec4c6bcb64 \
  532629b044a88473a7175f4a96c2511c91156136 \
  fcf3c51cb9368a3e7574f06f82434f92386d0a2b; do
  if jq -e --arg revision "$legacy_revision" '
    any(.packages[]; (.source // "") | contains($revision))
  ' "$metadata_file" >/dev/null; then
    echo "Ledger 8 source $legacy_revision remains in the selected production graph." >&2
    exit 1
  fi
done

if ! jq -e --arg ledger "$ledger_source" '
  ([.packages[] | select(.name == "midnight-ledger-v9" and (.version == "1.0.2") and (.source | startswith($ledger)))] | length == 1)
  and ([.packages[] | select(.name == "midnight-zswap" and (.version == "9.0.1") and (.source | startswith($ledger)))] | length == 1)
' "$metadata_file" >/dev/null; then
  echo "Ledger 9 and Zswap packages do not match the reviewed cohort." >&2
  exit 1
fi

if ! jq -e --arg compact "$compact_source" --arg identity "$identity_source" '
  ([.packages[] | select(.name == "midnight-compact-runtime" and (.source | startswith($compact)))] | length == 1)
  and ([.packages[] | select(.name | test("^midnight-did-(domain|jubjub-schnorr|method|runtime)$"))]
       | length == 4 and all(.source | startswith($identity)))
' "$metadata_file" >/dev/null; then
  echo "Compact runtime and Midnight DID packages differ from the reviewed Ledger 9 sources." >&2
  exit 1
fi

git_midnight_count="$(jq '[.packages[] | select((.name | startswith("midnight-")) and ((.source // "") | startswith("git+")))] | length' "$metadata_file")"
echo "Midnight Git source rules passed for $direct_count direct dependencies and $git_midnight_count reviewed Ledger 9 cohort packages."
