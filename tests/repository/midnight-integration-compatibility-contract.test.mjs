// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { auditCompatibility } from "../../scripts/check-midnight-integration-compatibility.mjs";

test("reviewed Ledger 9 wallet, native identity, shared stack, and Portal pins are explicit", () => {
  const result = auditCompatibility();
  assert.equal(result.state, "compatible");
  assert.equal(result.ledgerFamily, "ledger9");
  assert.equal(result.contractRelease, "0.5.0");
  assert.equal(result.demoReady, false, "native composition must not masquerade as qualified Portal readiness");
  assert.match(result.manifestSha256, /^[0-9a-f]{64}$/u);
});

test("a runtime compatibility-schema override cannot bypass the reviewed manifest", () => {
  assert.throws(
    () => auditCompatibility({ environment: { OXID_MIDNIGHT_COMPATIBILITY_SCHEMA: "legacy" } }),
    /runtime compatibility schema override differs/u,
  );
});

test("the shared-stack attach preflight is read-only and manifest-driven", async () => {
  const attach = await readFile(new URL("../../scripts/midnight-attach.sh", import.meta.url), "utf8");
  assert.match(attach, /config\/midnight-integration-compatibility\.json/u);
  assert.match(attach, /chain_getBlockHash/u);
  assert.match(attach, /node and indexer disagree/u);
  assert.doesNotMatch(attach, /docker compose|\bup -d\b|\bdown\b/u);
});

test("Nix consumes the same immutable Ledger 9 identity and validates ZKIR compatibility", async () => {
  const flake = await readFile(new URL("../../flake.nix", import.meta.url), "utf8");
  const manifest = JSON.parse(await readFile(
    new URL("../../config/midnight-integration-compatibility.json", import.meta.url),
    "utf8",
  ));
  const identity = manifest.wallet.nativeIdentity;
  assert.ok(flake.includes(`git+${identity.repository}?rev=${identity.revision}&ref=develop&submodules=1`));

  const derivation = await readFile(
    new URL("../../nix/packages/midnight-did-ledger9-zkir.nix", import.meta.url),
    "utf8",
  );
  assert.match(derivation, /rust-compatibility\.json/u);
  assert.match(derivation, /\.compatibility\.ledger_version/u);
  assert.match(derivation, /\.compatibility\.runtime_abi/u);
  assert.match(derivation, /\.compatibility\.ir_schema/u);
  assert.doesNotMatch(derivation, /fetchurl|midnight-did\/releases/u);
});

test("cleanup remains receipt-owned when compatibility inputs change", async () => {
  const lifecycle = await readFile(new URL("../../scripts/portal-consumer-lifecycle.sh", import.meta.url), "utf8");
  assert.match(lifecycle, /if \[ "\$OPERATION" = down \]; then[\s\S]*COMPATIBILITY_MANIFEST_SHA256=""/u);
  assert.match(lifecycle, /run_down\(\)[\s\S]*cleanup_receipt_valid \|\| cleanup_starting_receipt_valid/u);
  assert.match(lifecycle, /PREPARED_RECEIPT_SCHEMA="oxid-portal-consumer-prepared-v2"/u);
  assert.match(lifecycle, /discard_legacy_prepared_state/u);
});
