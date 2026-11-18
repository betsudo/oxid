// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const script = await readFile(
  new URL("../../scripts/e2e/shared-ledger9-native-did-headless-e2e.sh", import.meta.url),
  "utf8",
);
const justfile = await readFile(new URL("../../Justfile", import.meta.url), "utf8");

test("shared Ledger 9 DID lane attaches without owning stack lifecycle", () => {
  assert.match(script, /scripts\/midnight-attach\.sh/);
  assert.doesNotMatch(script, /standalone-(?:up|down|status)\.sh/);
  assert.doesNotMatch(script, /docker\s+(?:compose|stop|rm)/);
  assert.match(script, /OXID_ENABLE_LIVE_LEDGER9_DID_E2E/);
  assert.match(script, /funded_wallet_deploys_and_resolves_a_native_holder_did/);
  assert.match(script, /http:\/\/127\.0\.0\.1:9092/);
  assert.match(justfile, /^shared-ledger9-native-did-headless-e2e:/mu);
});

test("shared Ledger 9 DID lane requires authenticated generated artifacts", () => {
  assert.match(script, /#midnight-did-ledger9-zkir/);
  assert.match(script, /\/nix\/store\/\*/);
  assert.match(script, /manifest\.json/);
  assert.match(script, /OXID_MIDNIGHT_DID_ARTIFACTS_DIR/);
  assert.match(script, /process\.wait\(timeout=2_100\)/);
  assert.match(script, /os\.killpg\(process\.pid, signal\.SIGTERM\)/);
  assert.match(script, /unset OXID_PRESENTATION_ARTIFACTS_DIR/);
});
