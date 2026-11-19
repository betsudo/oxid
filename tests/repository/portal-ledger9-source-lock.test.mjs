// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const commit = "154ad777456ab40ab2f46a8b94959ae63b14a459";
const tree = "4f9952cebd0e9cc8a82ec9d459d2eadc9cce8adb";
const provenanceSha256 = "70f67a9f339ca0756ca4d10f5bef9dea769746094076288b8f571d93cb9c51fc";
const profileSourceCommit = "76e8edf394a4cb37ca822037272d543c68f25f71";
const root = new URL(`../../fixtures/laceid-portal/${commit}/`, import.meta.url);

test("Ledger 9 Portal source lock authenticates the exact merged profile evidence", async () => {
  const lock = JSON.parse(await readFile(new URL("source-lock.json", root), "utf8"));
  assert.deepEqual(lock, {
    integrationCommit: commit,
    integrationTree: tree,
    profileSourceCommit,
    provenancePath: "openid4vci-final/provenance.json",
    provenanceSha256,
    schema: "oxid-portal-source-lock-v3",
  });
  const bytes = await readFile(new URL(lock.provenancePath, root));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), provenanceSha256);

  const provenance = JSON.parse(bytes);
  assert.equal(provenance.portal.repository, "https://github.com/input-output-hk/lace-id-portal");
  assert.equal(provenance.portal.profileSourceCommit, profileSourceCommit);
  assert.deepEqual(provenance.profile, {
    credentialConfigurationId: "digital_passport_v1",
    name: "lace-id-portal-oxid-midnight-phase1",
    openid4vciVersion: "1.0 Final",
    representationFormat: "midnight_cbor_phase1",
  });
});
