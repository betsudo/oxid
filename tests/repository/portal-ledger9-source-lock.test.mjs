// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const profileSourceCommit = "76e8edf394a4cb37ca822037272d543c68f25f71";
const sources = [
  {
    commit: "154ad777456ab40ab2f46a8b94959ae63b14a459",
    tree: "4f9952cebd0e9cc8a82ec9d459d2eadc9cce8adb",
    provenanceSha256: "70f67a9f339ca0756ca4d10f5bef9dea769746094076288b8f571d93cb9c51fc",
  },
  {
    commit: "12b4b1baef544e514e6d35c6ba8b5b18bebf611c",
    tree: "6aaa3b3cf557d6d28248269012925fd29d5f2cef",
    provenanceSha256: "1f167d0f8eb0b9db543381afba49ffd75b0c5a77a5adc949a303f90bc2a6e748",
  },
];

for (const { commit, tree, provenanceSha256 } of sources) {
  test(`Ledger 9 Portal source lock authenticates profile evidence for ${commit.slice(0, 8)}`, async () => {
    const root = new URL(`../../fixtures/laceid-portal/${commit}/`, import.meta.url);
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
}
