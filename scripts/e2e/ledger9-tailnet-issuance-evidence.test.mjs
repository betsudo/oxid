// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { summarizeEvidence } from "./ledger9-tailnet-issuance-evidence.mjs";

function receipt() {
  return {
    schema: "oxid-ledger9-tailnet-issuance-evidence-v1",
    bindings: {
      oxidHead: "a".repeat(40), oxidSourceSha256: "b".repeat(64),
      apkSha256: "c".repeat(64), signerSha256: "d".repeat(64),
      portalHead: "e".repeat(40), portalManifestSha256: "f".repeat(64),
      chainFingerprint: "1".repeat(64),
    },
    phases: {
      prerequisites: "passed", custodyUpgrade: "passed", tailnetTransport: "passed",
      automaticDust: "passed", nativeHolderDid: "passed", strictIssuance: "passed",
      encryptedReopen: "passed", freshReverification: "passed", refusal: "passed",
      expiredOffer: "passed", consumedOffer: "passed", cleanup: "passed",
    },
  };
}

test("requires every phase before reporting physical Ledger 9 readiness", () => {
  assert.deepEqual(summarizeEvidence(receipt()), { verdict: "ready", failed: [], unverified: [] });
  for (const phase of Object.keys(receipt().phases)) {
    const candidate = receipt();
    candidate.phases[phase] = "unverified";
    assert.deepEqual(summarizeEvidence(candidate), { verdict: "unverified", failed: [], unverified: [phase] });
    candidate.phases[phase] = "failed";
    assert.deepEqual(summarizeEvidence(candidate), { verdict: "failed", failed: [phase], unverified: [] });
  }
});

test("rejects missing checks, malformed bindings, and payload-shaped fields", () => {
  const missing = receipt();
  delete missing.phases.nativeHolderDid;
  assert.throws(() => summarizeEvidence(missing), /receipt shape/u);
  const extra = receipt();
  extra.phases.offer = "some payload";
  assert.throws(() => summarizeEvidence(extra), /receipt shape/u);
  const malformed = receipt();
  malformed.bindings.portalManifestSha256 = "some payload";
  assert.throws(() => summarizeEvidence(malformed), /receipt values/u);
});
