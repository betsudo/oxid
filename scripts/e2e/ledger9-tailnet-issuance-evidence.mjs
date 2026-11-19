// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const schema = "oxid-ledger9-tailnet-issuance-evidence-v1";
const bindings = {
  oxidHead: 40,
  oxidSourceSha256: 64,
  apkSha256: 64,
  signerSha256: 64,
  portalHead: 40,
  portalManifestSha256: 64,
  chainFingerprint: 64,
};
const phases = [
  "prerequisites", "custodyUpgrade", "tailnetTransport", "automaticDust",
  "nativeHolderDid", "strictIssuance", "encryptedReopen", "freshReverification",
  "refusal", "expiredOffer", "consumedOffer", "cleanup",
];
const outcomes = new Set(["passed", "failed", "unverified"]);

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((field) => Object.hasOwn(value, field));
}

export function summarizeEvidence(receipt) {
  if (!exactFields(receipt, ["schema", "bindings", "phases"]) || receipt.schema !== schema
      || !exactFields(receipt.bindings, Object.keys(bindings))
      || !exactFields(receipt.phases, phases)) {
    throw new Error("invalid Ledger 9 Tailnet receipt shape");
  }
  if (!Object.entries(bindings).every(([key, length]) => {
    const value = receipt.bindings[key];
    return typeof value === "string" && value.length === length && /^[0-9a-f]+$/u.test(value);
  }) || !phases.every((phase) => outcomes.has(receipt.phases[phase]))) {
    throw new Error("invalid Ledger 9 Tailnet receipt values");
  }
  const failed = phases.filter((phase) => receipt.phases[phase] === "failed");
  const unverified = phases.filter((phase) => receipt.phases[phase] === "unverified");
  const verdict = failed.length ? "failed" : unverified.length ? "unverified" : "ready";
  return { verdict, failed, unverified };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const [file] = process.argv.slice(2);
    if (!file || process.argv.length !== 3) throw new Error();
    const result = summarizeEvidence(JSON.parse(readFileSync(file, "utf8")));
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.verdict === "ready" ? 0 : 1;
  } catch {
    process.stderr.write("A valid private Ledger 9 Tailnet issuance receipt is required.\n");
    process.exitCode = 1;
  }
}
