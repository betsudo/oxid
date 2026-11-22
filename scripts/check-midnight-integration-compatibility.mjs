#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(root, "config", "midnight-integration-compatibility.json");

function fail(message) {
  throw new Error(`midnight integration compatibility: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function git(checkout, args) {
  return execFileSync("git", ["-C", checkout, ...args], { encoding: "utf8" }).trim();
}

function assertFullRevision(value, label) {
  if (!/^[0-9a-f]{40}$/u.test(value)) fail(`${label} must be a full immutable Git revision`);
}

function dependencyLine(cargo, name) {
  return cargo.split("\n").find((line) => line.startsWith(`${name} = {`));
}

function assertDependency(cargo, name, { repository, revision, version, packageName }) {
  const line = dependencyLine(cargo, name);
  if (!line) fail(`${name} dependency is missing`);
  if (!line.includes(`git = "${repository}"`) || !line.includes(`rev = "${revision}"`)) {
    fail(`${name} does not use the reviewed immutable source`);
  }
  if (!line.includes(`version = "=${version}"`)) fail(`${name} version differs from the reviewed cohort`);
  if (packageName && !line.includes(`package = "${packageName}"`)) fail(`${name} package alias differs from the reviewed cohort`);
}

export function auditCompatibility({ portalSource, environment = process.env } = {}) {
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  if (manifest.schema !== "oxid-midnight-integration-compatibility-v2") fail("unsupported manifest schema");
  if (manifest.wallet.ledgerFamily !== "ledger9") fail("wallet graph is not Ledger 9");
  if (manifest.demoReadiness.outOfBandHolderPublicationAllowed !== false) {
    fail("out-of-band holder publication must remain forbidden");
  }

  for (const [label, component] of Object.entries({
    ledger: manifest.wallet.ledger,
    compact: manifest.wallet.compact,
    proofs: manifest.wallet.proofs,
    zkir: manifest.wallet.zkir,
    identity: manifest.wallet.nativeIdentity,
  })) assertFullRevision(component.revision, label);

  const cargo = readFileSync(path.join(root, "Cargo.toml"), "utf8");
  if (!cargo.includes(`rust-version = "${manifest.rust.minimumVersion}"`)) fail("Cargo MSRV differs from the reviewed cohort");
  const toolchain = readFileSync(path.join(root, "rust-toolchain.toml"), "utf8");
  if (!toolchain.includes(`channel = "${manifest.rust.channel}"`)) fail("Rust toolchain differs from the reviewed cohort");

  const ledger = manifest.wallet.ledger;
  for (const [name, version] of [
    ["midnight-base-crypto", "1.1.1"],
    ["midnight-coin-structure", "3.0.1"],
    ["midnight-onchain-runtime", "4.0.1"],
    ["midnight-onchain-state", "4.0.1"],
    ["midnight-serialize", "1.2.1"],
    ["midnight-storage", "3.1.0"],
    ["midnight-transient-crypto", "3.1.0"],
    ["midnight-zswap", "9.0.1"],
  ]) assertDependency(cargo, name, { repository: ledger.repository, revision: ledger.revision, version });
  assertDependency(cargo, "midnight-ledger", {
    repository: ledger.repository,
    revision: ledger.revision,
    version: ledger.packageVersion,
    packageName: ledger.package,
  });

  const compact = manifest.wallet.compact;
  assertDependency(cargo, "midnight-compact-runtime", {
    repository: compact.repository,
    revision: compact.revision,
    version: compact.runtimeVersion,
  });
  const zkir = manifest.wallet.zkir;
  assertDependency(cargo, "midnight-zkir", {
    repository: zkir.repository,
    revision: zkir.revision,
    version: zkir.packageVersion,
  });
  const identity = manifest.wallet.nativeIdentity;
  for (const name of ["midnight-did-domain", "midnight-did-jubjub-schnorr", "midnight-did-runtime", "midnight-vc-proof"]) {
    assertDependency(cargo, name, {
      repository: identity.repository,
      revision: identity.revision,
      version: identity.packageVersion,
    });
  }

  const flake = readFileSync(path.join(root, "flake.nix"), "utf8");
  if (!flake.includes(`git+${identity.repository}?rev=${identity.revision}&ref=develop&submodules=1`)) {
    fail("Nix identity source differs from the reviewed Ledger 9 cohort");
  }
  const flakeLock = JSON.parse(readFileSync(path.join(root, "flake.lock"), "utf8"));
  const identityLock = flakeLock.nodes?.["midnight-identity-ledger9"];
  if (identityLock?.flake !== false
    || identityLock?.locked?.type !== "git"
    || identityLock?.locked?.url !== identity.repository
    || identityLock?.locked?.submodules !== true
    || identityLock?.locked?.ref !== "develop"
    || identityLock?.locked?.rev !== identity.revision) {
    fail("Nix identity lock differs from the reviewed Ledger 9 cohort");
  }
  const zkirPackage = readFileSync(path.join(root, "nix", "packages", "midnight-did-ledger9-zkir.nix"), "utf8");
  if (!zkirPackage.includes(".compatibility.ledger_version")
    || !zkirPackage.includes(".compatibility.runtime_abi")
    || !zkirPackage.includes(".compatibility.ir_schema")) {
    fail("Nix DID ZKIR package does not validate the Ledger 9 compatibility contract");
  }

  const lock = readFileSync(path.join(root, "Cargo.lock"), "utf8");
  for (const legacyRevision of [
    "8655615e7c4cbf3a1187b3203bf72e69dc09b8dc",
    "32e314770da10cc62dab30dcfeb340ec4c6bcb64",
    "532629b044a88473a7175f4a96c2511c91156136",
    "fcf3c51cb9368a3e7574f06f82434f92386d0a2b",
  ]) {
    if (cargo.includes(legacyRevision) || lock.includes(legacyRevision)) fail("Ledger 8 source remains in the production dependency graph");
  }
  for (const revision of [ledger.revision, compact.revision, manifest.wallet.proofs.revision, zkir.revision, identity.revision]) {
    if (!lock.includes(revision)) fail("lockfile is missing a reviewed Ledger 9 cohort revision");
  }

  const shared = manifest.sharedStack;
  if (shared.nodeRpcUrl !== "http://127.0.0.1:9944"
    || shared.indexerHttpUrl !== "http://127.0.0.1:8088/api/v4/graphql"
    || shared.indexerWsUrl !== "ws://127.0.0.1:8088/api/v4/graphql/ws"
    || shared.proofServerUrl !== "http://127.0.0.1:6300") {
    fail("shared Ledger 9 stack endpoints differ from the reviewed attach contract");
  }
  if (environment.OXID_MIDNIGHT_COMPATIBILITY_SCHEMA
    && environment.OXID_MIDNIGHT_COMPATIBILITY_SCHEMA !== manifest.schema) {
    fail("runtime compatibility schema override differs from the reviewed manifest");
  }

  const lifecycle = readFileSync(path.join(root, "scripts", "portal-consumer-lifecycle.sh"), "utf8");
  for (const [label, expected] of [
    ["Portal commit", `PORTAL_COMMIT="${manifest.portal.commit}"`],
    ["Portal tree", `PORTAL_TREE="${manifest.portal.tree}"`],
    ["Portal repository", `PORTAL_REMOTE="${manifest.portal.repository}"`],
  ]) if (!lifecycle.includes(expected)) fail(`${label} does not match the reviewed manifest`);

  if (portalSource) {
    if (git(portalSource, ["remote", "get-url", "origin"]) !== manifest.portal.repository) fail("Portal repository differs");
    if (git(portalSource, ["rev-parse", "HEAD"]) !== manifest.portal.commit) fail("Portal commit differs");
    if (git(portalSource, ["rev-parse", "HEAD^{tree}"]) !== manifest.portal.tree) fail("Portal tree differs");
    if (git(portalSource, ["status", "--porcelain", "--untracked-files=all"]) !== "") fail("Portal checkout is dirty");
  }

  return {
    schema: "oxid-midnight-integration-compatibility-result-v2",
    state: "compatible",
    ledgerFamily: manifest.wallet.ledgerFamily,
    contractRelease: manifest.contractRelease,
    manifestSha256: sha256(manifestBytes),
    demoReady: manifest.demoReadiness.nativeHolderDidImplemented === true
      && manifest.demoReadiness.portalUnderstandsNativeDidRelease === true
      && manifest.demoReadiness.exactTailnetIssuanceQualified === true,
  };
}

function parsePortalSource(args) {
  if (args.length === 0) return undefined;
  if (args.length === 2 && args[0] === "--portal-source") return path.resolve(args[1]);
  fail("usage: check-midnight-integration-compatibility.mjs [--portal-source PATH]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(auditCompatibility({ portalSource: parsePortalSource(process.argv.slice(2)) }))}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
