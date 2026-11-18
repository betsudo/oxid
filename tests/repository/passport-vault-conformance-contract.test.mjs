// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));

const read = (relativePath) => readFile(path.join(root, relativePath), "utf8");

async function rustSources(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const sources = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      sources.push(...await rustSources(absolute));
    } else if (entry.isFile() && entry.name.endsWith(".rs")) {
      sources.push(absolute);
    }
  }
  return sources;
}

test("external Passport Vault prerequisites are explicit ignored tests", async () => {
  const artifacts = await read("crates/adapters/passport-vault/src/compact_artifacts.rs");
  const composer = await read("crates/adapters/passport-vault/src/compact_composer_conformance.rs");
  const composition = await read("crates/composition/src/passport_vault/tests.rs");

  for (const [source, testName] of [
    [artifacts, "packaged_artifacts_authenticate_and_resolve_only_wallet_circuits_when_configured"],
    [composer, "packaged_composer_emits_a_rust_compatible_unproven_call_when_configured"],
    [composition, "standalone_managed_claim_composes_and_settles_through_the_native_stack"],
  ]) {
    const start = source.indexOf(`fn ${testName}`);
    assert.notEqual(start, -1, testName);
    assert.match(source.slice(Math.max(0, start - 240), start), /#\[ignore = ".*passport-vault-conformance.*"\]/u, testName);
  }
});

test("Passport Vault conformance is quarantined outside the active Ledger9 closure", async () => {
  const justfile = await read("Justfile");
  const packages = await read("nix/packages/default.nix");
  const devshell = await read("nix/devshells/default.nix");
  const workflow = await read(".github/workflows/ci.yml");

  for (const [name, source] of [
    ["Justfile", justfile],
    ["Nix package set", packages],
    ["Nix development shell", devshell],
    ["hosted CI", workflow],
  ]) {
    assert.doesNotMatch(source, /passport-vault-(?:compact-artifacts|call-composer)/u, name);
  }
  assert.doesNotMatch(devshell, /OXID_PASSPORT_VAULT_(?:ARTIFACTS_DIR|COMPOSER)/u);
});

test("non-ignored Rust tests cannot silently pass when an environment prerequisite is absent", async () => {
  // Explicit ignored conformance entrypoints are admitted only through the
  // launcher checked above, which validates every external prerequisite
  // before deliberately running them with `--ignored --exact`. Ordinary tests
  // must still fail closed rather than silently returning.
  const silentPrerequisiteReturn = /#\[(?:[a-z_]+::)?test\](?:(?!#\[(?:[a-z_]+::)?test\])[\s\S]){0,1600}?std::env::var_os\([^)]*\)[\s\S]{0,160}?else\s*\{\s*return\s*;\s*\}/gu;
  const hasUnignoredSilentReturn = (source) => [...source.matchAll(silentPrerequisiteReturn)]
    .some((match) => !/#\[ignore(?:\s*=\s*[^\]]+)?\]/u.test(match[0]));
  const fixture = (attributes) => `#[test]\n${attributes}fn check() {\n  let Some(value) = std::env::var_os("FIXTURE") else { return; };\n}`;

  assert.equal(hasUnignoredSilentReturn(fixture("")), true);
  assert.equal(hasUnignoredSilentReturn(fixture("#[ignore = \"external fixture\"]\n")), false);
  const violations = [];

  for (const sourcePath of await rustSources(path.join(root, "crates"))) {
    const source = await readFile(sourcePath, "utf8");
    if (hasUnignoredSilentReturn(source)) {
      violations.push(path.relative(root, sourcePath));
    }
  }

  assert.deepEqual(violations, [], `silent environment-gated tests: ${violations.join(", ")}`);
});

test("repository verification owns the conformance bookkeeping contract", async () => {
  const runner = await read("run.sh");
  assert.match(runner, /node --test tests\/repository\/passport-vault-conformance-contract\.test\.mjs/u);
});
