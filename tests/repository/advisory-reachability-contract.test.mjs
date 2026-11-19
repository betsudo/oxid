// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const gate = fileURLToPath(new URL("../../scripts/check-advisories.sh", import.meta.url));
const ruzstd = {
  advisory: { id: "RUSTSEC-2026-0344" }, package: { name: "ruzstd", version: "0.8.3" },
};
const bigint = {
  advisory: { id: "RUSTSEC-2026-0387" }, package: { name: "crypto-bigint", version: "0.5.5" },
};

function audit(t, entries, graph = "", graphExit = 0, day = "2026-11-19") {
  const directory = mkdtempSync(path.join(tmpdir(), "oxid-advisory-fixture-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(path.join(directory, "cargo"), `#!/usr/bin/env bash
case "$1" in
  audit) printf '%s\\n' "$OXID_TEST_AUDIT"; exit 1 ;;
  tree)
    [ "$*" = 'tree --locked --workspace --all-features --target all --edges normal,build,dev --invert ruzstd@0.8.3 --prefix none' ] || exit 2
    printf '%s' "$OXID_TEST_GRAPH"
    exit "$OXID_TEST_GRAPH_EXIT" ;;
  *) exit 2 ;;
esac
`, { mode: 0o700 });
  writeFileSync(path.join(directory, "date"), '#!/usr/bin/env bash\nprintf "%s\\n" "$OXID_TEST_DAY"\n', { mode: 0o700 });
  return spawnSync("bash", [gate], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${directory}${path.delimiter}${process.env.PATH}`,
      OXID_TEST_AUDIT: JSON.stringify({ vulnerabilities: { found: true, list: entries } }),
      OXID_TEST_GRAPH: graph,
      OXID_TEST_GRAPH_EXIT: String(graphExit),
      OXID_TEST_DAY: day,
    },
  });
}

test("only the exact inactive ruzstd finding can pass", (t) => {
  assert.equal(audit(t, [ruzstd]).status, 0);
  assert.match(audit(t, [ruzstd], "ruzstd v0.8.3\nsubxt-lightclient v0.44.3\n").stderr,
    /Denied: RUSTSEC-2026-0344 ruzstd 0.8.3/u);
  assert.notEqual(audit(t, [ruzstd], "", 2).status, 0);
  assert.notEqual(audit(t, [{ ...ruzstd, package: { name: "ruzstd", version: "0.8.2" } }]).status, 0);
});

test("the active Ledger 9 exception reports residual risk and expires fail closed", (t) => {
  const accepted = audit(t, [ruzstd, bigint], "", 0, "2026-12-02");
  assert.equal(accepted.status, 0);
  assert.match(accepted.stderr, /Warning: active finding RUSTSEC-2026-0387 crypto-bigint 0.5.5/u);
  for (const day of ["2026-12-03", ""]) {
    const denied = audit(t, [ruzstd, bigint], "", 0, day);
    assert.notEqual(denied.status, 0);
    assert.match(denied.stderr, /Denied: RUSTSEC-2026-0387 crypto-bigint 0.5.5/u);
  }
  const otherVersion = { ...bigint, package: { ...bigint.package, version: "0.6.1" } };
  assert.notEqual(audit(t, [otherVersion]).status, 0);
});
