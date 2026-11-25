# Ledger 9 local credential issuance

For the physical standalone demo, use the
[Android Tailnet scenario contract](ledger9-tailnet-issuance.md).

## Purpose

This is the fast, local qualification lane for a native Ledger 9 holder DID and
strict OpenID4VCI issuance from Lace ID Portal into the packaged Oxid iOS app.
It uses the designated shared `midnight-network` stack and one disposable,
receipt-owned iOS Simulator. It does not use Android, Tailnet, Preview, PreProd,
or a physical device.

The lane is successful only when the holder DID is deployed and resolved from
Indexer API v4, the credential is verified and stored encrypted, the app
process is killed and restarted without deleting its data, and a fresh resolver
read verifies the restored credential. A synthetic DID, mock resolver success,
or publication outside Oxid is not acceptance evidence.

Native Digital Passport verification uses the immutable `midnight-vc-proof`
crate for the Compact body root and issuance signature. The wallet applies its
holder binding, fresh issuer resolution, issuer trust, and time policy before
acceptance. Digital Passport uses `NoStatusBinding`, so the report leaves
credential status unchecked.

## Ownership

- The designated Midnight owner exclusively manages the shared node, indexer,
  and proof server. Oxid attaches read-only with `scripts/midnight-attach.sh`.
- The Portal task exclusively manages the `lace-id-portal-shared` Compose
  project, issuer seed, DID-manager custody, and issuer bootstrap.
- The Oxid task exclusively manages the fresh holder wallet, fixed local faucet
  process, holder-DID operation journal, packaged app, and disposable simulator.
- The Portal issuer and Oxid holder use distinct wallets.

Never run `standalone-up`, `standalone-down`, or an Oxid-owned Compose lifecycle
against the shared stack. Do not reuse a foreign simulator or Portal process.

## Exact inputs

Record these before the run:

- Oxid commit and tree;
- the compatibility manifest digest and immutable Ledger, Compact, ZK, ZKIR,
  and `midnight-identity` revisions;
- Portal commit, tree, deployment manifest digest, issuer DID, assertion method,
  and resolver image digest;
- shared genesis hash, node release, protocol version, proof-server release,
  and indexed height/hash;
- authenticated DID artifact path and manifest digest.

No seed, mnemonic, token, proof, credential payload, or private key belongs in
published evidence.

## Headless qualification

With Portal's resolver healthy on `127.0.0.1:9092`, run:

```sh
OXID_ENABLE_LIVE_LEDGER9_DID_E2E=1 \
  just shared-ledger9-native-did-headless-e2e
```

The command attaches read-only to the shared stack, authenticates the generated
DID artifacts, creates a fresh holder wallet, receives the fixed local grant,
and waits for positive DUST. It terminates the owned wallet process after
observing a durable partial DID receipt list. A new wallet process reopens the
same store and resumes the same operation and DID. The test compares the
finalized prefix before and after restart, requires all eight effects and live
resolution, and reports the number of preserved receipts. It removes its
temporary wallet and faucet state.

Headless clients can read the saved checkpoint with `did.deploy.status`
without starting publication. The result separates finalized receipts from
their authenticated observations and reports elapsed attempt and visibility
wait times when measured. The diagnostic ring records only fixed publication
event codes.

The local development wallet uses the bounded settlement worker to retry
preparation while the funded NIGHT output or fee allowance settles. A wallet
whose eligible outputs cannot cover the fee shows **Add more NIGHT to enable
DUST** and waits for the next wallet observation. Both outcomes occur before
draft creation. Recovery of a retained submission follows its transaction
journal.

Run the protocol/store matrix separately from the live DID publication lane:

```sh
cargo test -p oxid-headless \
  --features development-did-approval-fixture \
  --test portal_profile_flow
```

This matrix must prove positive issuance, invalid holder proof, unresolved
issuer DID, redeemed-offer replay, malformed credential rejection, exact local
network admission, stale resolver-state rejection, encrypted persistence, and
new-process restoration. It is hermetic protocol/store evidence. It does not
replace the shared-stack DID publication command or the packaged iOS journey.

## Packaged iOS qualification

Do not start iOS until the headless lane and Portal issuer bootstrap are green.
The older `just ios-portal-exact-sequence-simulator` wrapper pins a different
Portal source. Use the commands below for the shared Ledger 9 stack.

From a clean checkout, export the absolute
`OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_PATH` and its independently reviewed
`OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256`. Run the remaining blocks in
the same Bash shell. The build authenticates the native DID artifacts.

```bash
set -euo pipefail
umask 077
root="$(git rev-parse --show-toplevel)"
cd "$root"
test -z "$(git status --porcelain=v1)"
: "${OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_PATH:?Set the reviewed manifest path}"
: "${OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256:?Set the reviewed manifest digest}"
run_dir="$(mktemp -d "${TMPDIR:-/tmp}/oxid-ledger9-local.XXXXXX")"
./scripts/midnight-attach.sh >"$run_dir/shared-stack-attach.json"
source scripts/e2e/ios-simulator-ownership.sh
developer_dir="$(oxid_ios_discover_developer_directory)"
OXID_XCODE_DEVELOPER_DIR="$developer_dir" OXID_UI_PROFILE=user \
  OXID_MOBILE_CUSTODY=development OXID_STANDALONE_NETWORK_PROFILE=local \
  OXID_MOBILE_PORTAL_PROFILE=local OXID_MOBILE_PRESENTATION_PROVING=unavailable \
  ./bootstrap.sh -- bash scripts/run-ios-simulator.sh build >"$run_dir/app-build.log" 2>&1

case "$(uname -m)" in
  arm64) rust_target=aarch64-apple-ios-sim ;;
  x86_64) rust_target=x86_64-apple-ios ;;
esac
bundle_root="$root/target/dx/oxid-app/debug/ios"
app="$bundle_root/OxidApp.app"
artifact_receipt="$bundle_root/oxid-app-artifact-receipt.json"
app_config="mobile,standalone-development,standalone-local,standalone-portal|ui=user|custody=development|network=local|tailnet=none|portal=local|proving=unavailable|portal_manifest=$OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256"
node scripts/app-artifact-receipt.mjs verify --platform ios-simulator \
  --artifact "$app" --target "$rust_target" --configuration "$app_config" \
  --receipt "$artifact_receipt"
cp "$artifact_receipt" "$run_dir/app-artifact-receipt.json"
```

The app receipt binds the reviewed Portal manifest digest. Build again when
the manifest changes or a previously built app has an older receipt format.

Choose an installed iOS runtime and iPhone device type. Export their full IDs
as `OXID_IOS_RUNTIME_ID` and `OXID_IOS_DEVICE_TYPE_ID`. The qualification used
`com.apple.CoreSimulator.SimRuntime.iOS-26-4` and
`com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro`.

```bash
simulator_receipt="$run_dir/simulator-receipt.json"
cleanup_owned_simulator() {
  if [ -f "$simulator_receipt" ]; then
    oxid_ios_delete_owned "$developer_dir" "$simulator_receipt"
  fi
}
trap cleanup_owned_simulator EXIT
oxid_ios_preflight "$developer_dir" "$OXID_IOS_RUNTIME_ID" "$OXID_IOS_DEVICE_TYPE_ID"
udid="$(oxid_ios_create_owned "$developer_dir" "$OXID_IOS_RUNTIME_ID" \
  "$OXID_IOS_DEVICE_TYPE_ID" "Oxid-Ledger9-$(basename "$run_dir")" "$simulator_receipt")"
shasum -a 256 "$simulator_receipt" | awk '{print $1}' >"$run_dir/simulator-receipt.sha256"
oxid_ios_owned_simctl "$developer_dir" "$simulator_receipt" boot
OXID_IOS_OPERATION_TIMEOUT_SECONDS=600 \
  oxid_ios_owned_simctl "$developer_dir" "$simulator_receipt" bootstatus -b
oxid_ios_owned_simctl "$developer_dir" "$simulator_receipt" install "$app"

mkdir "$run_dir/project"
OXID_REPOSITORY_ROOT="$root" xcodegen generate \
  --spec "$root/tests/mobile/ios/project.yml" --project "$run_dir/project"
project="$run_dir/project/OxidMobileSmoke.xcodeproj"
clang="$developer_dir/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
operator="$(id -un)"

run_xctest() {
  local scenario="$1" seconds="$2" operation="$3"
  shift 3
  oxid_ios_receipt_matches_simulator "$developer_dir" "$simulator_receipt" || return 1
  node "$root/scripts/e2e/ios-xcode-supervisor.mjs" \
    --scenario "$scenario" --timeout-seconds "$seconds" --cwd "$root" -- \
    env -i DEVELOPER_DIR="$developer_dir" HOME="$HOME" LANG="${LANG:-en_US.UTF-8}" \
    LOGNAME="$operator" USER="$operator" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    TMPDIR="${TMPDIR:-/tmp}" \
    OXID_XCODE_REAL_CLANG="$clang" \
    /usr/bin/xcodebuild "$operation" -project "$project" -scheme OxidUITests \
    -destination "platform=iOS Simulator,id=$udid" -derivedDataPath "$run_dir/derived-data" \
    CODE_SIGNING_ALLOWED=NO CC="$root/scripts/e2e/xcode-swift-only-clang-wrapper.sh" \
    LD="$clang" "$@" >"$run_dir/$scenario.log" 2>&1
}

run_portal_test() {
  local selector="$1" seconds="$2" scenario
  scenario="$(oxid_ios_scenario_name ledger9-local "$selector")"
  run_xctest "$scenario" "$seconds" test-without-building \
    -parallel-testing-enabled NO -only-testing:"OxidUITests/PortalFlowTests/$selector"
}

run_xctest ledger9-local-build 1800 build-for-testing
```

The holder test expects the development faucet on `http://127.0.0.1:36301`.
Use the existing listener if its owner confirms it serves the same chain.
If the port is free, start this command in a second terminal from the same
checkout. Set `run_dir` to the private directory created above. Interrupt
that terminal when the faucet is no longer needed.

```bash
: "${run_dir:?Set the private run directory from the first terminal}"
OXID_ENABLE_STANDALONE_FAUCET=1 \
  OXID_STANDALONE_FAUCET_HTTP_ADDRESS=127.0.0.1:36301 \
  OXID_PROFILE_STORE_PATH="$run_dir/faucet-profiles.json" \
  ./bootstrap.sh -- cargo run --locked -p oxid-headless \
    --features standalone-faucet --bin oxid-standalone-faucet-http
```

Once the expected faucet is listening, run these in the first terminal:

```bash
run_portal_test testPrepareHolder 1800
run_portal_test testFundedWalletRecoversAcrossRestart 600
```

The journey must perform, in order:

1. create and fund a fresh holder wallet;
2. converge NIGHT and DUST without a manual synchronization prerequisite;
3. deploy and resolve the holder DID containing `#key-auth` and `#key-assert`;
4. fetch and preview the exact Portal offer without consuming it;
5. obtain explicit holder consent;
6. complete token, nonce, holder proof, and credential requests;
7. verify issuer DID, assertion method, holder binding, and credential proof;
8. persist only the encrypted credential envelope;
9. kill the app process, restart without reinstall or data reset, and list the
   same credential;
10. reverify it through a fresh resolver/indexer read.

### Offer handoff

Create the offer only after the holder DID is live and resolvable. A Portal
offer is a short-lived, single-use capability. Record only its SHA-256 digest
and expiry in private run state; never copy the URI into logs or evidence.
Stage it directly onto the receipt-owned simulator pasteboard from its
mode-`0600` file, then clear the pasteboard immediately after XCTest consumes
it. If preview or issuance reports expiry, discard the entire offer and create
exactly one fresh offer. Never retry a consumed or expired URI.

For the pinned local issuer, after independently resolving the holder's
authentication and assertion methods, create and consume one synthetic offer:

```bash
curl --noproxy '*' -fsS --max-time 15 -H 'Content-Type: application/json' --data '{}' \
  http://127.0.0.1:8090/api/issuer/kyc-sessions >"$run_dir/portal-response.json"
jq -er '.credentialOfferUri | strings | select(startswith("openid-credential-offer://"))' \
  "$run_dir/portal-response.json" >"$run_dir/offer.txt"
unlink "$run_dir/portal-response.json"
shasum -a 256 "$run_dir/offer.txt" | awk '{print $1}' >"$run_dir/offer.sha256"
oxid_ios_receipt_matches_simulator "$developer_dir" "$simulator_receipt"
oxid_ios_xcrun "$developer_dir" simctl pbcopy "$udid" <"$run_dir/offer.txt"
unlink "$run_dir/offer.txt"
issuance_status=0
run_portal_test testPasteAndIssue 600 || issuance_status=$?
oxid_ios_receipt_matches_simulator "$developer_dir" "$simulator_receipt"
oxid_ios_xcrun "$developer_dir" simctl pbcopy "$udid" </dev/null
test "$issuance_status" -eq 0
```

The rendered handoff is:

1. open **Documents** and **Add document**;
2. paste into **Credential offer URI**;
3. select **Preview credential offer**;
4. review WHO → WHAT → FROM → WHY and explicitly consent;
5. select **Accept and issue credential**;
6. require the single valid Digital Passport details view.

The repository-owned XCTest selector is
`OxidUITests/PortalFlowTests/testPasteAndIssue`. The holder bootstrap selector
is `testPrepareHolder`. Run `testFundedWalletRecoversAcrossRestart` next, on the
same simulator and profile, to observe DUST readiness and the unchanged public
NIGHT address after a process restart. Create the offer after that check to
preserve its lifetime for issuance. The issuance selector verifies that the
synthetic Passport's names start hidden, reveals and hides only the first
name, and leaves it visible for the restart check. `testRestored` requires the
names to be hidden when the credential is reopened. Build the XCTest bundle
once and reuse it with `test-without-building`. Preserve app data throughout
the sequence.

### Restart and protected-store checks

Before restart, require the credential store magic `OXIDVC01`, a 32-byte
wrapping key, and a plaintext denylist pass for the offer, token, nonce, DID,
passport names, document number, signed credential, proof, and private parts.
Record only booleans and file digests. Terminate the exact application bundle,
prove its old PID absent, relaunch it without uninstall or data reset, and
require a different PID. Run `run_portal_test testRestored 600` against that
restarted simulator. It must list exactly one credential and apply a fresh
resolver-backed reverification before the run can pass.

Capture only closed counters, booleans, immutable source/artifact digests, and
cleanup results. Bind the receipt to the committed Oxid HEAD/tree, packaged app
digest, Portal commit/tree/manifest digest, compatibility-manifest digest,
shared-stack public fingerprint, simulator runtime/device identifiers, and
test-selector outcomes. A focused diagnostic run or a dirty-tree artifact
cannot be promoted to acceptance.

The final readiness verdict is one of:

- `READY`: headless matrix, live DID publication, packaged iOS issuance,
  encrypted restart, fresh reverification, and receipt-scoped cleanup all pass;
- `NOT_READY`: any required phase is missing, failed, dirty-tree-only, or lacks
  an immutable receipt.

Only `READY` is a demo handoff.

## DID deployment recovery matrix

The native deployment coordinator is a durable command/effect state machine.
Qualify these cells whenever its transitions change:

| Condition | Required behavior | Focused evidence |
| --- | --- | --- |
| Fresh command completes | Compose and submit the eight ordered effects, then require live resolution before `ready` | `deployment_reaches_ready_and_repeated_requests_do_not_resubmit` |
| Process stops in `submitting` or `confirming` | Reconcile the durable submission receipt before any funding, proving, or broadcast | `restored_submitting_operation_reconciles_before_continuing` |
| Node outcome is unknown | Persist `outcome_unknown`; only reconciliation may advance it | `outcome_unknown_reconciles_without_a_second_submission` |
| Pre-broadcast effect fails | Resume only from the last durable transaction boundary | identity-application deployment retry tests |
| Duplicate command/event | Return or reconcile the existing operation; never create a second submission | deployment idempotency and journal-barrier tests |
| Competing replacement in the same realm | Reject the second active operation instead of superseding protected work | storage deployment `rejects_a_second_active_operation_for_the_same_realm` |
| Stale/backwards transition | Reject through timestamp/state invariants; retain the newer durable operation | identity-application operation-model tests |
| Cancellation | No public DID-deployment cancellation command exists after admission; do not invent force-cancellation across the broadcast boundary | Not applicable by design; unknown outcomes remain reconcilable |

This matrix is intentionally narrower than wallet transaction cancellation. A
DID deployment must not turn process suspension, duplicate UI admission, or a
late observation into a second chain effect.

## Cleanup

Remove only receipt-owned simulator, build/test state, temporary holder wallet,
and loopback faucet state. The Portal task stops its own containers and retains
its custody volumes. The Midnight owner decides whether the shared stack remains
running. Preserve private failure diagnostics until the failure is understood;
never publish them as demo evidence.

Cleanup is part of acceptance. Run `cleanup_owned_simulator` and verify that
the owned UDID, old app PID, and all task-owned XCTest/build children are
absent. Keep the receipt digest and sanitized run evidence. Record the final
swap, memory-pressure, disk, listener, and ownership checks in the private
factory receipt.
