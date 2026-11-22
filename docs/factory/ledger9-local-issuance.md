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
waits for positive DUST, deploys all eight holder-DID effects, and requires live
resolution. It owns and removes only its temporary wallet/faucet state.

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
Use one newly created simulator through the repository's iOS ownership helper.
Build the app with development custody, the local standalone network profile,
the local Portal profile, and the exact Portal deployment manifest plus digest.

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
require a different PID. `testRestored` must list exactly one credential and
apply a fresh resolver-backed reverification before the run can pass.

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

Cleanup is part of acceptance. Revalidate the simulator receipt before shutting
down and deleting that exact UDID. Prove the old app PID and all task-owned
XCTest/build children absent. Do not shut down another booted simulator, kill
CoreSimulator services, change the shared `midnight-network` project, or stop a
Portal process whose ownership belongs to the Portal task. Record the final
swap, memory-pressure, disk, listener, and ownership checks in the private
factory receipt.
