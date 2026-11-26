<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-DRAFT: Coordinate ordered Midnight ledger operations

- Status: Proposed
- Date: 2026-11-25
- Delivery: [#1232](https://github.com/betsudo/oxid/issues/1232), milestone-0.3.0
- Lookup optimization: [#1231](https://github.com/betsudo/oxid/issues/1231)

## Context

During a PreProd DID publication, three writes finalized and the fourth became
ambiguous. Oxid had retained its transaction hash, finalized anchor, and
deadline. Several submission and watch failures collapsed into
`outcome_unknown`, so the exact transport failure remained unclassified. A
repeated unknown observation triggered an integrity error, and a deadline
shared by the entire deployment prevented a fresh attempt after expiry. The
original DID was recovered after finalized history ruled out the old
transaction. Oxid kept the first three receipts, completed the remaining
writes, and resolved the finished DID.

[ADR-0122](0122-compose-ledger-backed-midnight-dids-natively.md) already requires
the DID bootstrap effects to be ordered, finalized, indexed, and resolved.
The native coordinator has durable receipts and checks the indexed action
against the preceding receipt. This proposal makes the evidence and recovery
rules explicit and applies them to other Oxid ledger operations over time.
It builds on the application-owned reconcilers in
[ADR-0114](0114-model-wallet-runtime-as-typed-resources-and-reconcilers.md) and
the process-death contract in
[ADR-0116](0116-define-suspension-and-process-death-recovery-contract.md).

## Decision

Model a ledger operation as a versioned, finite list of typed steps bound to
the wallet profile, authenticated chain identity, and intended resource. For
example, `Deploy → Update1 → Update2 → Update3 → Update4` is a single operation
with five ordered steps and its own completion check. DID publication uses the
same shape for its eight writes. A single ledger write is a one-step plan.
The admitted plan identifies effects and their success conditions. Compose
each transaction just in time using the verified state required by its step.

**A dependent step may start only after the previous step has finalized
successfully and its expected effect is visible in authenticated state.**
Persist both facts before the successor can be composed, funded, authorized,
signed, proved, or submitted. A transaction hash, RPC acknowledgment, or
best-block inclusion leaves the step pending.

### State machine

Use a closed Rust enum with data on the states that need it. For example,
`Confirming` carries an attempt identity and `AwaitingVisibility` carries
verified execution evidence. The pure reducer accepts typed commands and
facts, returning a next state and authorized effects. Persist the next state
before issuing its effects. UI and headless commands can request progress,
approval, or pause. They cannot assert a ledger result.

| Current state | Action or verified event | Transition and effect |
| --- | --- | --- |
| `Planned` | Start or resume the admitted operation | Validate the plan version, profile, chain, cursor, and any predecessor evidence. Enter `Preparing` for the current step. |
| `Preparing` | Precondition verified and intent composed | Enter `AwaitingApproval` when fresh authority is needed. Otherwise enter `Executing` with valid authority. |
| `AwaitingApproval` | Approval granted for the exact intent | Enter `Executing`. An expired intent or changed precondition returns to `Preparing`. Denial or cancellation pauses at this step. |
| `Executing` | Funding, signing, and proving complete under valid authority | Persist the exact attempt ID, extrinsic hash, finalized anchor, and deadline. Enter `BroadcastArmed` before handing the transaction to the transport. |
| `BroadcastArmed` | Node acknowledges the exact extrinsic | Enter `Confirming`. A timeout, interrupted send, or restart enters `Reconciling`, even if the wallet never saw an acknowledgment. |
| `Confirming` | Watch interrupted, deadline reached, or process restored | Enter `Reconciling` and check the same journaled attempt by exact identity. |
| `BroadcastArmed`, `Confirming`, or `Reconciling` | Exact extrinsic verified in a canonical finalized block with successful execution and the required Midnight ledger outcome | Persist the finalized receipt. Enter `AwaitingVisibility` and begin observation. |
| `Reconciling` | Result remains ambiguous | Retain the attempt and the cursor. Schedule a bounded read-only check or show the reason further progress is blocked. |
| `Reconciling` | Authoritative evidence closes the attempt without the intended effect, with no possibility it can still land | Preserve the closed attempt as history. Enter `Preparing` for a new attempt at the same step if retry policy allows it. Otherwise enter `Paused`. |
| `AwaitingVisibility` | Authenticated observation proves the expected postcondition | Atomically save the observation and advance the cursor once. Enter `Preparing` for the successor, or `VerifyingPlan` after the final step. |
| `VerifyingPlan` | The live completion check passes | Enter `Completed`. A DID requires the expected identifier, Ed25519 authentication, and Jubjub assertion relationships before issuance. |
| `Paused` | User resumes, or the specific blocker clears and policy allows automatic progress | Restore the saved phase. Reconcile any armed attempt. Resume observation for a finalized step. Return to approval when protected work needs fresh authority. |
| `Completed` | Duplicate start, resume, or delayed event | Return the saved result. The operation emits no more writes. |

The coordinator handles an authoritative failed execution while confirming
through the same reconciliation rules. Entering `BroadcastArmed` grants one
dispatch to the current worker. A restored armed record authorizes only
read-only reconciliation. Entering `Paused` retains the phase, evidence, and
reason in a typed checkpoint. A pause can stop new writes while permitting
read-only reconciliation of an existing submission.

On restart, an effect before `BroadcastArmed` rebuilds its transient
material from fresh state and requires current authority. The authorization
binds the exact trusted preview and its allowed effects and cost. Before
arming broadcast, verify that the constructed transaction still fits that
approval. If it does not, return to preparation and request a new approval.

Finality and visibility advance separately. When the indexer is behind, the
step remains visible in the app as waiting for indexed state. An observation
at the receipt block may satisfy the transition directly. A newer observation
may also satisfy it when it is anchored to the same canonical chain, the
original effect is attributable to the receipt, and the expected postcondition
still holds. An unrelated update or a conflicting contract revision cannot
advance the cursor. If an intervening write changes a precondition, surface
that conflict and use the operation's reviewed replan or approval policy.
An indexer lookup may locate the candidate block. The node and the applicable
ledger result establish finalized execution.

In the Ledger 9 DID adapter, match the Substrate extrinsic in its canonical
block to the successful Midnight transaction and contract action in that
extrinsic's events. Match the indexer action to the resulting Midnight hash.
Compare its serialized state with the state returned by
`midnight_contractState` at the receipt's exact block hash. A later indexed
head can confirm the same action. A different action needs its own verified
compatibility decision before any successor can run.

### Automatic recovery

| Failure or interruption | Recovery policy |
| --- | --- |
| Node, indexer, or prover unavailable before the broadcast boundary | Retry the same phase with bounded backoff. Recompose against fresh state when the deadline or precondition changes. Obtain fresh approval when required. |
| App closes or transport fails after the broadcast record is committed | Recover the exact attempt from finalized history. A reconnect, deadline, or missing indexer result alone never closes the attempt. |
| Transaction is absent after expiry | Require canonical coverage back to the saved anchor and a timestamp past expiry on that same finalized range. Admit a replacement only once those conditions are verified. |
| Execution is finalized but the indexer is behind | Retry observation from the saved finalized receipt. Leave the write intact and keep the successor blocked. |
| Authorization expires or the device locks | Continue public reconciliation where permitted. Pause protected work at its current step and ask for fresh user presence. |
| Worker completes late or an event arrives twice | Compare the operation, step, attempt, revision, and lifecycle generation. Discard stale completions and return already persisted evidence on duplicates. |
| Conflicting ledger state, wrong chain, or contradictory receipts | Pause with a typed integrity or conflict reason. Verify the journal and source before allowing replanning or progression. |
| Journal unavailable, unrecognized format, or unclassified failure | Preserve the last durable checkpoint. Wait for a validated reload. If a broadcast record exists or its persistence is uncertain, reconcile it before allowing a write. Surface unresolved errors as action required. |

Lifecycle, connectivity, and timer events wake the worker. They never stand in
for execution or visibility evidence. Use bounded backoff and a retry budget
for automatic work, with explicit recovery when it is exhausted. A valid
state or a verified receipt can clear its relevant blocker. Expiring a local
timer alone cannot clear a ledger ambiguity. The worker can recover through
restart, connection loss, and indexer lag. Custody failures and integrity
conflicts require a valid new decision before work resumes.

### Persistence, retry, and custody

- Keep a stable operation ID, ordered step IDs, and a separate ID for each
  attempt. Use the existing protected journals and retain earlier confirmed
  receipts when a step is retried. Save enough metadata to recover the exact
  attempt without relying on a live socket or an in-memory task.
- Use one worker per operation and one unresolved attempt per step. Revision
  and lifecycle generation checks prevent a duplicate command or late
  response from advancing the cursor or overwriting newer evidence. Preserve
  existing wallet-wide funding and spend guards for operations sharing inputs.
- Treat a transport loss after crossing the broadcast boundary as ambiguous.
  A replacement requires authoritative evidence that the old effect cannot
  still land. For an absent transaction, verify finalized coverage back to the
  saved anchor and require the timestamp of that same finalized range to pass
  the attempt deadline. If finality or coverage is unavailable, retain the
  attempt and surface the blocker.
- Manage validity per attempt. Set the window from measured proving and
  inclusion behavior and the applicable ledger constraints. Renew an expired
  window before broadcast, or after the prior attempt has been safely
  reconciled. A fresh window never changes the operation or step identity.
- Run the reducer and worker in the application layer. Dioxus and headless read
  the same durable progress. A restart can reconcile public evidence at any
  time. Resume protected work only with valid authority under ADR-0116 and ask
  for user presence when needed. The journal contains no secrets, witnesses,
  signed transactions, or reusable authorization.

### Progress and diagnostics

Expose the finalized and visible step counts, current effect, and the next useful action.
Name missing confirmation and missing indexed state separately. After
suspension, leave a pending DID in the identity inventory with a resume action.
Use bounded event codes for composition, proving, broadcast attempt, node
acknowledgment, watch timeout or interruption, finalization, indexed
observation, and approval required. Record stage durations without transaction
bodies, private wallet data, or provider credentials. Apply the support journal
boundary in [ADR-0119](0119-bound-a-secret-safe-support-journal.md).

## Adoption and verification

1. Qualify the native DID flow first. Restore existing journals by their
   version, preserve confirmed receipts, and reverify incomplete or legacy
   evidence before enabling a new write. Keep unsupported records available
   for diagnosis and block progression until they can be reconciled safely.
2. Exercise ordered effects in deterministic headless tests. Include failure or
   process death on both sides of the broadcast journal write, lost watch
   results, finalized rejection and expiry, lagging or mismatched indexer
   views, later compatible state, duplicate commands, and stale completions.
   Verify that unsupported states and events fail closed. Assert the exact
   submission count and that no successor runs before both evidence checks pass.
3. Qualify on the shared Ledger 9 stack, then exercise restart and resume in
   the iOS simulator using the same state machine. Extend the proven boundary
   to DUST registration, transfers, and other protected contract calls in
   focused slices. Measure lookup separately under #1231.

## Consequences

Dependent writes inherit finality and observation latency. The operation
reports that wait and preserves its confirmed prefix across restarts. A
multi-transaction plan can leave a visible on-chain prefix while it is paused.
Recovery continues from that prefix. Compensating or reversing a confirmed
effect requires a separate domain operation and its own authorization.
