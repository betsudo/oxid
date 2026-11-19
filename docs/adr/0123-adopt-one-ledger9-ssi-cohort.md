# ADR-0123: Adopt one Ledger 9 SSI cohort

- Status: Accepted
- Date: 2026-11-18
- Source: ADR-0015, ADR-0118, ADR-0122, and issues #1191–#1195
- Supersedes: ADR-0122's Ledger 8 dependency selection; its native-process and no-shortcut boundaries remain in force

## Context

Milestone 0.2.0 proved that a ledger-backed holder DID must be composed in the
native Rust process and finalized before a Portal issuer can resolve it. That
implementation selected Ledger 8 packages and generated APIs. The shared
Midnight development stack and the reusable `midnight-identity` DID/VC
packages have moved to Ledger 9.1, Compact's Rust AST runtime, ZKIR schema 20,
and Rust 1.99. Ledger 9 also removes the generated-executor surface used by the
old Oxid adapter.

Mixing the old transaction graph with the new generated contract runtime would
produce source ambiguity, incompatible state and proof types, and false demo
readiness. A dependency-only bump is therefore insufficient.

## Decision

Oxid milestone 0.3.0 selects one immutable compatibility cohort recorded in
`config/midnight-integration-compatibility.json`:

- Ledger 9.1 transaction and Zswap packages from one `midnight-ledger`
  revision;
- Compact Rust AST/runtime ABI 54 from one `compact` revision;
- the corresponding `midnight-zk` proof implementation and ZKIR 3.2.1 schema
  20 revisions;
- one `midnight-identity` revision for DID, VC Core, DID binding, proof, and
  DigitalPassport packages;
- Rust 1.99 as the workspace toolchain and MSRV.

During local migration, the exact remotely reachable head of upstream
`betsudo/midnight-identity#110` may be used. A release-qualified Oxid change
must pin that PR's immutable merge commit.

The application attaches read-only to the designated owner's shared Ledger 9
stack. `scripts/midnight-attach.sh` verifies node `2.1.101`, protocol
`2,001,100`, Indexer API v4, node/indexer hash agreement, and proof server
`9.0.2`. It never starts, stops, rebuilds, or resets that stack. Destructive or
incompatible tests require an explicitly isolated stack.

Ledger-specific types remain inside outgoing adapters. The DID adapter must
implement the new typed `Ledger9DidProvider` and `LedgerIndexerProvider`
boundaries with protected custody, authenticated ZKIR/verifier material,
funding, proving, journal-before-broadcast, submission, durable finality, and
resolution reconciliation. No mock provider, out-of-band holder publication,
WebView composer, or JavaScript bridge may be presented as a working
ledger-backed DID.

Delivery follows the fastest evidence line: locked headless compile and tests,
then the shared-stack headless issuance journey, then one canonical iOS
simulator run. Android remains a required target but is deferred to the final
qualification pass to avoid unnecessary host contention.

## Consequences

- Source-policy gates reject old Ledger 8 revisions and any unreviewed
  Midnight Git source.
- Existing Ledger 8 generated-executor code will fail to compile until the
  provider migration is implemented; that failure is truthful migration
  evidence rather than a reason to restore compatibility shims.
- Nix and mobile artifact packaging must consume the same Ledger 9 identity
  source and ZKIR schema as Cargo.
- The shared stack is an external capability with an explicit health contract,
  not a lifecycle owned by a worktree or demo script.
- Passport Vault is temporarily excluded from the Oxid brand surface and the
  default Nix package/dev-shell closure. Its Ledger8 composer is not a
  prerequisite for OpenID4VCI credential issuance. The reviewed Rust sources
  and historical tests remain in the repository so issue #1194 can restore the
  feature only after its Compact artifacts and composer join this Ledger9
  cohort.
- VC and DigitalPassport reuse follows only after the DID provider and exact
  dependency graph are stable.
- The previous Ledger 8 documentation remains as historical 0.2.0 evidence.
