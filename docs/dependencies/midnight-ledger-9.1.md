# Midnight Ledger 9 dependency review

- Status: selected for milestone 0.3.0; provider migration in progress
- Reviewed: 2026-11-18
- Tracking: issues #1191, #1192, and #1193
- Rust: 1.99

## Immutable cohort

Oxid selects one Ledger 9 cohort for its native production graph:

| Component | Revision | Selected API |
| --- | --- | --- |
| `betsudo/midnight-ledger` | `6fbc2e3900845a858f70eebf8a0deab1d4d3c0d6` | `midnight-ledger-v9 1.0.2`, `midnight-zswap 9.0.1` |
| `betsudo/compact` | `d6513a24debac14d43a8199460d9dc2c6d9af2b1` | Rust runtime `0.2.0`, ABI 54 |
| `betsudo/midnight-zk` | `bca8db4d9e2c1ecaa5d1db5ba7a201935b6c6c8a` | `midnight-proofs 0.8.2` |
| `betsudo/midnight-zkir` | `3377ad9e48741f60e0aa17010b6f23e34223d906` | ZKIR `3.2.1`, schema 20 |
| `betsudo/midnight-identity` | `e7e28eea94515d59b5e7360a717f5c0dee3eecdf` | merged DID/VC Ledger 9 release source `0.5.0` |

Preview and PreProd history includes events encoded before the Ledger 9
upgrade. The adapter's optional `mixed-era-replay` feature pins the published
Ledger 8.1.3 decoder cohort with lockfile checksums. That cohort is used only
for historical wallet replay. The Ledger 9 graph continues to own live state,
transaction construction, proving, and DID/VC calls. The source check admits
only the exact replay aliases in `wallet.historicalReplay`. See [the public
issuance runbook](../factory/ledger9-public-issuance.md#replay-wallet-history-across-the-ledger-9-upgrade).

The identity revision is the immutable merge commit of upstream PR
`betsudo/midnight-identity#110` and is the qualified release source.

## Runtime topology

Development attaches read-only to the designated owner's shared
`midnight-network` stack. `scripts/midnight-attach.sh` validates:

- node `2.1.101` on `http://127.0.0.1:9944`;
- Indexer API v4 on `http://127.0.0.1:8088/api/v4/graphql` and its WebSocket
  companion;
- protocol `2,001,100` and an exact node/indexer block-hash match;
- proof server `9.0.2` on `http://127.0.0.1:6300`.

The attach command never owns the shared Docker lifecycle. An isolated stack
is required for destructive chain-state tests or incompatible revisions.

## Boundaries and risks

Ledger, Compact, proving, and generated types remain inside outgoing adapters.
Oxid domain and application ports use owned types. The Ledger 9 DID runtime
replaces the removed Ledger 8 generated-executor API with typed
`DidContractCall`, `Ledger9DidProvider`, `LedgerIndexerProvider`, and durable
finality reconciliation. That provider migration is tracked separately in
#1193; dependency pinning must not disguise the missing provider with a mock or
out-of-band publication.

`scripts/check-midnight-sources.sh` audits the resolved Cargo metadata. It
admits only the five reviewed Git sources above and rejects all previously
selected Ledger 8 revisions, mutable branches, and local paths.
