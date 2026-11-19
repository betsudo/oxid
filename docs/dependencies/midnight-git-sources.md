# Midnight Git source policy

- Status: Ledger 9 source policy selected for milestone 0.3.0
- Reviewed: 2026-11-18
- Tracking: issues #1191–#1195
- ADR: [ADR-0123](../adr/0123-adopt-one-ledger9-ssi-cohort.md)

## Selected cohort

Oxid admits one immutable Ledger 9 cohort. The compatibility manifest in
`config/midnight-integration-compatibility.json` is the machine-readable
authority for repositories, revisions, package versions, protocol, ZKIR
schema, Rust MSRV, and shared-stack releases.

| Repository | Revision | Purpose |
| --- | --- | --- |
| `betsudo/midnight-ledger` | `6fbc2e3900845a858f70eebf8a0deab1d4d3c0d6` | Ledger 9.1 transaction, state, Zswap, serialization, and cryptography packages |
| `betsudo/compact` | `d6513a24debac14d43a8199460d9dc2c6d9af2b1` | Compact Rust AST/runtime ABI 54 |
| `betsudo/midnight-zk` | `bca8db4d9e2c1ecaa5d1db5ba7a201935b6c6c8a` | proving implementation selected by Ledger 9 |
| `betsudo/midnight-zkir` | `3377ad9e48741f60e0aa17010b6f23e34223d906` | ZKIR 3.2.1, schema 20 |
| `betsudo/midnight-identity` | `e7e28eea94515d59b5e7360a717f5c0dee3eecdf` | merged Ledger 9 DID/VC release source |

The identity revision is the immutable merge commit of upstream PR
`betsudo/midnight-identity#110` and is admitted for release qualification.

## Required source form

Direct Midnight Git dependencies use HTTPS and a full immutable `rev`:

```toml
midnight-ledger = { package = "midnight-ledger-v9", version = "=1.0.2", git = "https://github.com/betsudo/midnight-ledger", rev = "6fbc2e3900845a858f70eebf8a0deab1d4d3c0d6", default-features = false }
midnight-compact-runtime = { version = "=0.2.0", git = "https://github.com/betsudo/compact", rev = "d6513a24debac14d43a8199460d9dc2c6d9af2b1", features = ["experimental-functional"] }
midnight-zkir = { version = "=3.2.1", git = "https://github.com/betsudo/midnight-zkir", rev = "3377ad9e48741f60e0aa17010b6f23e34223d906", default-features = false }
```

Branches, tags, abbreviated revisions, local paths, source rewrites, and a
mixed Ledger 8/Ledger 9 graph are forbidden. Registry packages may remain in
the transitive graph when selected by the reviewed cohort and locked by
`Cargo.lock`; they are not authority to introduce another Git source family.

## Adapter boundary

Ledger, generated Compact, ZKIR, and proving types remain inside outgoing
adapters. Oxid domain and application crates keep owned types and ports. The
source migration does not authorize a fake provider, out-of-band DID
publication, WebView composer, or JavaScript compatibility bridge.

## Enforcement

`scripts/check-midnight-sources.sh` evaluates locked Cargo metadata and rejects:

- unreviewed Git repositories or revisions;
- any previously selected Ledger 8 revision;
- mutable or local-path direct Midnight dependencies;
- the wrong Ledger, Zswap, Compact runtime, DID runtime, or ZKIR package
  version.

`scripts/check-midnight-integration-compatibility.mjs` verifies the declared
cohort, Rust toolchain, shared-stack contract, and product readiness truth.
Both checks are repository gates. The old Ledger 8 record remains only as
historical milestone 0.2.0 evidence.
