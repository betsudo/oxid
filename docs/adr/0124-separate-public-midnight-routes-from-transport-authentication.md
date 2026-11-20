# ADR-0124: Separate public Midnight routes from transport authentication

- Status: Proposed
- Date: 2026-11-20
- Source: ADR-0098, ADR-0118, ADR-0123, and [issue #1200](https://github.com/betsudo/oxid/issues/1200)

## Context

PreProd Ledger 9 node and indexer access uses Blockfrost. Deployment profiles
are public signed statements about network identity, the expected genesis,
and approved routes. They already reject URL credentials, queries, and
fragments. Blockfrost supports a `project_id` header on native HTTP and
GraphQL WebSocket clients. The node WebSocket route needs an independent
read-only handshake check. [Blockfrost Midnight API](https://docs.blockfrost.io/midnight/#authentication)

## Decision

Keep the signed profile query-free. Obtain the PreProd project ID from a
runtime native secret provider scoped to the installed app and network. A
mobile provider should use device-local protected storage without cloud
backup. Credential rotation is independent of profile and wallet recovery.
An absent, malformed, or wrong-network value must fail before networking.

Add the sensitive `project_id` header only on the exact approved Blockfrost
route. The native HTTP and WebSocket clients keep the existing TLS trust,
connection deadlines, response limits, and redirect refusal. Request failures
surface bounded categories. They never report headers, remote response
payloads, or the provider token. Do not persist the token with the profile or
the wallet. The read-only preflight checks node genesis against the signed
profile and compares the indexer's Ledger 9 tip hash with the canonical
node block at the same height. A node/indexer mismatch blocks composition.

## Verification and adoption

1. Test native request construction, rejected credentials and routes, actual
   synthetic header receipt, and refusal to forward authentication on redirect.
2. Install the credential on the complete signed node and indexer cohort.
   The request boundary applies the same policy to NIGHT, DUST, and shielded
   subscriptions, tip reads, and node submission and reconciliation.
3. Wire the native secret provider into mobile startup. With an approved
   signed profile, verify the live runtime, genesis, and node/indexer block
   alignment before enabling wallet activity. Record only public provenance and outcomes.

This proposal covers PreProd. Preview and the shared local network retain
their existing transport configuration.
