# Ledger 9 local credential issuance

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

Capture only closed counters, booleans, immutable source/artifact digests, and
cleanup results. A focused diagnostic run cannot be promoted to acceptance.

## Cleanup

Remove only receipt-owned simulator, build/test state, temporary holder wallet,
and loopback faucet state. The Portal task stops its own containers and retains
its custody volumes. The Midnight owner decides whether the shared stack remains
running. Preserve private failure diagnostics until the failure is understood;
never publish them as demo evidence.
