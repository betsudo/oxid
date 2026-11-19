# Ledger 9 Digital Passport issuance on Android over Tailnet

This scenario uses a real Android phone, a private Tailnet, and the shared
Ledger 9 `undeployed` network. The [local headless and iOS lane](ledger9-local-issuance.md)
and the [public physical-device lane](https://github.com/betsudo/oxid/issues/1203)
have separate acceptance paths. The [Ledger 9 migration](https://github.com/betsudo/oxid/issues/1191)
tracks this scenario.

## Environment and app update

- Attach read-only to the owner-managed chain. Verify the exact Android
  artifact and signer, Portal source and deployment manifest, shared chain
  fingerprint, live issuer DID, and assertion key.
- Authenticate indexer HTTPS and WSS, node WSS, prover HTTPS, and Portal
  issuer and resolver HTTPS. Exercise transaction submission and finalized
  observation as distinct steps. Reject certificate, hostname, and unexpected
  redirect failures with a bounded error for the affected transport.
- Install the same-package, same-signer build in place. Wallet-only and
  DID-enabled development builds use the same encrypted custody. Verify that
  the active profile, NIGHT address, balance, and credential store survive
  restart and upgrade. App-data reset requires a separate explicit action.
  A legacy profile with a missing custody root requires recovery. Block
  replacement-root initialization for that profile.
- Keep Home and navigation responsive during startup, chain catch-up, and
  DUST work. Record the startup phase when a launch stalls. Keep service-only
  Portal lifecycle independent of phone installs, app data, and shared
  chain lifecycle.

For the upgrade check, select a disposable funded test profile and record the
original signer, realm fingerprint, active profile, public NIGHT receive
address, and balance in private evidence. Replace the APK in place with the
same signer. On the first launch, visit Wallet and Documents and return to
Home while the new projection is loading. After a force-stop and relaunch,
compare the same facts and verify signing through an authorized test
operation. Run the missing-root negative test on a separate disposable
profile. Record a slow first launch separately from a missing root.

## Funding and DUST readiness

Select **Local (undeployed)** and fund the protected holder wallet's public
NIGHT address with one standalone faucet grant. Observe the grant on the
same chain before retrying an ambiguous faucet response.

After confirmed eligible NIGHT is visible, Oxid prepares and submits
development DUST registration automatically. Oxid durably records the exact
submission before broadcast, observes finality, and catches up the selected
wallet's DUST state. **Ready** requires a positive synced DUST balance.

| Settlement state | Expected behavior |
| --- | --- |
| Waiting for funded NIGHT | Show that the selected wallet is waiting for eligible NIGHT. |
| Registering or confirming | Show progress and keep navigation available. |
| Updating balance | Show that registration is confirmed and DUST is catching up. |
| Ready | Display spendable DUST when unmasked. Keep readiness visible when the amount is masked. |
| Interrupted or outcome unknown | Show a recoverable state. Reconcile the retained submission before admitting any replacement. |

Display NIGHT sync independently of DUST readiness. Distinguish a synced
zero from an unknown balance. Use the active profile and realm generation
for status and DID or Send prerequisites. Discard stale results after a
switch. Preserve an ambiguous legacy `Submitting` record and retire it only
after establishing pre-broadcast failure or reconciling the chain outcome.

## Holder DID and credential handoff

1. With DUST ready, open **Documents → Manage identities → Create a DID**.
   Wait for finalized native publication and live resolution of the holder
   DID and its authentication and assertion methods.
2. Open the verified Portal page on the Mac. Complete test verification
   and scan the fresh offer QR in Oxid. Review the issuer, credential, and purpose.
3. Explicitly accept and issue the Digital Passport. Require strict OpenID4VCI
   validation, the `midnight-vc-passport` credential path, holder binding,
   and encrypted storage. This scenario disables the `mn-passport-acc` contract.
4. Relaunch the app with the same data, find the credential in **Documents**,
   and reverify it with a fresh resolver read. Exercise refusal and expired
   or consumed offers in separate test sessions.

Record exact build, chain, Portal, and phase evidence in a sanitized receipt.
Keep recovery material, device identifiers,
offers, tokens, and credential payloads out of receipts and logs.

## Evidence and cleanup

Keep the operator's receipt private with mode `0600`. Use schema
`oxid-ledger9-tailnet-issuance-evidence-v1` and these two objects:

| Object | Required fields |
| --- | --- |
| `bindings` | `oxidHead`, `oxidSourceSha256`, `apkSha256`, `signerSha256`, `portalHead`, `portalManifestSha256`, `chainFingerprint` |
| `phases` | `prerequisites`, `custodyUpgrade`, `tailnetTransport`, `automaticDust`, `nativeHolderDid`, `strictIssuance`, `encryptedReopen`, `freshReverification`, `refusal`, `expiredOffer`, `consumedOffer`, `cleanup` |

Use lowercase hexadecimal commit IDs or SHA-256 digests. Set each phase to
`passed`, `failed`, or `unverified` according to the evidence collected from
that run. A successful issuance alone leaves upgrade checks, reverification,
and the negative offer cases unverified. For the transport phase, require
indexer HTTP/WSS, node WSS submit and finalized read, prover HTTPS, and the
pinned issuer and resolver HTTPS. Record a service failure at its specific
phase. For cleanup, stop only scenario-owned Portal processes and routes and
confirm that the shared chain and wallet data are still available.

```sh
node scripts/e2e/ledger9-tailnet-issuance-evidence.mjs /absolute/path/to/private-receipt.json
```

The command validates the receipt format and returns a bounded verdict and
phase names. It does not generate evidence, start services, or touch a device.

## Qualification matrix

| Coverage | Test layer | Follow-up |
| --- | --- | --- |
| Wallet-only to Portal upgrade, startup responsiveness, and missing-root recovery | Native tests and an on-demand physical upgrade | [#1204](https://github.com/betsudo/oxid/issues/1204) |
| Tailnet transport and transaction finality | Host transport checks and Android transaction smoke | [#1205](https://github.com/betsudo/oxid/issues/1205) |
| Automatic registration, interruption, and journal recovery | Headless failure matrix and mobile restart smoke | [#1206](https://github.com/betsudo/oxid/issues/1206) |
| Wallet and DUST status, masking, and profile isolation | Presentation projection tests and independent Maestro flows | [#1207](https://github.com/betsudo/oxid/issues/1207) |
| Ledger-backed DID, strict QR issuance, and encrypted restore | On-demand physical Android demo | [#1208](https://github.com/betsudo/oxid/issues/1208) |

Run deterministic checks in the normal development gates. Run the physical
scenario locally on demand and before a physical demo or release qualification.
