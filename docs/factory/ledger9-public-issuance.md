# Ledger 9 public issuance

Use the [local qualification](ledger9-local-issuance.md) first. Preview is the
first public phase. PreProd adds the separate Blockfrost transport admission
from [#1200](https://github.com/betsudo/oxid/issues/1200). Qualify one iOS
Simulator before the physical-device handoff.

## Sign one deployment

1. Start with the current public chain identity and the reviewed node, indexer,
   and private prover routes. Use fresh wallet and sync state for Preview.
2. Obtain an issuer DID on that chain and verify its Jubjub assertion method
   through the reviewed resolver. Record the exact Portal source lock and
   generate the canonical Ledger 9 Portal deployment manifest.
3. Put the issuer metadata URL, resolver base URL, and exact SHA-256 of the
   manifest in the signed deployment profile. The optional
   `ssi.portalManifestSha256` field is 64 lower-case hexadecimal characters.
   Deliver the exact manifest bytes with that profile.
4. Verify the signed profile and Portal configuration before requesting node
   genesis. The admission requires a same-network issuer DID and an exact
   match for both HTTPS routes. The issuer metadata uses
   `/.well-known/openid-credential-issuer` at the manifest's issuer origin.
   The resolver value is the base URL, including a path prefix when configured.
5. Require the issuer DID, assertion key, metadata, private prover, and
   resolver to be ready before creating an offer. Only use a fresh offer after
   the funded holder's DUST and native DID are ready.

The signature covers the optional manifest digest. A profile that omits it can
still be used for observation. Portal issuance requires the signed digest.
Local and Tailnet use their existing manifest routes. Keep transport
credentials, seeds, proofs, and offer contents out of profile bytes and run
evidence.

## Build the Preview app

The owner supplies three immutable public files:

- A reviewed trust root with `keyId`, `verifyingKeyHex` (the 32-byte Ed25519
  public key), `validFromSeconds`, `validUntilSeconds`,
  `minimumProfileSequence`, and optional `revokedAtSeconds`.
- The signed Preview deployment profile for audience `io.medianox.oxid`.
- The canonical Portal deployment manifest whose digest is inside that signed
  profile.

Export the absolute paths and independently reviewed SHA-256 digests:

```sh
export OXID_BUILD_PREVIEW_TRUST_ROOT_PATH=/absolute/path/preview-trust-root.json
export OXID_BUILD_PREVIEW_TRUST_ROOT_SHA256="reviewed-sha256"
export OXID_BUILD_PREVIEW_SIGNED_PROFILE_PATH=/absolute/path/preview-profile.json
export OXID_BUILD_PREVIEW_SIGNED_PROFILE_SHA256="reviewed-sha256"
export OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_PATH=/absolute/path/portal-deployment.json
export OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256="reviewed-sha256"
OXID_MOBILE_CUSTODY=native OXID_MOBILE_PORTAL_PROFILE=preview \
  ./bootstrap.sh -- bash scripts/run-ios-simulator.sh build
```

The build verifies the signed profile with the independent trust root and
requires its Portal digest to match. The artifact receipt binds all three
digests. Startup rechecks signature and time validity, admits the exact
HTTPS Portal configuration and issuer key, then authenticates node genesis.
The Preview feature selects platform custody, native DID deployment, strict
Portal issuance, and the normal camera and link adapters. Wallet profiles,
checkpoints, DID records, encrypted credentials, and recovery journals are
stored in the app data directory scoped by network and genesis.

Deploy the artifact only to the receipt-owned simulator. Preview requires live
qualification. PreProd startup also requires the separate Blockfrost transport.

## Qualify the public app

Use protected native custody. On the receipt-owned simulator, fund the fresh
holder and open **Wallet status**. When **Review needed** appears under DUST,
open **Review DUST registration**, check the NIGHT amount and maximum DUST fee,
then select **Confirm registration**. Wait for the wallet to confirm the
transaction and refresh its DUST balance automatically. Deploy and resolve the
holder DID, then accept the Portal Digital Passport offer.
Check the encrypted store, replace the app process with its data intact, and
require fresh resolver-backed reverification. Capture exact source and
artifact hashes, non-sensitive results, durations, and simulator cleanup.
Physical-device evidence is a separate run.

The manifest admission boundary is only one prerequisite. Public wallet
composition, actual service readiness, and completion of the full journey
determine demo readiness. Track Preview in
[#1201](https://github.com/betsudo/oxid/issues/1201) and PreProd in
[#1202](https://github.com/betsudo/oxid/issues/1202).
