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
4. Verify the signed profile and authenticate the live node genesis. Admit the
   Portal manifest via `AuthenticatedProductionDeployment::authenticate_portal_manifest`
   using the already-authenticated profile. The admission requires a same-network
   issuer DID and an exact match for both HTTPS routes. The issuer metadata uses
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

## Compose the Preview wallet

The `oxid-composition/public-portal` feature installs the protected mobile
wallet, native DID deployment, and strict Portal issuance through
`compose_authenticated_public_portal`. Supply the authenticated deployment
and its bound manifest together. The composition requires the native DID
artifacts and stores wallet profiles, checkpoints, submission and recovery
journals, DID records, and encrypted credentials under the platform data
directory scoped by network and genesis. A fresh chain gets a fresh scope.

Public DUST registration uses protected authorization. The development
automatic-registration authority is isolated to its existing local path.
The public mobile app still needs a signed Preview startup profile and a
user-facing protected DUST authorization flow before funded live testing.
PreProd startup also needs the separate Blockfrost transport.

## Qualify the public app

Use protected native custody. On the receipt-owned simulator, fund the fresh
holder, observe automatic DUST readiness, deploy and resolve the holder DID,
and accept the Portal Digital Passport offer through the normal consent flow.
Check the encrypted store, replace the app process with its data intact, and
require fresh resolver-backed reverification. Capture exact source and
artifact hashes, non-sensitive results, durations, and simulator cleanup.
Physical-device evidence is a separate run.

The manifest admission boundary is only one prerequisite. Public wallet
composition, actual service readiness, and completion of the full journey
determine demo readiness. Track Preview in
[#1201](https://github.com/betsudo/oxid/issues/1201) and PreProd in
[#1202](https://github.com/betsudo/oxid/issues/1202).
