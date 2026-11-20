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
HTTPS Portal configuration and issuer key, then authenticates node genesis
and checks the private HTTPS proof server's `/version` for the Ledger 9
release paired with the app. The version check sends no witnesses or
provider credentials. If a required service cannot be reached, the app stays
on **Preview access**. Use
**Retry connection** after restoring connectivity. The wallet remains gated
until the signed deployment passes startup checks.

The Preview feature selects platform custody, native DID deployment, strict
Portal issuance, and the normal camera and link adapters. Wallet profiles,
checkpoints, DID records, encrypted credentials, and recovery journals are
stored in the app data directory scoped by network and genesis.

Deploy the artifact only to the receipt-owned simulator. Preview requires live
qualification. PreProd startup also requires the separate Blockfrost transport.

## Check the PreProd network before starting the wallet

Use the expected genesis from the independently reviewed signed profile.
Supply the PreProd project ID from a private input source that emits only the
credential, such as an owner-readable file. Use the normal local toolchain to
build the operator probe.

```bash
./bootstrap.sh -- cargo build --locked -p oxid-adapter-midnight --example preprod_preflight
target/debug/examples/preprod_preflight "$REVIEWED_PREPROD_GENESIS_HEX"   < "$OXID_PREPROD_PROJECT_ID_FILE"
```

The probe confirms the signed genesis over node WSS and checks the exact hash
of the HTTP indexer tip at the same node height. The node runtime and indexer
protocol at that block must both match the pinned Ledger 9 runtime. Its
receipt contains a public height or a bounded failure category. The mobile PreProd startup and Portal
issuance require their own qualification.

## Build and provision the isolated PreProd iOS profile

Use independently reviewed PreProd signed inputs. Export the PreProd trust
root and signed profile paths and SHA-256 pins using the
`OXID_BUILD_PREPROD_TRUST_ROOT_*` and `OXID_BUILD_PREPROD_SIGNED_PROFILE_*`
settings. Pin the Portal deployment manifest the same way as Preview.

```bash
OXID_MOBILE_CUSTODY=native OXID_MOBILE_PORTAL_PROFILE=preprod   ./bootstrap.sh -- bash scripts/run-ios-simulator.sh build
```

On first launch, choose **Enter project ID** and save the PreProd credential
in the native secure field. Tap **Retry connection** after saving. The
credential is stored in a device-only Keychain item and stays outside the
app build, the wallet profile, and the UI's state. Startup checks signed
inputs before accessing the credential. The background startup worker
requires the node genesis, the indexed block hash, and the GraphQL
WebSocket acknowledgement to agree with the configured routes.

The build links a simulator-only Keychain identity into the simulator
executable. Physical iOS builds use their provisioned application identifier
and Keychain access group. [Apple Keychain entitlement guidance](https://developer.apple.com/documentation/security/errsecmissingentitlement)

## Replay wallet history across the Ledger 9 upgrade

The Preview and PreProd indexers retain legacy DUST and shielded history.
Oxid's public Portal build includes the native Ledger 8 decoder for that
history and selects the decoder from each event's `protocolVersion`. A
missing or invalid version, a wire-format mismatch, or a return to Ledger 8
after Ledger 9 stops replay at the most recent durable checkpoint.

The DUST cursor survives the transition. The Ledger 9 DUST tree starts empty
and replays the new era's registrations. Shielded replay carries its
commitment tree, owned notes, and observed outputs into Ledger 9. The wallet
releases reservations from legacy pending spends. Checkpoints record the
active ledger era, so a restart resumes with the correct decoder and the
same next cursor. Historical checkpoints can report progress while live
synchronization catches up. The native worker can reopen the stream from its
latest durable cursor when a replay window fills. This keeps sync progress
visible while retaining the overall session deadline. Transaction preparation
requires a current Ledger 9 result.

Run the bounded native regression matrix before public qualification:

```bash
./bootstrap.sh -- cargo test --locked -p oxid-adapter-midnight --lib --features mixed-era-replay
```

The transport fixtures reopen DUST and shielded checkpoints before and after
the transition. They compare the resumed cursors and serialized wallet state
with uninterrupted replay at the same tip, then reject a return to Ledger 8.
Use the signed deployment to qualify real history on Preview and PreProd.
The standalone builds continue to use their Ledger 9 stream.
See [Midnight's Ledger 9 upgrade notes](https://docs.midnight.network/relnotes/ledger-9#detect-the-upgrade-in-your-wallet-or-dapp)
and [Oxid #1212](https://github.com/betsudo/oxid/issues/1212).

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

## Prepare the physical Android Preview demo

Finish the Preview and PreProd simulator qualifications first. Use Preview
for the Android handoff in [#1203](https://github.com/betsudo/oxid/issues/1203).
Use the same reviewed Preview trust root, signed profile, Portal manifest,
and independent digests as the simulator qualification. On a clean checkout
of the approved Oxid commit, build the ARM64 test APK without connecting a
device.

```bash
OXID_MOBILE_PORTAL_PROFILE=preview ./bootstrap.sh -- just android-release-build
```

The command builds only the protected Preview composition. Cargo verifies
the signed profile, audience, network, and Portal manifest digest. The build
then checks the packaged ABI, 16 KiB alignment, and exactly one APK signer,
and writes both files under `target/android-release-candidate/preview/`
with their own receipt schema. The receipt binds the signed inputs, native
DID artifact manifest, and signer fingerprint. Compare the Gradle test
signer's fingerprint with the installed Oxid APK's signer before authorizing
an in-place update.

Check the receipt and artifact immediately before handing them to the device
operator.

```bash
candidate=target/android-release-candidate/preview
apk="$candidate/oxid-app-arm64-v8a-release.apk"
receipt="$candidate/receipt.json"
jq -e '.schema == "oxid-android-preview-candidate-receipt-v1"
  and .preview.network == "preview" and .preview.features == "preview-portal"' "$receipt"
test "$(git rev-parse HEAD)" = "$(jq -er '.source.head' "$receipt")"
test "$OXID_BUILD_PREVIEW_SIGNED_PROFILE_SHA256" = "$(jq -er '.preview.signedProfileSha256' "$receipt")"
test "$OXID_BUILD_PREVIEW_TRUST_ROOT_SHA256" = "$(jq -er '.preview.trustRootSha256' "$receipt")"
test "$OXID_BUILD_PORTAL_DEPLOYMENT_MANIFEST_SHA256" = "$(jq -er '.preview.portalManifestSha256' "$receipt")"
test "$(shasum -a 256 "$apk" | cut -d' ' -f1)" = "$(jq -er '.artifact.sha256' "$receipt")"
```

When the owner authorizes the exact physical device and confirms signer
continuity, install with `adb -s "$AUTHORIZED_DEVICE" install -r "$apk"`.
If Android rejects the signature or version, resolve the signing or version
issue before proceeding. Preserve the owner's wallet data throughout the
demo. Use a separate protected test wallet for the public journey.

Follow the public qualification steps with a fresh Portal QR displayed on a
separate screen. After issuance, terminate and relaunch the app with its
data intact and verify the restored credential against the public resolver.
Record the verified source and APK digests, signer fingerprint, chain
identity, and non-sensitive outcomes. The handoff is `READY` when the
simulator qualifications, approved signed install, physical scan, issuance,
encrypted restart, and fresh reverification all pass. Record `NOT_READY`
with the first unmet prerequisite otherwise.
