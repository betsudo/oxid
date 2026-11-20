# Offline PreProd startup fixtures

This fixture binds the canonical Blockfrost PreProd routes to a synthetic
genesis and reserved issuer, resolver and proof routes. It verifies feature
composition and signed-input handling without admission to a live deployment.
The disposable signer has no authority outside the fixture.

`keychain-profile.json` is for the packaged iOS persistence test. It shares
the fixture signer and manifest and substitutes a reserved node route.
Production route admission rejects that route before sending the synthetic
project ID. Reaching this rejection again after app relaunch proves the
device-local Keychain record was retained.
