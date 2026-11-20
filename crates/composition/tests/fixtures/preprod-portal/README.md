# Offline PreProd startup fixtures

This fixture binds the canonical Blockfrost PreProd routes to a synthetic
genesis and reserved issuer, resolver and proof routes. It verifies feature
composition and signed-input handling without admission to a live deployment.
The disposable signer has no authority outside the fixture.
