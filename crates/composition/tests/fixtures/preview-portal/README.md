# Offline Preview startup fixtures

These signed profiles use reserved `.test` routes, a synthetic genesis, an
existing public Jubjub test point in Ledger 9 encoding, and a disposable
Ed25519 signer. Only the public key and signatures are retained.
`wrong-network.json` is correctly signed and selects PreProd.

Run the admission tests from the pinned development shell.

```sh
cargo test --locked -p oxid-composition --features public-portal \
  --lib profile_production::preview_startup::tests
```

Use these fixtures for admission and compile checks. A live build requires the
reviewed service deployment and its signed profile.
