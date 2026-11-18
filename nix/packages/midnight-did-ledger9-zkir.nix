{
  lib,
  stdenvNoCC,
  jq,
  coreutils,
  midnightIdentitySource,
  zkirCompiler,
  publicParams,
}:

stdenvNoCC.mkDerivation {
  pname = "oxid-midnight-did-ledger9-artifacts";
  version = "0.5.0-e50d606";

  src = midnightIdentitySource;
  nativeBuildInputs = [
    jq
    coreutils
    zkirCompiler
    publicParams
  ];
  MIDNIGHT_PP = publicParams;

  dontConfigure = true;

  buildPhase = ''
    runHook preBuild
    mkdir -p build/zkir build/keys
    for circuit in \
      setVerificationMethod \
      setSchnorrJubjubVerificationMethod \
      setVerificationMethodRelation
    do
      cp "crates/midnight-did-runtime/assets/keys/$circuit.zkir" build/zkir/
    done
    zkir compile-many build/zkir build/keys
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/keys" "$out/zkir"
    cp build/keys/*.prover build/keys/*.verifier "$out/keys/"
    cp build/zkir/*.bzkir "$out/zkir/"
    cp crates/midnight-did-runtime/assets/rust-compatibility.json "$out/"

    jq -n \
      --arg gitSha "e50d606c8b9cd7573bbe29e0a2d69726dd3d2a6b" \
      --arg version "0.5.0" \
      '
        def entry($id): {
          id: $id,
          files: {
            prover: ("keys/" + $id + ".prover"),
            verifier: ("keys/" + $id + ".verifier"),
            zkir: ("zkir/" + $id + ".bzkir")
          },
          sha256: { prover: "", verifier: "", zkir: "" }
        };
        {
          schema: "midnight-did-zk-artifacts",
          version: $version,
          gitSha: $gitSha,
          circuits: [
            entry("setVerificationMethod"),
            entry("setSchnorrJubjubVerificationMethod"),
            entry("setVerificationMethodRelation")
          ]
        }
      ' > "$out/manifest.json"

    for circuit in \
      setVerificationMethod \
      setSchnorrJubjubVerificationMethod \
      setVerificationMethodRelation
    do
      prover=$(sha256sum "$out/keys/$circuit.prover" | cut -d' ' -f1)
      verifier=$(sha256sum "$out/keys/$circuit.verifier" | cut -d' ' -f1)
      zkir=$(sha256sum "$out/zkir/$circuit.bzkir" | cut -d' ' -f1)
      jq \
        --arg id "$circuit" \
        --arg prover "$prover" \
        --arg verifier "$verifier" \
        --arg zkir "$zkir" \
        '(.circuits[] | select(.id == $id) | .sha256) = {
          prover: $prover,
          verifier: $verifier,
          zkir: $zkir
        }' \
        "$out/manifest.json" > "$out/manifest.json.next"
      mv "$out/manifest.json.next" "$out/manifest.json"
    done
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    test "$(jq -r .compatibility.ledger_version "$out/rust-compatibility.json")" = ledger-9.1.0.2
    test "$(jq -r .compatibility.runtime_abi "$out/rust-compatibility.json")" = 54
    test "$(jq -r .compatibility.ir_schema "$out/rust-compatibility.json")" = 20
    test "$(jq -r .compatibility.rust_version "$out/rust-compatibility.json")" = 1.99
    test "$(jq '.circuits | length' "$out/manifest.json")" = 3
    for circuit in \
      setVerificationMethod \
      setSchnorrJubjubVerificationMethod \
      setVerificationMethodRelation
    do
      test -s "$out/keys/$circuit.prover"
      test -s "$out/keys/$circuit.verifier"
      test -s "$out/zkir/$circuit.bzkir"
    done
  '';

  meta = {
    description = "Ledger 9 Midnight DID bootstrap proving closure";
    homepage = "https://github.com/betsudo/midnight-identity/pull/110";
    license = lib.licenses.asl20;
  };
}
