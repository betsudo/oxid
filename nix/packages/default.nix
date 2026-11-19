{ inputs, ... }:

{
  perSystem =
    { pkgs, self', ... }:
    let
      midnightDidPackages = inputs.midnight-did-toolchain.packages.${pkgs.stdenv.hostPlatform.system};
      rustToolchain = inputs.fenix.packages.${pkgs.stdenv.hostPlatform.system}.toolchainOf {
        channel = "1.99.0";
        sha256 = "sha256-zm3dyIY2T414ZRR3EhLOvptzG6gta4WZUcawzMUWtqI=";
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain.cargo;
        rustc = rustToolchain.rustc;
      };
      compactSource =
        (builtins.fromJSON (builtins.readFile ../../config/midnight-integration-compatibility.json))
        .wallet.compact;
      buildRustPackage = rustPlatform.buildRustPackage.override {
        importCargoLock = rustPlatform.importCargoLock.override {
          # Compact's retained CI evidence mentions Nix store paths. Fetch the
          # reviewed Git tree directly so the evidence does not enter a fetchgit
          # fixed-output derivation. Keep the exact revision and NAR hash.
          fetchgit =
            source:
            if source.url == compactSource.repository && source.rev == compactSource.revision then
              (builtins.fetchTree {
                type = "git";
                inherit (source) url rev;
                allRefs = true;
                submodules = true;
                narHash = source.sha256;
              }).outPath
            else
              pkgs.fetchgit source;
        };
      };
      midnightDidCompactArtifacts = pkgs.callPackage ./midnight-did-compact-artifacts.nix { };
      midnightDidLedger9Zkir = pkgs.callPackage ./midnight-did-ledger9-zkir.nix {
        midnightIdentitySource = inputs.midnight-identity-ledger9;
        zkirCompiler = inputs.midnight-zkir-ledger9.packages.${pkgs.stdenv.hostPlatform.system}.zkir;
        publicParams =
          inputs.midnight-zkir-ledger9.packages.${pkgs.stdenv.hostPlatform.system}.public-params;
      };
      cargoOutputHashes = {
        "midnight-base-crypto-1.1.1" = "sha256-7nPujsILZToXHIBcRemu8NLrxmrg2+QM4sKPsJwGgu0=";
        "midnight-compact-runtime-0.2.0" = "sha256-Z7UM69FOS0DWefFGW71GlEz2lYWTOFoi1XnekD2jgM8=";
        "midnight-did-domain-0.5.0" = "sha256-J684SunbTIK8fblcMAtBg7lTFj0lzyzpiRNDW9w2Uv4=";
        "midnight-proofs-0.8.2" = "sha256-lofqa58hDlJ0C3vIWFodsdwYYwYoPEDpS1PMGV9TULg=";
        "midnight-zkir-3.2.1" = "sha256-GtULoNDWGXjgIf9Vh8C4OXKlRLwm37lDQ+f0DAay/9c=";
      };
      presentationCompactArtifacts = pkgs.callPackage ./presentation-compact-artifacts.nix {
        compactMidnight = midnightDidPackages.compact-midnight;
        compactToolchain = midnightDidPackages.compact-toolchain;
        midnightCircuitParams = midnightDidPackages.midnight-circuit-params;
        midnightVcSource = inputs.midnight-verifiable-credentials;
      };
      oxidApp = buildRustPackage {
        pname = "oxid";
        version = "0.2.0";
        src = pkgs.lib.cleanSource ../..;

        cargoLock = {
          lockFile = ../../Cargo.lock;
          outputHashes = cargoOutputHashes;
        };
        cargoBuildFlags = [
          "-p"
          "oxid-app"
        ];
        cargoTestFlags = [ "--workspace" ];
        nativeBuildInputs = [ pkgs.pkg-config ] ++ linuxNativeBuildInputs;
        buildInputs = [ pkgs.openssl ] ++ linuxBuildInputs;

        # Per-push CI verifies tests once in the repository gate; the hermetic
        # re-run lives in the checked variants below, exercised by
        # `nix flake check` and the nightly workflow.
        doCheck = false;
        strictDeps = true;

        meta = {
          description = "Rust-first identity-native wallet foundation";
          homepage = "https://github.com/MediaNoxLabs/oxid";
          license = pkgs.lib.licenses.asl20;
          mainProgram = "oxid-app";
        };
      };
      brandCheck = buildRustPackage {
        pname = "oxid-brand-check";
        version = "0.2.0";
        src = pkgs.lib.cleanSource ../..;

        cargoLock = {
          lockFile = ../../Cargo.lock;
          outputHashes = cargoOutputHashes;
        };
        cargoBuildFlags = [
          "-p"
          "oxid-brand-build"
          "--bin"
          "oxid-brand-check"
        ];
        cargoTestFlags = [
          "-p"
          "oxid-brand-build"
        ];
        strictDeps = true;

        meta = {
          description = "Validated Oxid build-time brand-pack checker";
          homepage = "https://github.com/MediaNoxLabs/oxid";
          license = pkgs.lib.licenses.asl20;
          mainProgram = "oxid-brand-check";
        };
      };
      brandDirectories = pkgs.lib.filterAttrs (_name: kind: kind == "directory") (
        builtins.readDir ../../brands
      );
      brandChecks = pkgs.lib.mapAttrs' (
        name: _kind:
        pkgs.lib.nameValuePair "brand-${name}" (
          pkgs.runCommand "oxid-brand-${name}-check" { nativeBuildInputs = [ brandCheck ]; } ''
            oxid-brand-check ${../../brands}/${name}
            touch $out
          ''
        )
      ) brandDirectories;
      linuxBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.glib
        pkgs.gtk3
        pkgs.libsoup_3
        pkgs.webkitgtk_4_1
        pkgs.xdotool
      ];
      linuxNativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.wrapGAppsHook3
      ];
    in
    {
      packages = {
        default = oxidApp;

        oxid-app-oxid = oxidApp;

        brand-check = brandCheck;

        headless = buildRustPackage {
          pname = "oxid-headless";
          version = "0.2.0";
          src = pkgs.lib.cleanSource ../..;

          cargoLock = {
            lockFile = ../../Cargo.lock;
            outputHashes = cargoOutputHashes;
          };
          cargoBuildFlags = [
            "-p"
            "oxid-headless"
          ];
          cargoTestFlags = [
            "-p"
            "oxid-headless"
          ];

          # See packages.default: hermetic tests run in the checked variant.
          doCheck = false;
          strictDeps = true;

          meta = {
            description = "Headless Oxid wallet flow harness";
            homepage = "https://github.com/MediaNoxLabs/oxid";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "oxid-headless";
          };
        };

        presentation-compact-artifacts = presentationCompactArtifacts;

        midnight-did-compact-artifacts = midnightDidCompactArtifacts;

        midnight-did-ledger9-zkir = midnightDidLedger9Zkir;

        dioxus-cli = pkgs.dioxus-cli;

        # Pinned through flake.lock; local Maestro pilots never fetch a global CLI.
        maestro = pkgs.maestro;
      }
      // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
        xcodegen = pkgs.xcodegen;
      };

      # The checked variants re-enable the hermetic sandbox test run that the
      # per-push package builds skip; `nix flake check` and the nightly
      # workflow build these.
      checks = {
        package = self'.packages.default.overrideAttrs (_: {
          doCheck = true;
        });
        headless = self'.packages.headless.overrideAttrs (_: {
          doCheck = true;
        });
        presentation-compact-artifacts = presentationCompactArtifacts;
        midnight-did-compact-artifacts = midnightDidCompactArtifacts;
        midnight-did-ledger9-zkir = midnightDidLedger9Zkir;
        brand-packs =
          pkgs.runCommand "oxid-brand-packs-check"
            {
              nativeBuildInputs = [ brandCheck ];
            }
            ''
              oxid-brand-check ${../../brands}
              touch $out
            '';
      }
      // brandChecks;
      formatter = pkgs.nixfmt;
    };
}
