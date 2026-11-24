{
  description = "Oxid identity wallet - reproducible Rust and Dioxus environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix.url = "github:nix-community/fenix";
    flake-parts.url = "github:hercules-ci/flake-parts";
    midnight-did-toolchain.url = "github:midnightntwrk/midnight-did/05b237a5e51f9c22853b424e7d4236dfa9384c24";
    midnight-verifiable-credentials = {
      url = "github:midnightntwrk/midnight-verifiable-credentials/39b1354212620b396e914b29603e6a38f2656546";
      flake = false;
    };
    # Immutable merge commit of the qualified Ledger 9 DID/VC migration.
    midnight-identity-ledger9 = {
      url = "git+https://github.com/betsudo/midnight-identity?rev=a18fc76406db35bf38fb0618b2102ef97e31dc7c&ref=develop&submodules=1";
      flake = false;
    };
    midnight-zkir-ledger9.url = "github:betsudo/midnight-zkir/3377ad9e48741f60e0aa17010b6f23e34223d906";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        ./nix/packages
        ./nix/devshells
      ];
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
    };
}
