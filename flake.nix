{
  description = "slib";

  inputs = {
    nixpkgs.follows = "haskellNix/nixpkgs-2405";
    haskellNix = {
      url = "github:input-output-hk/haskell.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    iohkNix = {
      url = "github:input-output-hk/iohk-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, haskellNix, iohkNix }:
    let
      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];
    in
      flake-utils.lib.eachSystem supportedSystems (system:
      let
        overlays = [
          haskellNix.overlay
          iohkNix.overlays.utils
          (final: _prev: {
            hixProject =
              final.haskell-nix.hix.project {
                src = ./.;
                # uncomment with your current system for `nix flake show --allow-import-from-derivation` to work:
                evalSystem = "x86_64-linux";
              };
            fourmolu = final.hixProject.tool "fourmolu" "latest";
          })
        ];
        pkgs = import nixpkgs { inherit system overlays; inherit (haskellNix) config; };
        flake = pkgs.hixProject.flake {};
      in nixpkgs.lib.recursiveUpdate flake {
        legacyPackages = pkgs;

        hix = pkgs.hixProject;

        packages = {
        };
      });

  # --- Flake Local Nix Configuration ----------------------------
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
      "https://s3.ap-southeast-2.amazonaws.com/cache.sambnt.io"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "cache.sambnt.io:juiSxv2kOyXiXZuwx4RHuYmyUCdYmbAYAKdzBtkM7mo="
    ];
    allow-import-from-derivation = "true";
  };
}
