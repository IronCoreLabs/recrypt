{
  inputs = {
    typelevel-nix.url = "github:typelevel/typelevel-nix";
    nixpkgs.follows = "typelevel-nix/nixpkgs";
    flake-utils.follows = "typelevel-nix/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, typelevel-nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ typelevel-nix.overlays.default ];
        };

        mkShell = jdk: pkgs.devshell.mkShell {
          imports = [ typelevel-nix.typelevelShell ];
          name = "recrypt";
          typelevelShell = {
            jdk.package = jdk;
          };
        };
      in
      rec {
        devShell = devShells."temurin@25";

        devShells = {
          "temurin@25" = mkShell pkgs.temurin-bin-25;
        };
      }
    );
}

