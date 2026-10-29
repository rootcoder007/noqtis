# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# Nix: `nix build` builds noqtis (shared, every test run in checkPhase);
# `nix build .#consumer` (also a flake check) builds the consumer program
# against it through pkg-config and find_package.
{
  description = "noqtis: post-quantum signing, KEMs and sealed input records";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin"
                  "aarch64-darwin" ];
      each = f: nixpkgs.lib.genAttrs systems
        (system: f nixpkgs.legacyPackages.${system});
      mk = pkgs: rec {
        noqtis = pkgs.stdenv.mkDerivation {
          pname = "noqtis";
          version = "0.1.1";
          src = self;
          nativeBuildInputs = [ pkgs.cmake ];
          cmakeFlags = [ "-DNQSHARED=ON" "-DNQWERROR=OFF" ];
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            ctest --output-on-failure -j $NIX_BUILD_CORES
            runHook postCheck
          '';
          meta = {
            description =
              "Post-quantum signing, KEMs and sealed input records in C11";
            homepage = "https://github.com/rootcoder007/noqtis";
            license = with pkgs.lib.licenses; [ asl20 llvm-exception ];
            platforms = pkgs.lib.platforms.unix;
          };
        };
        consumer = pkgs.stdenv.mkDerivation {
          name = "noqtis-consumer";
          src = ./tests/consumer;
          nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
          dontUseCmakeConfigure = true;
          buildPhase = ''
            sh ./run.sh ${noqtis} "$TMPDIR/use"
          '';
          installPhase = "touch $out";
        };
        default = noqtis;
      };
    in {
      packages = each mk;
      checks = each (pkgs: { inherit (mk pkgs) consumer; });
    };
}
