{
  description = "Reproducible SPARKTLSCrypto build environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              alire
              bash
              coreutils
              findutils
              gcc
              git
              gnugrep
              gnused
              gnumake
              valgrind
              which
            ];

            shellHook = ''
              echo "SPARKTLSCrypto dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
