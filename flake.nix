{
  description = "Reproducible SPARKTLSCrypto build environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # HACL* (F*-verified crypto, extracted C): used ONLY as a test oracle by
    # tests/fuzz (its verified generic Montgomery multiply and modular
    # exponentiation, Hacl_Bignum64). Pinned by commit; nothing from it is
    # linked into the library.
    hacl-star = {
      url = "github:hacl-star/hacl-star/504c2987452f87fe44bce9b9f12e19d6e051761f";
      flake = false;
    };
  };

  outputs =
    { nixpkgs, hacl-star, ... }:
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
              openssl
              openssl.dev
              patchelf
              valgrind
              valgrind.dev
              which
            ];

            shellHook = ''
              export C_INCLUDE_PATH="${pkgs.valgrind.dev}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
              # The OpenSSL oracle of tests/prepared is compiled by Alire's
              # GCC, which does not see the Nix compiler wrapper's flags:
              # give it this OpenSSL's headers, and tests/prepared/prepared.gpr
              # links and sets the run path from SPARKTLSCRYPTO_OPENSSL_LIB.
              export C_INCLUDE_PATH="${pkgs.openssl.dev}/include:$C_INCLUDE_PATH"
              export SPARKTLSCRYPTO_OPENSSL_LIB="${pkgs.openssl.out}/lib"
              export HACL_STAR_SRC="${hacl-star}"
              echo "SPARKTLSCrypto dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
