# Sourced by the CI lanes whose test programs link the flake's OpenSSL.
#
# Those programs are linked by Alire's gcc against the runner's glibc, but
# -lcrypto comes from the flake, and the flake's libcrypto pulls in the
# flake's libdl and libpthread. Under the runner's loader, the process then
# mixes two glibcs. On an older runner (ubuntu-24.04, glibc 2.39) the flake's
# libdl asks the runner's libc.so.6 for symbol versions it doesn't have
# ("GLIBC_ABI_DT_X86_64_PLT not found"). Run each such program under the
# flake's own loader instead, as tests/timing/run_ctgrind.sh does, so the
# whole process uses the flake's glibc. glibc is backward compatible, so a
# program linked against an older runner glibc runs under it.
#
# use_flake_loader PROGRAM...   (a no-op outside `nix develop`)
use_flake_loader() {
    if [ -z "${NIX_CC:-}" ] || [ ! -f "$NIX_CC/nix-support/dynamic-linker" ]; then
        return 0
    fi
    local loader
    loader="$(cat "$NIX_CC/nix-support/dynamic-linker")"
    command -v patchelf >/dev/null 2>&1 || { echo "patchelf not installed" >&2; return 2; }
    local exe
    for exe in "$@"; do
        patchelf --set-interpreter "$loader" "$exe"
    done
}
