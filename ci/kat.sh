#!/usr/bin/env bash
# Known-answer tests: the NIST CAVP HMAC_DRBG SHA-256 vectors (both the
# no-reseed and reseed files), plus the mechanism's built-in self-test and
# its reseed gate; the NIST CAVP GCM decryption vectors and Wycheproof's
# AES-GCM vectors on every AES-GCM tier the CPU has. The archives are
# fetched once, pinned by SHA-256.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/kat"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
echo "== known-answer tests =="
bash fetch.sh
alr -n --no-tty build
bin/kat_hmac_drbg vectors
bin/kat_aes_gcm vectors
