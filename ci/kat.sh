#!/usr/bin/env bash
# NIST CAVP known-answer tests: the HMAC_DRBG SHA-256 vectors (both the
# no-reseed and reseed files), plus the mechanism's built-in self-test and
# its reseed gate. The archive is fetched once, pinned by SHA-256.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/kat"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
echo "== known-answer tests =="
bash fetch.sh
alr -n --no-tty build
bin/kat_hmac_drbg vectors
