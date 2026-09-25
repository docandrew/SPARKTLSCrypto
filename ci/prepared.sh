#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

# OpenSSL EVP is an independent oracle, linked only into this test.
for tier in enabled disabled; do
    echo "== prepared AES-GCM differential tests: $tier =="
    SPARKTLSCRYPTO_ASM="$tier" \
    SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled \
    SPARKTLSCRYPTO_CONTRACTS=enabled \
        alr -n --no-tty exec -- gprbuild -s -P tests/prepared/prepared.gpr \
            test_prepared.adb -j"${JOBS:-0}"
    tests/prepared/bin/test_prepared
done

# Restore the caller's configuration before subsequent CI lanes. Without -s,
# GPRbuild can keep the checked objects when the requested switches change.
alr -n --no-tty build -- -s
