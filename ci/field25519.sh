#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1 NO_COLOR=1

# Check all public limb bounds with an independent OpenSSL bignum oracle.
SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled SPARKTLSCRYPTO_CONTRACTS=enabled \
    alr -n --no-tty exec -- gprbuild -s -P tests/field25519/field25519.gpr \
        test_field25519.adb -j"${JOBS:-0}"
tests/field25519/bin/test_field25519
# Restore the caller's build switches for subsequent CI lanes.
alr -n --no-tty build -- -s
