#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1 NO_COLOR=1
SPARKTLSCRYPTO_BUILD_MODE=optimize \
SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled \
SPARKTLSCRYPTO_CONTRACTS=enabled \
    alr -n --no-tty exec -- gprbuild -f -s -P tests/gcm16_fused/gcm16_fused.gpr \
        test_fused.adb -j"${JOBS:-8}"
tests/gcm16_fused/bin/test_fused
alr -n --no-tty build -- -f -s
