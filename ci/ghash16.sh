#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
python3 tests/ghash16/check_algebra.py
SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled SPARKTLSCRYPTO_CONTRACTS=enabled \
    alr -n --no-tty exec -- gprbuild -f -s -P tests/ghash16/ghash16.gpr \
        test_ghash16.adb -j"${JOBS:-0}"
tests/ghash16/bin/test_ghash16
alr -n --no-tty build -- -s
