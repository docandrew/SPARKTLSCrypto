#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export ALR_NON_INTERACTIVE=1 NO_COLOR=1
python3 tools/generate_ed25519_base.py --check
SPARKTLSCRYPTO_BUILD_MODE=optimize SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled SPARKTLSCRYPTO_CONTRACTS=enabled     alr -n --no-tty exec -- gprbuild -f -s -P tests/base25519/base25519.gpr         test_base25519.adb -j"${JOBS:-8}"
result="$(mktemp)"
trap 'rm -f "$result"' EXIT
tests/base25519/bin/test_base25519 >"$result"
python3 - "$result" <<'PYHASH'
from pathlib import Path
import hashlib,sys
actual=hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
expected=Path("tests/base25519/golden.sha256").read_text().split()[0]
if actual != expected:raise SystemExit("fixed-base golden mismatch: "+actual)
print("PASS: 4096 fixed-base cases match OpenSSL and baseline golden "+actual)
PYHASH
# Restore the caller's configuration, including rebuilding its archive.
alr -n --no-tty build -- -f -s
