#!/usr/bin/env bash
# Verify the generated Fiat_* bodies still match their generator output.
#
# src/sparktlscrypto-fiat_p384.adb and -fiat_p384_scalar.adb are produced
# mechanically from fiat-crypto's Coq-verified C by tools/fiat/generate.py.
# This check regenerates them and requires a byte-exact match, which catches:
#
#   * a generated file edited by hand (the usual way generated code rots)
#   * a change to the translator that silently alters output
#   * the pinned fiat-crypto C sources being swapped underneath
#
# What this check does NOT do is prove the translation is correct. That rests
# on two other things, documented in tools/fiat/README.md:
#   1. a one-time manual validation -- the same translator was run over
#      p256_64.c and its Mul body compared statement-by-statement against the
#      pre-existing hand-written Fiat_P256 port (all 103 arithmetic statements
#      identical). Note the rest of that hand port inlines some primitive
#      calls, so it is NOT a mechanical whole-file match and is not asserted
#      as one here.
#   2. the test suite -- P-384 KATs, CAVP, wycheproof and the ECDSA/ECDHE
#      integration tests, which is what actually gates a release.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="$ROOT/tools/fiat/generate.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -f "$ROOT/tools/fiat/p384_64.c" ]]; then
    echo "SKIP: pinned fiat-crypto sources absent; see tools/fiat/README.md"
    exit 0
fi

rc=0
for target in p384 p384_scalar; do
    committed="$ROOT/src/sparktlscrypto-fiat_${target}.adb"
    if [[ ! -f "$committed" ]]; then
        echo "SKIP: $committed not present yet"
        continue
    fi
    python3 "$GEN" "$target" > "$TMP/$target.adb" 2>"$TMP/err" || {
        echo "FAIL: generator errored for $target"; cat "$TMP/err"; rc=1; continue; }
    if diff -q "$committed" "$TMP/$target.adb" >/dev/null; then
        echo "PASS: $(basename "$committed") matches generator output"
    else
        echo "FAIL: $(basename "$committed") differs from generator output"
        diff "$committed" "$TMP/$target.adb" | head -30
        echo "      Regenerate with: tools/fiat/generate.py $target > $committed"
        rc=1
    fi
done

exit $rc
