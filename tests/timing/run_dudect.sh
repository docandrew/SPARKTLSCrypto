#!/usr/bin/env bash
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/bin"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "Rebuilding library + timing harnesses in optimize mode..."
(
  cd "$DIR" &&
  SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1
)
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed; aborting"
  exit 2
fi

echo "=== dudect statistical timing analysis ==="
echo ""

run_one() {
  local name="$1"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  echo "--- $name ---"
  local out
  out=$("$exe" 2>&1)
  local status=$?
  echo "$out"
  echo ""
  if echo "$out" | grep -q "TIMING DEPENDS ON SECRET INPUT"; then
    return 1
  fi
  return "$status"
}

fail=0
run_one dudect_x25519      || fail=1
run_one dudect_p256_ecdsa  || fail=1
run_one dudect_p384_ecdsa  || fail=1
run_one dudect_aead        || fail=1

if [ "$fail" -eq 0 ]; then
  echo "=== ALL dudect checks pass ==="
else
  echo "=== DUDECT TIMING REGRESSION ==="
fi

exit "$fail"
