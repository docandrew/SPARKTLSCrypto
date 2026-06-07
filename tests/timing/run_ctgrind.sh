#!/usr/bin/env bash
set +e

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/../.."
BIN="$DIR/bin"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind not installed; aborting"
  exit 2
fi

echo "Rebuilding library + timing harnesses in ctgrind mode..."
(
  cd "$DIR" &&
  SPARKTLSCRYPTO_BUILD_MODE=ctgrind alr -n --no-tty build >/dev/null 2>&1
)
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed; aborting"
  exit 2
fi

run_one() {
  local name="$1" expect_errs="$2"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  local out
  out=$(valgrind --tool=memcheck --error-exitcode=1 \
                 --track-origins=yes --quiet "$exe" 2>&1)
  local errs
  errs=$(echo "$out" | grep -c "Use of uninitialised\\|Conditional jump.*uninitialised")
  if [ "$expect_errs" = "0" ]; then
    if [ "$errs" -eq 0 ]; then
      echo "  PASS  $name (0 errors)"
    else
      echo "  FAIL  $name ($errs errors)"
      echo "$out" | sed 's/^/      /' | head -20
      return 1
    fi
  else
    if [ "$errs" -gt 0 ]; then
      echo "  PASS  $name ($errs errors from expected canary leak)"
    else
      echo "  FAIL  $name (0 errors; canary should have leaked)"
      return 1
    fi
  fi
}

echo "=== ctgrind constant-time analysis ==="
echo ""
fail=0
run_one ct_negative_control 1   || fail=1
run_one ct_chacha20_poly1305 0  || fail=1
run_one ct_poly1305_scalar   0  || fail=1
run_one ct_x25519            0  || fail=1
run_one ct_ed25519           0  || fail=1
run_one ct_p256_ecdsa        0  || fail=1
run_one ct_p384_ecdsa        0  || fail=1
run_one ct_hkdf              0  || fail=1
run_one ct_aes_gcm           0  || fail=1
run_one ct_aead_decrypt      0  || fail=1
run_one ct_rfc6979           0  || fail=1
run_one ct_hmac              0  || fail=1

echo ""
if [ "$fail" -eq 0 ]; then
  echo "=== ALL constant-time checks pass ==="
  rc=0
else
  echo "=== CONSTANT-TIME REGRESSION ==="
  rc=1
fi

echo "Restoring optimize build..."
(
  cd "$ROOT" &&
  SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >/dev/null 2>&1
)

exit "$rc"
