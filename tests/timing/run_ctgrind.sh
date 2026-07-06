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
build_log="$(mktemp)"
(
  cd "$DIR" &&
  SPARKTLSCRYPTO_BUILD_MODE=ctgrind alr -n --no-tty build >"$build_log" 2>&1
)
build_status=$?
if [ "$build_status" -ne 0 ]; then
  echo "Rebuild failed with status $build_status; aborting"
  echo ""
  echo "=== ctgrind rebuild log ==="
  cat "$build_log"
  rm -f "$build_log"
  exit 2
fi
rm -f "$build_log"

if [ -n "${NIX_CC:-}" ] && [ -f "$NIX_CC/nix-support/dynamic-linker" ]; then
  nix_ld="$(cat "$NIX_CC/nix-support/dynamic-linker")"
  if ! command -v patchelf >/dev/null 2>&1; then
    echo "patchelf not installed; aborting"
    exit 2
  fi
  for exe in "$BIN"/*; do
    if [ -x "$exe" ] && [ -f "$exe" ]; then
      patchelf --set-interpreter "$nix_ld" "$exe"
    fi
  done
fi

run_one() {
  local name="$1" mode="$2"
  local exe="$BIN/$name"
  if [ ! -x "$exe" ]; then
    echo "  $name: BINARY MISSING ($exe)"
    return 1
  fi
  local out
  out=$(valgrind --tool=memcheck --error-exitcode=1 \
                 --track-origins=yes --quiet "$exe" 2>&1)
  local status=$?
  local errs
  errs=$(echo "$out" |
    grep -E -c "Use of uninitiali[sz]ed|Conditional jump.*uninitiali[sz]ed|ERROR SUMMARY: [1-9]")
  if [ "$mode" = "clean" ]; then
    if [ "$status" -eq 0 ] && [ "$errs" -eq 0 ]; then
      echo "  PASS  $name (0 errors)"
    else
      echo "  FAIL  $name (valgrind status $status, $errs errors)"
      echo "$out" | sed 's/^/      /' | head -20
      return 1
    fi
  elif [ "$mode" = "canary" ]; then
    if [ "$status" -ne 0 ] || [ "$errs" -gt 0 ]; then
      echo "  PASS  $name ($errs errors from expected canary leak)"
    else
      echo "  FAIL  $name (0 errors; canary should have leaked)"
      echo "$out" | sed 's/^/      /' | head -20
      return 1
    fi
  elif [ "$mode" = "xfail" ]; then
    if [ "$errs" -gt 0 ]; then
      echo "  XFAIL $name ($errs known ctgrind errors)"
    else
      echo "  XPASS $name (known ctgrind finding no longer reproduces)"
      echo "      Remove the xfail entry for $name."
      return 1
    fi
  else
    echo "  $name: internal error: unknown mode '$mode'"
    return 1
  fi
}

echo "=== ctgrind constant-time analysis ==="
echo ""
fail=0
run_one ct_negative_control canary || fail=1
run_one ct_chacha20_poly1305 clean || fail=1
run_one ct_poly1305_scalar   clean || fail=1
run_one ct_x25519            clean || fail=1
run_one ct_ed25519           clean || fail=1
run_one ct_p256_ecdsa        clean || fail=1
run_one ct_p384_ecdsa        clean || fail=1
run_one ct_hkdf              clean || fail=1
run_one ct_aes_gcm           clean || fail=1
run_one ct_aead_decrypt      clean || fail=1
run_one ct_rfc6979           clean || fail=1
run_one ct_hmac              clean || fail=1

echo ""
if [ "$fail" -eq 0 ]; then
  echo "=== ALL constant-time checks pass ==="
  rc=0
else
  echo "=== CONSTANT-TIME REGRESSION ==="
  rc=1
fi

echo "Restoring optimize build..."
restore_log="$(mktemp)"
(
  cd "$ROOT" &&
  SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >"$restore_log" 2>&1
)
restore_status=$?
if [ "$restore_status" -ne 0 ]; then
  echo "Warning: failed to restore optimize build (status $restore_status)" >&2
  echo "=== optimize rebuild log ===" >&2
  cat "$restore_log" >&2
fi
rm -f "$restore_log"

exit "$rc"
