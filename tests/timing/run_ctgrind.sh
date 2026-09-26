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

# Valgrind's virtual CPU does not advertise BMI2/ADX, so left to CPUID the
# harnesses would only ever exercise the portable Montgomery code. Build
# the library with the tier assumed present (SPARKTLSCRYPTO_ASM=
# assume_bmi2_adx, a compile-time selection into its own obj/lib
# directory, see SPARKTLSCrypto.Tier_Config) so memcheck's taint tracking
# covers the assembly. Valgrind 3.22 executes mulx/adcx/adox.
# CTGRIND_PORTABLE=1 checks the portable path instead.
if [ "${CTGRIND_PORTABLE:-0}" = "1" ]; then
  export SPARKTLSCRYPTO_ASM=disabled
else
  export SPARKTLSCRYPTO_ASM=assume_bmi2_adx
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

#  run_one NAME MODE [COUNT]
#    clean   : must report no errors
#    canary  : must report at least one (negative control)
#    xfail   : known finding, must still reproduce
#    exact N : must report exactly N errors (classified sites, see below)
run_one() {
  local name="$1" mode="$2" want="${3:-}"
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
  elif [ "$mode" = "exact" ]; then
    if [ "$errs" -eq "$want" ]; then
      echo "  PASS  $name ($errs errors; exactly the classified sites)"
    else
      echo "  FAIL  $name ($errs errors; expected exactly $want classified sites)"
      echo "$out" | sed 's/^/      /' | head -30
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
#  ct_p256_ecdsa: exactly ONE classified site. Sign re-decodes the nonce
#  point [k]G (SR-66 fault check) to confirm it is on the curve before
#  using its x-coordinate as r. That coordinate is public (it becomes the
#  signature's r) but memcheck taints it through the secret nonce k, so
#  the on-curve branch reads as key-dependent; its outcome does not vary
#  with k and dudect shows no timing dependence. Same category as
#  ct_rsa_sign_crt. Any other count means a new key-dependent branch.
run_one ct_p256_ecdsa        exact 1 || fail=1
#  ct_p384_ecdsa: exactly ONE classified site, the on-curve check of the
#  nonce point in P384.ECDSA.Sign (P384_Public_Key_Valid_Mask /= 0). The
#  point is public (it becomes the signature's r) but memcheck taints it
#  through the poisoned nonce and blind; its outcome does not vary with
#  either. Same category as ct_p256_ecdsa's one site.
run_one ct_p384_ecdsa        exact 1 || fail=1
run_one ct_p384_ecdsa_verify clean || fail=1
run_one ct_p256_ecdsa_verify clean || fail=1
run_one ct_hkdf              clean || fail=1
run_one ct_prepared clean || fail=1
run_one ct_aes_gcm           clean || fail=1
run_one ct_aead_decrypt      clean || fail=1
run_one ct_rfc6979           clean || fail=1
run_one ct_hmac              clean || fail=1
run_one ct_rsa_sign_plain    clean || fail=1
run_one ct_rsa_verify        clean || fail=1
#  ct_rsa_sign_crt: exactly TWO classified sites, both one decision --
#  the verify-after-sign check in RSA_Private_Fast (a constant-time
#  compare of two PUBLIC outputs, signature and padded message, whose
#  bytes nevertheless derive from the poisoned key) and the propagation
#  of its Boolean through Sign_PSS's OK. Reported as seen, not masked.
#  Any other count is a regression: more means a new key-dependent
#  branch; fewer means the poison stopped reaching the signer. A
#  toolchain bump that moves the count is re-triaged against the valgrind
#  output, not renumbered.
#  Re-triaged 2026-09-25 for -fno-tree-vrp: there were three sites, the
#  third the harness's print of OK (ct_rsa_sign_crt.adb:166). Without
#  value-range propagation Sign_PSS sets OK through its branch at the
#  second site, so the harness receives a defined value; the two library
#  sites (sparktlscrypto-rsa.adb:1202 and :1291) are unchanged.
run_one ct_rsa_sign_crt      exact 2 || fail=1

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
  SPARKTLSCRYPTO_ASM=enabled SPARKTLSCRYPTO_BUILD_MODE=optimize alr -n --no-tty build >"$restore_log" 2>&1
)
restore_status=$?
if [ "$restore_status" -ne 0 ]; then
  echo "Warning: failed to restore optimize build (status $restore_status)" >&2
  echo "=== optimize rebuild log ===" >&2
  cat "$restore_log" >&2
fi
rm -f "$restore_log"

exit "$rc"
