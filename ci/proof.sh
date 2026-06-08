#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

mapfile -t UNITS < <(
  find src -maxdepth 1 -type f \( -name '*.adb' -o -name '*.ads' \) \
    -printf '%f\n' | sort
)

alr gnatprove \
  -j0 \
  --level="${SPARKTLSCRYPTO_PROOF_LEVEL:-1}" \
  --counterexamples=off \
  --output=oneline \
  --output-header \
  -u "${UNITS[@]}" 2>&1 | tee gnatprove-run.txt

OUT="obj/gnatprove/gnatprove.out"

if grep -nE 'SPARKTLSCrypto\..*not proved|sparktlscrypto-.*:.*(medium|high):' \
   "$OUT" gnatprove-run.txt; then
  echo "SPARKTLSCrypto proof failed: see $OUT and gnatprove-run.txt" >&2
  exit 1
fi

if grep -nE 'SPARKNaCl\..*not proved|sparknacl-.*:.*(medium|high):' "$OUT" \
   >/dev/null; then
  echo "Note: dependency SPARKNaCl has unproved checks in the GNATprove report." >&2
  echo "SPARKTLSCrypto units proved; dependency findings are classified separately." >&2
fi
