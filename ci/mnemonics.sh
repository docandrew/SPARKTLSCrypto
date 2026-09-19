#!/usr/bin/env bash
# Instruction-set gate for the hand-written tiers.
#
# Disassembles each accelerated unit's object from the default (optimize,
# tiers enabled) build and fails if it contains a mnemonic that is not in
# that unit's reviewed allowlist (tests/timing/mnemonics/<unit>.allow).
# The allowlists hold only instructions with data-operand-independent
# timing (Intel's DOIT list; fixed latency on AMD): no div/idiv, no
# data-dependent-count string ops, nothing whose latency depends on its
# operand values. A new mnemonic, even a harmless one, is a review event:
# add it to the allowlist in the same change, with the reason. Branches
# are allowed by mnemonic because their conditions are checked by the
# ctgrind lane (memcheck taint), not here.
#
#   ci/mnemonics.sh            check
#   ci/mnemonics.sh --record   (re)generate the allowlists from the current
#                              objects; review the diff before committing
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
UNITS=(bignat64_adx p256_gather_avx2 aes_ni ghash_ni hashing-sha256 aes_gcm_avx512 chacha20_avx512
       poly1305_avx512 poly1305_avx512_ifma)
DENY='^(div|idiv|divq|divl|idivq|idivl|rep|repz|repnz|rdrand|rdseed|syscall|int|int3|ud2)$'
fail=0
for u in "${UNITS[@]}"; do
  obj="obj/sparktlscrypto-$u.o"
  allow="tests/timing/mnemonics/$u.allow"
  if [ ! -f "$obj" ]; then echo "  MISSING $obj (run alr build first)"; fail=1; continue; fi
  seen=$(objdump -d --no-show-raw-insn "$obj" \
           | awk -F'\t' 'NF>=2 {n=split($2,a," "); i=1; while (i<=n && a[i] ~ /^(lock|data16|cs|ds|notrack|bnd|rex[.a-z]*)$/) i++; if (i<=n) print a[i]}' \
           | sort -u)
  if grep -qE "$DENY" <<<"$seen"; then
    echo "  FAIL  $u: denied instruction present:"; grep -E "$DENY" <<<"$seen" | sed 's/^/          /'; fail=1; continue
  fi
  if [ "${1:-}" = "--record" ]; then
    printf '%s\n' "$seen" > "$allow"; echo "  WROTE $allow ($(wc -l <"$allow") mnemonics)"; continue
  fi
  if [ ! -f "$allow" ]; then echo "  FAIL  $u: no allowlist $allow (run with --record and review)"; fail=1; continue; fi
  new=$(comm -23 <(printf '%s\n' "$seen") <(sort -u "$allow"))
  if [ -n "$new" ]; then
    echo "  FAIL  $u: mnemonics not in allowlist:"; sed 's/^/          /' <<<"$new"; fail=1
  else
    echo "  PASS  $u ($(wc -l <<<"$seen") distinct mnemonics, all allowlisted)"
  fi
done
[ $fail -eq 0 ] && echo "=== instruction-set gate: PASS" || { echo "=== instruction-set gate: FAIL"; exit 1; }
