#!/usr/bin/env bash
# Stack-residue gate: after each signing / key-agreement primitive returns,
# no fragment of the secrets it used may remain on the stack below the
# caller. tests/residue/residue_scan.adb explains the method; the run
# fails on any fragment, and also if its own negative control (a
# deliberately unscrubbed copy) is not detected, so a zero cannot come
# from a blind scanner. Native run, not valgrind.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/residue"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
echo "== stack-residue scan =="
alr -n --no-tty build
bin/residue_scan
