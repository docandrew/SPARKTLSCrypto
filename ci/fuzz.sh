#!/usr/bin/env bash
# Differential fuzzing of the accelerated tiers against the proven SPARK
# code (tests/fuzz/diff_fuzz.adb). Budget in seconds: $1 (default 30);
# seed: $2 (default fixed, for reproducibility; vary it in nightly runs).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/fuzz"
export ALR_NON_INTERACTIVE=1
export NO_COLOR=1
alr -n --no-tty build
bin/diff_fuzz "${1:-30}" ${2:+"$2"}
