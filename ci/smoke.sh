#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tests/smoke"

export ALR_NON_INTERACTIVE=1
export NO_COLOR=1

echo "== smoke tests =="
alr -n --no-tty build
bin/smoke_tests
