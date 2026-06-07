#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

case "${1:-ctgrind}" in
  ctgrind)
    tests/timing/run_ctgrind.sh
    ;;
  dudect)
    tests/timing/run_dudect.sh
    ;;
  all)
    tests/timing/run_ctgrind.sh
    tests/timing/run_dudect.sh
    ;;
  *)
    echo "usage: $0 [ctgrind|dudect|all]" >&2
    exit 2
    ;;
esac

