#!/usr/bin/env bash
# Fetch the NIST CAVP DRBG test vectors into tests/kat/vectors (gitignored).
# The archive is pinned by SHA-256; bump deliberately. Idempotent. Needs
# curl and unzip.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
V="$DIR/vectors"
mkdir -p "$V"

# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/random-number-generators
ZIP_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip"
ZIP_SHA256="5f7e5658ebd5b4e6785a7b12fa32333511d2acc2f2d9c5ae1ffa16b699377769"   # fetched 2026-09-22

if [ ! -f "$V/drbgtestvectors.zip" ]; then
    echo "fetching drbgtestvectors.zip"
    curl -sSfL -o "$V/drbgtestvectors.zip.tmp" "$ZIP_URL" && mv "$V/drbgtestvectors.zip.tmp" "$V/drbgtestvectors.zip"
fi
echo "$ZIP_SHA256  $V/drbgtestvectors.zip" | sha256sum -c - >/dev/null

# The archive holds one zip per variant; we use the two without prediction
# resistance (HMAC_DRBG.rsp in each).
for variant in no_reseed pr_false; do
    if [ ! -f "$V/$variant/HMAC_DRBG.rsp" ]; then
        rm -rf "$V/$variant"; mkdir -p "$V/$variant"
        unzip -q -o "$V/drbgtestvectors.zip" "drbgvectors_$variant.zip" -d "$V"
        unzip -q -o "$V/drbgvectors_$variant.zip" "HMAC_DRBG.rsp" -d "$V/$variant"
        rm -f "$V/drbgvectors_$variant.zip"
    fi
done
