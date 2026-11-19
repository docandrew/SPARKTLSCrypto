#!/usr/bin/env bash
# Fetch the NIST CAVP DRBG and GCM test vectors and the Wycheproof AES-GCM
# vectors into tests/kat/vectors (gitignored).
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

# AES-GCM: the NIST CAVP GCM vectors (decryption files carry FAIL cases)
# and Wycheproof's aes_gcm_test.json, both pinned by SHA-256. The JSON is
# flattened into one line per test for the Ada runner (python3 is already
# a CI dependency).
# https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
GCM_URL="https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip"
GCM_SHA256="f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023"   # fetched 2026-11-19
if [ ! -f "$V/gcmtestvectors.zip" ]; then
    echo "fetching gcmtestvectors.zip"
    curl -sSfL -o "$V/gcmtestvectors.zip.tmp" "$GCM_URL" && mv "$V/gcmtestvectors.zip.tmp" "$V/gcmtestvectors.zip"
fi
echo "$GCM_SHA256  $V/gcmtestvectors.zip" | sha256sum -c - >/dev/null
for f in gcmDecrypt128.rsp gcmDecrypt256.rsp; do
    [ -f "$V/gcm/$f" ] || unzip -q -o "$V/gcmtestvectors.zip" "$f" -d "$V/gcm"
done

WYCHEPROOF_COMMIT="dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166"
WYCHEPROOF_URL="https://raw.githubusercontent.com/C2SP/wycheproof/$WYCHEPROOF_COMMIT/testvectors_v1/aes_gcm_test.json"
WYCHEPROOF_SHA256="985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7"
if [ ! -f "$V/aes_gcm_test.json" ]; then
    echo "fetching wycheproof aes_gcm_test.json"
    curl -sSfL -o "$V/aes_gcm_test.json.tmp" "$WYCHEPROOF_URL" && mv "$V/aes_gcm_test.json.tmp" "$V/aes_gcm_test.json"
fi
echo "$WYCHEPROOF_SHA256  $V/aes_gcm_test.json" | sha256sum -c - >/dev/null
#  keySize ivSize tagSize tcId result key iv aad msg ct tag ("-" = empty)
python3 -I - "$V/aes_gcm_test.json" "$V/aes_gcm_test.txt" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
with open(sys.argv[2], "w") as out:
    for group in data["testGroups"]:
        for t in group["tests"]:
            fields = [group["keySize"], group["ivSize"], group["tagSize"],
                      t["tcId"], t["result"]]
            fields += [t[k] or "-" for k in ("key", "iv", "aad", "msg", "ct", "tag")]
            out.write(" ".join(str(f) for f in fields) + "\n")
PY
