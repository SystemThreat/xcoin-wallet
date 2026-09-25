#!/bin/bash
# Build xcoin-wallet from the Xcoin node's own PQClean sources: ML-DSA-65 (FIPS 204)
# and SLH-DSA-SHA2-128s (FIPS 205, the fallback leaf of every two-leaf address).
# This is why every address it prints is consensus-valid: identical code path
# to the derivation the node's former `pqderiveaddress` RPC used (removed 2026-09-14). Requires Xcode CLT + the Xcoin source tree.
set -e
cd "$(dirname "$0")"
# The PQClean sources are vendored in ./pqcrypto (the exact files the node builds
# from; provenance in pqcrypto/*/PQCLEAN). A node source tree, when you have one,
# takes precedence so wallet and node can never drift: NEX=/path/to/xCoin/source ./build.sh
PQ="./pqcrypto"
if [ -n "${NEX:-}" ]; then
  [ -d "$NEX/src/pqcrypto" ] || { echo "NEX=$NEX has no src/pqcrypto; unset NEX to use the vendored ./pqcrypto"; exit 1; }
  PQ="$NEX/src/pqcrypto"
fi
[ -d "$PQ/ml-dsa-65" ] || { echo "missing $PQ/ml-dsa-65 — vendored sources gone, and no NEX=/path/to/node-tree given"; exit 1; }
[ -d "$PQ/slh-dsa-sha2-128s" ] && [ -f "$PQ/common/sha2.c" ] || { echo "missing $PQ/slh-dsa-sha2-128s or $PQ/common/sha2.c — this tree predates SLH-DSA (node stage B3); use the vendored ./pqcrypto"; exit 1; }
# The node provides randombytes() from its own RNG; a tree without common/randombytes.c
# gets the local one (arc4random_buf).
RB="$PQ/common/randombytes.c"; [ -f "$RB" ] || RB="./randombytes.c"
CL="$PQ/common/cleanse.c"; [ -f "$CL" ] || CL=""
# ml-dsa-65 and slh-dsa-sha2-128s share file names (sign.c, params.h, api.h…): each
# directory compiles with only its own headers, into its own object directory.
OUT="$(mktemp -d "${TMPDIR:-/tmp}/xcoin-wallet-build.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/common" "$OUT/mldsa" "$OUT/slh"
for f in "$PQ/common/fips202.c" "$PQ/common/sha2.c" $CL "$RB"; do
  clang -O2 -arch arm64 -c -I"$PQ/common" "$f" -o "$OUT/common/$(basename "${f%.c}").o"
done
for f in "$PQ"/ml-dsa-65/*.c; do
  clang -O2 -arch arm64 -c -I"$PQ/common" -I"$PQ/ml-dsa-65" "$f" -o "$OUT/mldsa/$(basename "${f%.c}").o"
done
for f in "$PQ"/slh-dsa-sha2-128s/*.c; do
  clang -O2 -arch arm64 -c -I"$PQ/common" -I"$PQ/slh-dsa-sha2-128s" "$f" -o "$OUT/slh/$(basename "${f%.c}").o"
done
clang++ -O2 -arch arm64 -std=c++17 -I"$PQ/common" \
  xcoin-wallet.cpp "$OUT"/common/*.o "$OUT"/mldsa/*.o "$OUT"/slh/*.o -o xcoin-wallet
codesign -s - -f xcoin-wallet 2>/dev/null || true
echo "✅ built ./xcoin-wallet (ML-DSA-65 + SLH-DSA-SHA2-128s, witness v3 two-leaf)"

# The build is only good if it still speaks the chain's v3 byte language, and still
# derives the same two-leaf and carried programs as dex-wallet-cli's keytool.
./xcoin-wallet _v3vectors >/dev/null || { echo "❌ v3 golden vectors FAILED — do not use this build"; exit 1; }
echo "✅ v3 golden vectors verified (incl. the dex-wallet-cli two-leaf/carried cross-check)"
# Build the native tool yourself with ./build.sh — never ship a prebuilt binary.
