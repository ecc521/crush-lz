#!/bin/sh
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
# Coverage report for a fuzz corpus, replayed through a binary built with
# `build.sh <target> libfuzzer coverage`.
#
# Usage: fuzz/coverage.sh <target> <corpus-dir> [source-file ...]
#   source-file  optional: also show line-by-line detail for these files
# FUZZ_SANITIZER selects asan (default), msan or mte builds.

set -e
FUZZ_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)

TARGET=${1:?usage: fuzz/coverage.sh <target> <corpus-dir> [source-file ...]}
CORPUS=${2:?usage: fuzz/coverage.sh <target> <corpus-dir> [source-file ...]}
shift 2

case "${FUZZ_SANITIZER:-asan}" in
  asan) SUFFIX="" ;;
  msan|mte) SUFFIX="_${FUZZ_SANITIZER}" ;;
  *) echo "FUZZ_SANITIZER must be asan, msan or mte" >&2; exit 1 ;;
esac
STEM="${TARGET}${SUFFIX}_libfuzzer_cov"
BIN="$FUZZ_DIR/build/$STEM"
[ -x "$BIN" ] || { echo "missing $BIN: run fuzz/build.sh $TARGET libfuzzer coverage" >&2; exit 1; }

PROFDATA=${LLVM_PROFDATA:-$(xcrun --find llvm-profdata 2>/dev/null || command -v llvm-profdata)}
LLVMCOV=${LLVM_COV:-$(xcrun --find llvm-cov 2>/dev/null || command -v llvm-cov)}
[ -n "$PROFDATA" ] && [ -n "$LLVMCOV" ] || { echo "llvm-profdata/llvm-cov not found" >&2; exit 1; }

RAW="$FUZZ_DIR/build/$STEM.profraw"
DATA="$FUZZ_DIR/build/$STEM.profdata"
rm -f "$RAW" "$DATA"

LLVM_PROFILE_FILE="$RAW" "$BIN" -runs=0 "$CORPUS" >/dev/null
"$PROFDATA" merge -sparse "$RAW" -o "$DATA"

"$LLVMCOV" report "$BIN" -instr-profile="$DATA" -ignore-filename-regex='fuzz/'

if [ "$#" -gt 0 ]; then
  echo ""
  "$LLVMCOV" show "$BIN" -instr-profile="$DATA" "$@"
fi
