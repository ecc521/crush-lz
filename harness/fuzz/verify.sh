#!/bin/sh
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
# Usage: verify.sh [asan | msan | mte]. Uses the fuzz build's compiler/flags.
set -eu
cd "$(dirname "$0")"
mode=${1:-asan}
case "$mode" in
  asan) option=""; suffix="" ;;
  msan|mte) option=$mode; suffix="_$mode" ;;
  *) echo "usage: $0 [asan | msan | mte]" >&2; exit 1 ;;
esac
./build.sh buffer_selftest sanitizer_probe $option
${PYTHON:-python3} ./sanitizer_selftest.py "build/sanitizer_probe$suffix" "$mode"
if [ "$mode" = asan ]; then
  ${PYTHON:-python3} ./buffer_selftest.py build/buffer_selftest asan
else
  # Page protection is independent of sanitizer instrumentation.
  ${CC:-clang} -O1 -std=gnu99 buffer_selftest.c -o build/buffer_selftest_plain
  ${PYTHON:-python3} ./buffer_selftest.py build/buffer_selftest_plain
fi
