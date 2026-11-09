#!/bin/sh
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
# Builds the fuzz harnesses.
#
# Usage:  fuzz/build.sh [target ...] [libfuzzer] [coverage] [msan | mte]
#   msan: Linux/BSD MemorySanitizer instead of ASan/UBSan.
#   mte: Apple Clang checked heap entitlements + pointer arithmetic, with UBSan.
#        libfuzzer needs FUZZER_RUNTIME (a compatible libFuzzer archive).
#   targets    codec_buffers, crushlzfse_encode, crushlzvn_encode, crushlzfse_decode,
#              crushlzfse_decode_diff_vs_apple, lzbitmap_encode,
#              lzbitmap_decode, lzbitmap_decode_diff_vs_apple, lz4_encode,
#              lz4_decode, lz4_decode_diff_vs_apple, lzmesh_encode,
#              lzmesh_decode, lzmesh_decode_diff_vs_apple (default: all of them).
#              The *_diff_vs_apple targets only do real work on macOS.
#   setup      buffer_selftest and sanitizer_probe are standalone-only;
#              verify.sh builds and checks them with the selected sanitizer.
#   libfuzzer  coverage-guided build; needs a clang with the libFuzzer
#              runtime, which Apple's lacks:
#                CC=/opt/homebrew/opt/llvm/bin/clang fuzz/build.sh libfuzzer
#   coverage   also adds source-based coverage instrumentation to the code
#              under test, for fuzz/coverage.sh. Binary gets a `_cov` suffix.
#
# ASan+UBSan go on both the code under test and the harness; coverage
# instrumentation goes on the code under test only.
#
# Output goes to fuzz/build/, which the harness Makefile never wipes.
set -e
cd "$(dirname "$0")"
FUZZ_DIR=$(pwd)
HARNESS_DIR=$(cd .. && pwd)
CRUSHLZFSE_CSRC="$HARNESS_DIR/../crates/crushlzfse/csrc"
LZBITMAP_CSRC="$HARNESS_DIR/../crates/lzbitmap/csrc"
LZ4_CSRC="$HARNESS_DIR/../crates/crushlz4/csrc"
LZMESH_CSRC="$HARNESS_DIR/../crates/lzmesh/csrc"

CC=${CC:-clang}
OUT="$FUZZ_DIR/build"
mkdir -p "$OUT"

MTE=0
MSAN=0
LIBFUZZER=0
COVERAGE=0
TARGETS=""
for arg in "$@"; do
  case "$arg" in
    mte) MTE=1 ;;
    msan) MSAN=1 ;;
    libfuzzer) LIBFUZZER=1 ;;
    coverage)  COVERAGE=1 ;;
    *)         TARGETS="$TARGETS $arg" ;;
  esac
done
[ -n "$TARGETS" ] || TARGETS="codec_buffers crushlzfse_encode crushlzvn_encode crushlzfse_decode crushlzfse_decode_diff_vs_apple lzbitmap_encode lzbitmap_decode lzbitmap_decode_diff_vs_apple lz4_encode lz4_decode lz4_decode_diff_vs_apple lzmesh_encode lzmesh_decode lzmesh_decode_diff_vs_apple"

COMMON="-g -O1 -std=gnu99 -fno-strict-aliasing -fno-omit-frame-pointer -I$CRUSHLZFSE_CSRC -I$LZBITMAP_CSRC -I$LZ4_CSRC -I$LZMESH_CSRC"
# Match the shipping x86-64-v3 paths, including AVX2 and BMI2. Set
# ISA_CFLAGS= for a portable build, as in harness/flags.mk.
if $CC -dM -E - < /dev/null | grep -q '__x86_64__'; then
  COMMON="$COMMON ${ISA_CFLAGS--march=x86-64-v3}"
fi
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all"
if [ "$MSAN" = "1" ]; then
  [ "$(uname -s)" != "Darwin" ] || { echo "msan needs a Linux/BSD runtime; use a Linux VM/container on macOS" >&2; exit 1; }
  SAN="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-sanitize-recover=all"
  COMMON="$COMMON -fPIE"
fi

if [ "$MTE" = "1" ]; then
  [ "$(uname -s)" = "Darwin" ] || { echo "mte mode requires macOS and Apple Clang" >&2; exit 1; }
  [ "$MSAN" = "0" ] || { echo "mte and msan are separate builds" >&2; exit 1; }
  COMMON="$COMMON -isysroot $(xcrun --sdk macosx --show-sdk-path)"
  SAN="-march=armv8.5-a+memtag -fsanitize=undefined -fchecked-pointer-arithmetic -fno-sanitize-recover=all"
  if [ "$LIBFUZZER" = "1" ]; then
    [ -f "${FUZZER_RUNTIME:-}" ] || { echo "mte libfuzzer needs FUZZER_RUNTIME pointing to libclang_rt.fuzzer_osx.a" >&2; exit 1; }
  fi
fi

# Apple's libcompression is the encoder harnesses' second oracle on macOS.
EXTRA_LIBS="-lm"
if [ "$(uname -s)" = "Darwin" ]; then EXTRA_LIBS="-lcompression -lm"; fi

build_target() {
  target=$1
  shift
  srcs=$*

  under_test="$SAN"
  harness_flags="$SAN"
  harness_def=""
  link="$SAN"
  suffix=""
  if [ "$MTE" = "1" ]; then suffix="_mte"; fi
  if [ "$MSAN" = "1" ]; then suffix="_msan"; link="$link -pie"; fi

  if [ "$LIBFUZZER" = "1" ]; then
    under_test="$SAN -fsanitize=fuzzer-no-link"
    harness_flags="$SAN -fsanitize=fuzzer"
    if [ "$MTE" = "1" ]; then harness_flags="$SAN -fsanitize=fuzzer-no-link"; fi
    harness_def="-DFUZZ_LIBFUZZER"
    link="$SAN -fsanitize=fuzzer"
    if [ "$MSAN" = "1" ]; then link="$link -pie"; fi
    if [ "$MTE" = "1" ]; then link="$SAN $FUZZER_RUNTIME -lc++"; fi
    suffix="${suffix}_libfuzzer"
  fi

  if [ "$COVERAGE" = "1" ]; then
    COV_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
    under_test="$under_test $COV_FLAGS"
    link="$link $COV_FLAGS"
    suffix="${suffix}_cov"
  fi

  bin="$OUT/${target}${suffix}"

  objs=""
  for f in $srcs; do
    obj="$OUT/${target}${suffix}__$(basename "$f" .c).o"
    $CC $COMMON $under_test -c "$f" -o "$obj"
    objs="$objs $obj"
  done

  $CC $COMMON $harness_flags $harness_def -c "$FUZZ_DIR/${target}.c" -o "$OUT/${target}${suffix}__harness.o"
  $CC $COMMON $link $objs "$OUT/${target}${suffix}__harness.o" $EXTRA_LIBS -o "$bin"
  if [ "$MTE" = "1" ]; then
    codesign -s - -f --entitlements "$FUZZ_DIR/mte-entitlements.plist" "$bin"
  fi
  echo "built $bin"
}

for t in $TARGETS; do
  case "$t" in
    buffer_selftest|sanitizer_probe)
      [ "$LIBFUZZER" = "0" ] || { echo "$t is a standalone setup check" >&2; exit 1; }
      build_target "$t"
      ;;
    codec_buffers)
      build_target "$t" "$LZBITMAP_CSRC/libzbitmap.c" "$CRUSHLZFSE_CSRC/"*.c \
        "$LZ4_CSRC/crushlz4.c" "$LZ4_CSRC/vendor/lz4/lz4.c" "$LZ4_CSRC/vendor/lz4/lz4hc.c"
      ;;
    crushlzfse_encode|crushlzvn_encode|crushlzfse_decode|crushlzfse_decode_diff_vs_apple)
      build_target "$t" \
        "$CRUSHLZFSE_CSRC/lzfse_encode.c" \
        "$CRUSHLZFSE_CSRC/lzfse_encode_base.c" \
        "$CRUSHLZFSE_CSRC/lzvn_encode_base.c" \
        "$CRUSHLZFSE_CSRC/lzfse_fse.c" \
        "$CRUSHLZFSE_CSRC/crushlzfse.c" \
        "$CRUSHLZFSE_CSRC/crushlzvn.c" \
        "$CRUSHLZFSE_CSRC/lzfse_decode.c" \
        "$CRUSHLZFSE_CSRC/lzfse_decode_base.c" \
        "$CRUSHLZFSE_CSRC/lzvn_decode_base.c"
      ;;
    lzbitmap_encode|lzbitmap_decode|lzbitmap_decode_diff_vs_apple)
      build_target "$t" "$LZBITMAP_CSRC/libzbitmap.c"
      ;;
    lz4_encode|lz4_decode|lz4_decode_diff_vs_apple)
      build_target "$t" "$LZ4_CSRC/crushlz4.c" "$LZ4_CSRC/vendor/lz4/lz4.c" "$LZ4_CSRC/vendor/lz4/lz4hc.c"
      ;;
    lzmesh_encode|lzmesh_decode|lzmesh_decode_diff_vs_apple)
      build_target "$t" "$LZMESH_CSRC/crushlzmesh.c"
      ;;
    *)
      echo "unknown target: $t" >&2
      exit 1
      ;;
  esac
done
