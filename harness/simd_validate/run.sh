#!/bin/sh
# Build and run simd_validate for one or more configurations:
#
#   harness/simd_validate/run.sh [arm64] [x86-v3] [x86]
#
# Default: the host's shipping configuration; on an arm64 Mac also both
# x86-64 builds, run under Rosetta. SIMD_VALIDATE_EXHAUSTIVE=1 runs every
# 32-bit builtin input, all 64x64 copy offsets and more random cases.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$ROOT/harness/simd_validate"
SIMD="$ROOT/harness/proofs/simd"
ZBM="$ROOT/crates/lzbitmap/csrc"
OUT="$ROOT/harness/build/simd_validate"
CC=${CC:-cc}

if [ "$(uname -s)" = Darwin ]; then GC="-Wl,-dead_strip"; else GC="-ffunction-sections -Wl,--gc-sections"; fi

build_and_run() {
    name=$1; shift
    dir="$OUT/$name"
    mkdir -p "$dir"
    cf="-O2 -std=gnu99 -fno-strict-aliasing -I$ZBM -I$SIMD $*"
    # Three copies of libzbitmap.c link together once its public symbols are
    # renamed per copy.
    # shellcheck disable=SC2086
    $CC $cf -DCRUSH_SIMD_PORTABLE -DPFX=X_ -c "$HERE/zbm_wrap.c" -o "$dir/probe.o"
    syms=$(nm -g "$dir/probe.o" | awk '$2 == "T" {print $3}' | sed 's/^_//' | grep -v '^X_')
    for v in R D P; do
        ren=""
        for s in $syms; do ren="$ren -D$s=${v}_$s"; done
        case $v in
            R) extra="" ;;
            D) extra="-I$SIMD/include" ;;
            P) extra="-DCRUSH_SIMD_PORTABLE" ;;
        esac
        # shellcheck disable=SC2086
        $CC $cf $extra $ren -DPFX=${v}_ -c "$HERE/zbm_wrap.c" -o "$dir/$v.o"
    done
    # shellcheck disable=SC2086
    $CC $cf $GC "$HERE/simd_validate.c" "$dir/R.o" "$dir/D.o" "$dir/P.o" \
        -lpthread -o "$dir/simd_validate"
    "$dir/simd_validate"
}

configs=${*:-}
if [ -z "$configs" ]; then
    case "$(uname -m)" in
        arm64|aarch64)
            configs=arm64
            if [ "$(uname -s)" = Darwin ] && arch -x86_64 /usr/bin/true 2>/dev/null; then
                configs="arm64 x86-v3 x86"
            fi ;;
        x86_64) configs="x86-v3 x86" ;;
    esac
fi

status=0
for c in $configs; do
    case $c in
        arm64) build_and_run arm64 || status=1 ;;
        x86-v3)
            a=""; [ "$(uname -m)" = x86_64 ] || a="-arch x86_64"
            # shellcheck disable=SC2086
            build_and_run x86-v3 $a -march=x86-64-v3 || status=1 ;;
        x86)
            a=""; [ "$(uname -m)" = x86_64 ] || a="-arch x86_64"
            # shellcheck disable=SC2086
            build_and_run x86 $a || status=1 ;;
        *) echo "unknown configuration $c" >&2; exit 2 ;;
    esac
done
exit $status
