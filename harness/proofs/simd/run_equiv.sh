#!/bin/sh
# CBMC equivalence of the NEON, SSE and portable decoder wrappers in
# crush_simd.h (equiv/equiv.c), then the negative check that the blends
# disagree once a selector may be 16 or more. Run in the proof image:
#
#   docker run --rm -v "$PWD:/work" -w /work --entrypoint harness/proofs/simd/run_equiv.sh \
#     crushlz-proofs:6.11.0
#
# The NEON and SSE builds forge their predefined macros, so either runs on
# any host; the wrappers include only <stdint.h>, <string.h> and the shadow
# intrinsic headers.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
SIMD="$ROOT/harness/proofs/simd"
ZBM_CSRC="$ROOT/crates/lzbitmap/csrc"
WORK=${PROOF_WORK:-"$ROOT/harness/build/proofs-simd"}/equiv
mkdir -p "$WORK"

CHECKS="--bounds-check --pointer-check --pointer-overflow-check \
        --signed-overflow-check --undefined-shift-check --object-bits 10 \
        --sat-solver cadical"
INC="-I$SIMD/include -I$ZBM_CSRC"
NOARCH="-U__aarch64__ -U__ARM_NEON -U__ARM_NEON__ -U__x86_64__ -U__SSE4_1__ -U__POPCNT__ -U__AVX2__"
W="$SIMD/equiv/wrappers.c"

# shellcheck disable=SC2086
goto-cc -c $INC -fsigned-char -DCRUSH_SIMD_PORTABLE -DEXPECT_PORTABLE -DPFX=P_ "$W" -o "$WORK/p.o"
# shellcheck disable=SC2086
goto-cc -c $INC -fsigned-char $NOARCH -D__aarch64__=1 -D__ARM_NEON=1 -DEXPECT_NEON -DPFX=N_ "$W" -o "$WORK/n.o"
# shellcheck disable=SC2086
goto-cc -c $INC -fsigned-char $NOARCH -D__x86_64__=1 -D__SSSE3__=1 -D__SSE4_1__=1 \
    -D__POPCNT__=1 -D__AVX2__=1 -D__BMI2__=1 -DEXPECT_SSE -DPFX=S_ "$W" -o "$WORK/s.o"

status=0
for mode in positive negative; do
    def=""; [ "$mode" = negative ] && def=-DEQUIV_NEGATIVE
    # shellcheck disable=SC2086
    goto-cc -c $INC -fsigned-char $def "$SIMD/equiv/equiv.c" -o "$WORK/h-$mode.o"
    goto-cc --function harness "$WORK/h-$mode.o" "$WORK/p.o" "$WORK/n.o" "$WORK/s.o" \
        -o "$WORK/$mode.goto"
    # shellcheck disable=SC2086
    cbmc "$WORK/$mode.goto" $CHECKS --unwind 33 --unwinding-assertions \
        --slice-formula >"$WORK/$mode.log" 2>&1 || true
    summary=$(grep -E '^\*\* [0-9]+ of [0-9]+ failed' "$WORK/$mode.log" | tail -n 1)
    if [ "$mode" = positive ]; then
        echo "equivalence: $summary"
        grep -q '^VERIFICATION SUCCESSFUL' "$WORK/$mode.log" || {
            grep 'FAILURE$' "$WORK/$mode.log" >&2; status=1; }
    else
        # Both native blends must disagree with portable for some selector,
        # and nothing else may fail: the footprints hold for any selector.
        echo "negative (selectors unrestricted): $summary"
        grep -q 'NEON == portable: FAILURE$' "$WORK/$mode.log" &&
            grep -q 'SSE == portable: FAILURE$' "$WORK/$mode.log" &&
            ! grep 'FAILURE$' "$WORK/$mode.log" |
                grep -vq '== portable: FAILURE$\|selector semantics: FAILURE$\|reads base before writing it: FAILURE$' || {
            echo "FAIL negative check" >&2; grep 'FAILURE$' "$WORK/$mode.log" >&2; status=1; }
    fi
done
[ "$status" -eq 0 ] && echo "PASS simd equivalence" || echo "FAIL simd equivalence"
exit "$status"
