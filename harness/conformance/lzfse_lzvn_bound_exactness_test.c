// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for three crushlzfse_encode_bound()/crushlzvn_encode_bound()
// bugs, all now fixed:
//
// 1. The bound used the default block size for framing overhead even when
//    params->p.optimal.block_size was smaller, undersizing the destination
//    (encode_bound(5000) returned 5016 bytes for LZFSE when the real need at
//    block_size=1 was ~48800). Fixed by removing block_size as a runtime
//    parameter: every call, Greedy or Optimal, is now fixed to one
//    LZFSE_ZOPT_BLOCK_SIZE / LZVN_ZOPT_BLOCK_SIZE (65536-byte) block and
//    rejects larger input outright.
// 2. crushlzvn_encode_bound()'s per-block term was an empirical margin over
//    the optimal parser's cost-model heuristic, insufficient at level 8 for
//    match-shaped input (see fill_attack_shape below). Fixed by making
//    crushlzvn.c's encode_block() fall back to a pure-literal encoding
//    whenever a real parse would cost more, capping every block's true cost
//    at lzvn_literal_final_cost() so the bound is provable rather than an
//    empirical guess.
// 3. The GREEDY branch fed greedy's nominal (1<<30) block-size ceiling into
//    a per-block term meant for actual bytes, producing a ~16 MiB bound
//    regardless of src_size. GREEDY now shares the same fixed block as
//    OPTIMAL; the GREEDY loop below stays as a regression pin for this.
//
// This test sizes a destination via encode_bound() *exactly*, for every
// src_size up to the fixed block and every strategy, then feeds it to the
// matching _advanced() call under ASan: any write past that size is a
// heap-buffer-overflow. harness/fuzz/crushlzfse_encode.c only drives the
// level-based crushlzfse_encode_buffer() into a generous destination, so
// this exact-sizing case would otherwise go uncovered.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"
#include "crushlzvn.h"

static int failures;

static void fill_incompressible(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    for (size_t i = 0; i < n; i++) { s = s * 1103515245u + 12345u; b[i] = (uint8_t)(s >> 24); }
}

// Alternates short compressible runs with noise: neither purely
// incompressible (which some cost models special-case) nor purely
// repetitive, so it stresses realistic per-block accounting.
static void fill_pathological(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    size_t i = 0;
    while (i < n) {
        size_t run = 1 + (s % 5); s = s * 1103515245u + 12345u;
        for (size_t k = 0; k < run && i < n; k++, i++) b[i] = (uint8_t)i;
        size_t noise = 1 + (s % 7); s = s * 1103515245u + 12345u;
        for (size_t k = 0; k < noise && i < n; k++, i++) { s = s * 1103515245u + 12345u; b[i] = (uint8_t)(s >> 24); }
    }
}

// Mostly-random bytes with short (3-byte) matches planted at long random
// distances every ~4-16 bytes: the shape that broke crushlzvn_encode_bound()'s
// old margin at level 8 (pareto_k == 2), where neither fill_incompressible
// nor fill_pathological did. A bounded Pareto front can evict the
// pure-literal DP state in favor of a match-landing state that looks cheap
// under its cost model's undercount of a dangling literal tail (see
// crushlzvn.c's finish_with_literal_fallback comment).
static void fill_attack_shape(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    size_t i = 0;
    while (i < n) {
        size_t gap = 4 + (s % 13); s = s * 1103515245u + 12345u;
        for (size_t k = 0; k < gap && i < n; k++, i++) { s = s * 1103515245u + 12345u; b[i] = (uint8_t)(s >> 24); }
        if (i >= 16616 && i + 3 <= n) {
            size_t dist = 1 + (s % 16615); s = s * 1103515245u + 12345u;
            for (int k = 0; k < 3 && i < n; k++, i++) b[i] = b[i - dist];
        }
        if (i < n) { s = s * 1103515245u + 12345u; b[i++] = (uint8_t)(s >> 24); }
    }
}

static void check_lzfse(size_t n, const uint8_t *src) {
    crushlzfse_encode_params p;
    crushlzfse_params_for_level(3, &p); // first OPTIMAL level, the fixed 64 KiB block

    size_t bound = crushlzfse_encode_bound(n, &p);
    uint8_t *dst = malloc(bound ? bound : 1); // exact size: ASan redzone right after
    size_t enc = crushlzfse_encode_buffer_advanced(dst, bound, src, n, NULL, 0, &p);
    if (enc == 0) {
        printf("FAIL lzfse n=%zu bound=%zu: encode refused an exactly-bound-sized dst\n", n, bound);
        failures++;
    }
    free(dst);
}

static void check_lzvn(size_t n, const uint8_t *src) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(8, &p); // first OPTIMAL level, the fixed 64 KiB block

    size_t bound = crushlzvn_encode_bound(n, &p);
    uint8_t *dst = malloc(bound ? bound : 1);
    size_t enc = crushlzvn_encode_buffer_advanced(dst, bound, src, n, NULL, 0, &p);
    if (enc == 0) {
        printf("FAIL lzvn n=%zu bound=%zu: encode refused an exactly-bound-sized dst\n", n, bound);
        failures++;
    }
    free(dst);
}

int main(void) {
    // OPTIMAL-strategy calls now accept at most one LZFSE_ZOPT_BLOCK_SIZE /
    // LZVN_ZOPT_BLOCK_SIZE (65536-byte) piece per call, so every size below
    // stays at or under that. An oversized call is covered separately by
    // crushlzvn_dispatch_test.c's oversized_src case, not this exact-bound
    // property.
    size_t src_sizes[] = {0, 1, 100, 5000, 40000, 65536};

    for (size_t si = 0; si < sizeof src_sizes / sizeof src_sizes[0]; si++) {
        size_t n = src_sizes[si];
        uint8_t *src = malloc(n ? n : 1);
        for (int shape = 0; shape < 3; shape++) {
            unsigned seed = (unsigned)(7919 * (shape + 1) + n);
            if (shape == 0) fill_incompressible(src, n, seed);
            else if (shape == 1) fill_pathological(src, n, seed);
            else fill_attack_shape(src, n, seed);
            check_lzfse(n, src);
            check_lzvn(n, src);
        }
        free(src);
    }

    // GREEDY takes encode_bound()'s other branch (see bug 3 in the file
    // comment) and is bounded to the same fixed 65536-byte block as OPTIMAL;
    // an oversized call is a hard failure, covered separately by
    // crushlzvn_dispatch_test.c's oversized_src case.
    {
        size_t sizes[] = {0, 1, 100, 5000, 40000, 65536};
        for (size_t si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
            size_t n = sizes[si];
            uint8_t *src = malloc(n ? n : 1);
            for (int shape = 0; shape < 3; shape++) {
                unsigned seed = (unsigned)(9973 * (shape + 1) + n);
                if (shape == 0) fill_incompressible(src, n, seed);
                else if (shape == 1) fill_pathological(src, n, seed);
                else fill_attack_shape(src, n, seed);

                crushlzfse_encode_params fp;
                crushlzfse_params_for_level(0, &fp); // greedy
                size_t fbound = crushlzfse_encode_bound(n, &fp);
                uint8_t *fdst = malloc(fbound ? fbound : 1);
                if (crushlzfse_encode_buffer_advanced(fdst, fbound, src, n, NULL, 0, &fp) == 0) {
                    printf("FAIL lzfse GREEDY n=%zu shape=%d bound=%zu: refused exact dst\n", n, shape, fbound);
                    failures++;
                }
                free(fdst);

                crushlzvn_encode_params vp;
                crushlzvn_params_for_level(0, &vp); // greedy
                size_t vbound = crushlzvn_encode_bound(n, &vp);
                if (vbound > (1u << 20)) {
                    printf("FAIL lzvn GREEDY n=%zu shape=%d bound=%zu: absurdly large for this size\n", n, shape, vbound);
                    failures++;
                }
                uint8_t *vdst = malloc(vbound ? vbound : 1);
                if (crushlzvn_encode_buffer_advanced(vdst, vbound, src, n, NULL, 0, &vp) == 0) {
                    printf("FAIL lzvn GREEDY n=%zu shape=%d bound=%zu: refused exact dst\n", n, shape, vbound);
                    failures++;
                }
                free(vdst);
            }
            free(src);
        }
    }

    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
