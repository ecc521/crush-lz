// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for two crushlz4_encode_bound() bugs, both now fixed:
//
//   1. `blocks = src_size/BLOCK_SIZE + 1` over-counted one phantom whole
//      block whenever src_size was an exact multiple of
//      CRUSHLZ4_BLOCK_SIZE, the same off-by-one-block idiom
//      zbm_bound_exactness_test.c had for lzbitmap. Fixed to a real
//      ceiling division.
//   2. Per block, encode() took any upstream LZ4 "success" (k > 0)
//      unconditionally, without comparing it to what storing the block
//      raw would have cost. A compressed result that only just fit under
//      the old block-1 cap cost 12+k bytes, up to block+11 in the worst
//      case - 3 bytes *more* than the 8+block a stored block would have
//      cost for the same input, so "worst case is every block stored"
//      (what the bound formula's comment assumed) was not actually the
//      true worst case. Fixed by capping upstream's maxOutputSize at
//      block-4 instead of block-1: any k>0 it now returns already
//      satisfies 12+k <= 8+block, so compressed can never come back worse
//      than stored, and the true worst case is a clean 8+block per block.
//
// This test sizes a destination via crushlz4_encode_bound() *exactly* and
// feeds it to crushlz4_encode_buffer() under ASan: any write past that
// size is a heap-buffer-overflow, and a spurious 0 return against an
// exact-bound dst means the bound undersized. fill_near_incompressible
// specifically targets bug 2's old edge case (a block that just barely
// compresses), though the property holds regardless of whether any run
// happens to land exactly on that edge.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"

#define BLOCK CRUSHLZ4_BLOCK_SIZE

static int failures;

static void fill_incompressible(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    for (size_t i = 0; i < n; i++) { s = s * 1103515245u + 12345u; b[i] = (uint8_t)(s >> 24); }
}

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

// Aimed at the "barely compressible" edge from bug 2 above: almost entirely
// random, with exactly one short match planted near the very end of each
// BLOCK-sized piece, so upstream LZ4 has the best chance of finding
// something that just barely fits under the block-1 cap instead of
// declining outright.
static void fill_near_incompressible(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    fill_incompressible(b, n, seed);
    for (size_t base = 0; base + BLOCK <= n || (base == 0 && n < BLOCK); base += BLOCK) {
        size_t end = base + BLOCK <= n ? base + BLOCK : n;
        if (end >= base + 8) {
            b[end - 1] = b[end - 5];
            b[end - 2] = b[end - 6];
            b[end - 3] = b[end - 7];
            b[end - 4] = b[end - 8];
        }
        if (base == 0 && n < BLOCK) break;
    }
    (void)s;
}

static void check_whole(int level, const char *shape, const uint8_t *src, size_t src_size) {
    size_t bound = crushlz4_encode_bound(src_size);
    uint8_t *dst = malloc(bound ? bound : 1);
    size_t got = crushlz4_encode_buffer(dst, bound, src, src_size, NULL, 0, level);
    if (!got) {
        printf("FAIL lz4 level=%d shape=%s src_size=%zu bound=%zu: refused exact dst\n",
               level, shape, src_size, bound);
        failures++;
    }
    free(dst);
}

int main(void) {
    size_t src_sizes[] = {0, 1, 100, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK, 5 * BLOCK + 1234};

    for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++) {
        for (int shape = 0; shape < 3; shape++) {
            const char *name = shape == 0 ? "incompressible" : shape == 1 ? "pathological" : "near_incompressible";

            for (size_t si = 0; si < sizeof src_sizes / sizeof src_sizes[0]; si++) {
                size_t n = src_sizes[si];
                uint8_t *src = malloc(n ? n : 1);
                unsigned seed = (unsigned)(104729 * (shape + 1) + n + level);
                if (shape == 0) fill_incompressible(src, n, seed);
                else if (shape == 1) fill_pathological(src, n, seed);
                else fill_near_incompressible(src, n, seed);
                check_whole(level, name, src, n);
                free(src);
            }
        }
    }

    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
