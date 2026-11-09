// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for one crushlzbitmap_encode_bound() bug, now fixed, plus
// a pin on CRUSHLZBITMAP_MAX_CHUNK_SIZE's own exactness:
//
// - crushlzbitmap_encode_bound()'s `chunks = src_size / CHUNK_SIZE + 1`
//   counted one phantom extra body chunk (a whole MAX_CHUNK_SIZE, not a
//   few bytes) whenever src_size was an exact multiple of CHUNK_SIZE,
//   since the terminator's own cost is already the separate
//   LAST_CHUNK_SIZE term. Fixed to a real ceiling division.
// - CRUSHLZBITMAP_MAX_CHUNK_SIZE itself (CHUNK_SIZE + 10) looks at first
//   like it carries 4 bytes of unexplained margin over the uncompressed
//   escape's own CHUNK_SIZE + sizeof(struct zbm_chunk_hdr) (6) - it does
//   not: crushlzbitmap_encode_chunk() also writes the 4-byte stream magic
//   inline before chunk index 0's body, so the one dst_size a caller
//   reuses across every chunk call has to cover that case too. (An
//   earlier version of this constant was trimmed to CHUNK_SIZE + 6 on
//   that mistaken assumption; this test's check_chunk() case is what
//   caught it - every call failed before the revert.)
//
// This test sizes a destination via crushlzbitmap_encode_bound() and
// CRUSHLZBITMAP_MAX_CHUNK_SIZE *exactly*, for src_size values that straddle
// and land exactly on CHUNK_SIZE multiples, every level and three input
// shapes, then feeds it to the matching encode call under ASan: any write
// past that size is a heap-buffer-overflow, and a spurious refusal (0
// return against an exact-bound dst) means the bound undersized.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

#define CHUNK CRUSHLZBITMAP_CHUNK_SIZE

static int failures;

static void fill_incompressible(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    for (size_t i = 0; i < n; i++) { s = s * 1103515245u + 12345u; b[i] = (uint8_t)(s >> 24); }
}

// Short compressible runs interleaved with noise: stresses the literal/match
// mix rather than either pure extreme.
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

// Almost entirely literals with only sparse, short matches: maximizes the
// literal byte count per chunk, which is what pushes zbm_emit_literals'
// bulk-vs-exact threshold (total vs room) closest to the chunk's own tight
// bound.
static void fill_mostly_literal(uint8_t *b, size_t n, unsigned seed) {
    unsigned s = seed;
    size_t i = 0;
    while (i < n) {
        s = s * 1103515245u + 12345u;
        b[i++] = (uint8_t)(s >> 24);
        if (i >= 64 && i + 2 <= n && (s & 0xff) == 0) {
            size_t dist = 1 + (s >> 8) % 63;
            for (int k = 0; k < 2 && i < n; k++, i++) b[i] = b[i - dist];
        }
    }
}

static size_t zbm_ladder_max_scratch(void) {
    size_t max = 0;
    for (int lv = CRUSHLZBITMAP_LEVEL_MIN; lv <= CRUSHLZBITMAP_LEVEL_MAX; ++lv) {
        crushlzbitmap_params p;
        crushlzbitmap_params_for_level(lv, &p);
        size_t n = crushlzbitmap_scratch_size(&p);
        if (n > max) max = n;
    }
    return max;
}

// crushlzbitmap_encode_chunk() at dst_size == MAX_CHUNK_SIZE exactly, for
// chunk 0 of a source at least one full CHUNK long: this is the single
// worst-case chunk, malloc'd to the exact advertised ceiling so ASan
// catches any overrun and a 0 return means the constant undersized.
static void check_chunk(int lvl, const char *shape, const uint8_t *src, size_t src_size,
                        void *scratch, size_t scratch_bytes) {
    crushlzbitmap_params p;
    crushlzbitmap_params_for_level(lvl, &p);

    uint8_t *dst = malloc(CRUSHLZBITMAP_MAX_CHUNK_SIZE);
    size_t got = crushlzbitmap_encode_chunk(dst, CRUSHLZBITMAP_MAX_CHUNK_SIZE, src, src_size, 0,
                                            scratch, scratch_bytes, &p);
    if (!got) {
        printf("FAIL chunk lvl=%d shape=%s: refused exactly-MAX_CHUNK_SIZE dst\n", lvl, shape);
        failures++;
    }
    free(dst);
}

// crushlzbitmap_encode_buffer_advanced() at dst_size ==
// crushlzbitmap_encode_bound(src_size) exactly, for a whole src_size
// (including exact CHUNK multiples, the ceiling-division regression case).
static void check_whole(int lvl, const char *shape, const uint8_t *src, size_t src_size,
                        void *scratch, size_t scratch_bytes) {
    crushlzbitmap_params p;
    crushlzbitmap_params_for_level(lvl, &p);

    size_t bound = crushlzbitmap_encode_bound(src_size);
    uint8_t *dst = malloc(bound ? bound : 1);
    size_t got = crushlzbitmap_encode_buffer_advanced(dst, bound, src, src_size, scratch, scratch_bytes, &p);
    if (!got) {
        printf("FAIL whole lvl=%d shape=%s src_size=%zu bound=%zu: refused exact dst\n",
               lvl, shape, src_size, bound);
        failures++;
    }
    free(dst);
}

int main(void) {
    size_t scratch_bytes = zbm_ladder_max_scratch();
    void *scratch = malloc(scratch_bytes ? scratch_bytes : 1);

    // Chunk sizes: straddling and landing exactly on CHUNK, since bug 1 is a
    // per-chunk margin and the tight chunk math holds regardless of how many
    // chunks make up the whole source.
    size_t chunk_src_sizes[] = {CHUNK, CHUNK + 1, 3 * CHUNK};

    // Whole-buffer sizes: 0 and 1 as edges, then straddling and landing
    // exactly on one and two CHUNK multiples, which is what bug 2 needs to
    // regress on.
    size_t whole_src_sizes[] = {0, 1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 5 * CHUNK + 1234};

    for (int lvl = CRUSHLZBITMAP_LEVEL_MIN; lvl <= CRUSHLZBITMAP_LEVEL_MAX; ++lvl) {
        for (int shape = 0; shape < 3; shape++) {
            const char *name = shape == 0 ? "incompressible" : shape == 1 ? "pathological" : "mostly_literal";

            for (size_t si = 0; si < sizeof chunk_src_sizes / sizeof chunk_src_sizes[0]; si++) {
                size_t n = chunk_src_sizes[si];
                uint8_t *src = malloc(n);
                unsigned seed = (unsigned)(7919 * (shape + 1) + n + lvl);
                if (shape == 0) fill_incompressible(src, n, seed);
                else if (shape == 1) fill_pathological(src, n, seed);
                else fill_mostly_literal(src, n, seed);
                check_chunk(lvl, name, src, n, scratch, scratch_bytes);
                free(src);
            }

            for (size_t si = 0; si < sizeof whole_src_sizes / sizeof whole_src_sizes[0]; si++) {
                size_t n = whole_src_sizes[si];
                uint8_t *src = malloc(n ? n : 1);
                unsigned seed = (unsigned)(9973 * (shape + 1) + n + lvl);
                if (shape == 0) fill_incompressible(src, n, seed);
                else if (shape == 1) fill_pathological(src, n, seed);
                else fill_mostly_literal(src, n, seed);
                check_whole(lvl, name, src, n, scratch, scratch_bytes);
                free(src);
            }
        }
    }

    free(scratch);
    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
