// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Scratch contents never change the output. Every level of every codec
 * encodes the same inputs with scratch prefilled with 0x00, 0xA5 and 0xFF,
 * and with whatever an encode of an unrelated input left there, and each
 * must match the NULL-scratch encode byte for byte. Callers then never need
 * to clear scratch, and one caller's data cannot reach another's output.
 * LZFSE's chained encode is held to the same, for its bytes and its stats.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"
#include "crushlzvn.h"
#include "crushlzbitmap.h"
#include "crushlz4.h"

#define MAX_IN 65536

typedef size_t (*encode_fn)(void *, size_t, const void *, size_t, void *, size_t, int);

static size_t lzfse_scratch(int level) {
    crushlzfse_encode_params p;
    crushlzfse_params_for_level(level, &p);
    return crushlzfse_scratch_size(&p);
}
static size_t lzfse_bound(size_t n, int level) {
    crushlzfse_encode_params p;
    crushlzfse_params_for_level(level, &p);
    return crushlzfse_encode_bound(n, &p);
}
static size_t lzvn_scratch(int level) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(level, &p);
    return crushlzvn_scratch_size(&p);
}
static size_t lzvn_bound(size_t n, int level) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(level, &p);
    return crushlzvn_encode_bound(n, &p);
}
static size_t zbm_scratch(int level) {
    crushlzbitmap_params p;
    crushlzbitmap_params_for_level(level, &p);
    return crushlzbitmap_scratch_size(&p);
}
static size_t zbm_bound(size_t n, int level) { (void)level; return crushlzbitmap_encode_bound(n); }
static size_t lz4_scratch(int level) {
    crushlz4_encode_params p;
    crushlz4_params_for_level(level, &p);
    return crushlz4_scratch_size(&p);
}
static size_t lz4_bound(size_t n, int level) { (void)level; return crushlz4_encode_bound(n); }

static const struct {
    const char *name;
    int level_min, level_max;
    size_t (*scratch)(int);
    size_t (*bound)(size_t, int);
    encode_fn encode;
} CODECS[] = {
    {"lzfse", CRUSHLZFSE_LEVEL_MIN, CRUSHLZFSE_LEVEL_MAX, lzfse_scratch, lzfse_bound, crushlzfse_encode_buffer},
    {"lzvn", CRUSHLZVN_LEVEL_MIN, CRUSHLZVN_LEVEL_MAX, lzvn_scratch, lzvn_bound, crushlzvn_encode_buffer},
    {"lzbitmap", CRUSHLZBITMAP_LEVEL_MIN, CRUSHLZBITMAP_LEVEL_MAX, zbm_scratch, zbm_bound, crushlzbitmap_encode_buffer},
    {"lz4", CRUSHLZ4_LEVEL_MIN, CRUSHLZ4_LEVEL_MAX, lz4_scratch, lz4_bound, crushlz4_encode_buffer},
};

/* Text-like words with drifting runs, then fixed-width records: matches at
 * many distances, literals and long runs, so every tier does real work. */
static void fill_input(uint8_t *p, size_t n, uint32_t seed) {
    static const char *words[] = {"scratch ", "contract ", "level ", "block ", "stream ",
                                  "decode ", "period ", "match "};
    uint32_t x = seed;
    size_t i = 0;
    while (i < n / 2) {
        x = x * 1664525u + 1013904223u;
        const char *w = words[(x >> 24) & 7];
        for (; *w && i < n / 2; w++) p[i++] = (uint8_t)*w;
        if (((x >> 16) & 15) == 0 && i < n / 2) p[i++] = (uint8_t)(x >> 8);
    }
    for (; i < n; i++) {
        x = x * 1664525u + 1013904223u;
        p[i] = (uint8_t)((i % 24) < 8 ? i / 24 : (i % 24) < 16 ? 0x40 + (i % 7) : x >> 24);
    }
}

int main(void) {
    static const size_t sizes[] = {0, 1, 100, 4095, MAX_IN};
    static uint8_t input[MAX_IN], other[MAX_IN];
    fill_input(input, MAX_IN, 1);
    fill_input(other, MAX_IN, 2);
    unsigned checks = 0, failures = 0;

    for (size_t c = 0; c < sizeof CODECS / sizeof CODECS[0]; c++) {
        for (int level = CODECS[c].level_min; level <= CODECS[c].level_max; level++) {
            size_t need = CODECS[c].scratch(level);
            size_t cap = CODECS[c].bound(MAX_IN, level);
            uint8_t *scratch = malloc(need ? need : 1);
            uint8_t *want = malloc(cap), *got = malloc(cap);
            if (!scratch || !want || !got) abort();

            for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
                size_t n = sizes[s];
                size_t want_len = CODECS[c].encode(want, cap, input, n, NULL, 0, level);
                if (n && !want_len) {
                    printf("%-9s level %3d size %5zu: NULL-scratch encode failed\n",
                           CODECS[c].name, level, n);
                    failures++;
                    continue;
                }
                for (int fill = 0; fill < 4; fill++) {
                    if (fill < 3) {
                        static const uint8_t bytes[] = {0x00, 0xa5, 0xff};
                        memset(scratch, bytes[fill], need);
                    } else {
                        /* Leftovers from an unrelated input at the same level. */
                        if (!CODECS[c].encode(got, cap, other, MAX_IN, scratch, need, level)) abort();
                    }
                    size_t got_len = CODECS[c].encode(got, cap, input, n, scratch, need, level);
                    checks++;
                    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
                        static const char *names[] = {"0x00", "0xa5", "0xff", "leftover"};
                        printf("%-9s level %3d size %5zu scratch %-8s: output differs (%zu vs %zu bytes)\n",
                               CODECS[c].name, level, n, names[fill], got_len, want_len);
                        failures++;
                    }
                }
            }
            free(scratch);
            free(want);
            free(got);
        }
    }
    /* Chained LZFSE, seeded from an encode of the unrelated input. */
    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        crushlzfse_encode_params p;
        crushlzfse_params_for_level(level, &p);
        size_t need = crushlzfse_scratch_size(&p), cap = crushlzfse_encode_bound(MAX_IN, &p);
        uint8_t *scratch = malloc(need), *want = malloc(cap), *got = malloc(cap);
        if (!scratch || !want || !got) abort();
        crushlzfse_stats seed, want_stats, got_stats;
        memset(&seed, 0, sizeof seed);
        if (!crushlzfse_encode_buffer_chained(want, cap, other, MAX_IN, NULL, 0, &p, &seed)) abort();
        want_stats = seed;
        size_t want_len = crushlzfse_encode_buffer_chained(want, cap, input, MAX_IN, NULL, 0, &p, &want_stats);
        for (int fill = 0; fill < 4; fill++) {
            if (fill < 3) {
                static const uint8_t bytes[] = {0x00, 0xa5, 0xff};
                memset(scratch, bytes[fill], need);
            } else {
                got_stats = seed;
                if (!crushlzfse_encode_buffer_chained(got, cap, other, MAX_IN, scratch, need, &p, &got_stats)) abort();
            }
            got_stats = seed;
            size_t got_len = crushlzfse_encode_buffer_chained(got, cap, input, MAX_IN, scratch, need, &p, &got_stats);
            checks++;
            if (got_len != want_len || memcmp(got, want, want_len) != 0 ||
                memcmp(&got_stats, &want_stats, sizeof got_stats) != 0) {
                printf("lzfse chained level %3d fill %d: output or stats differ\n", level, fill);
                failures++;
            }
        }
        free(scratch);
        free(want);
        free(got);
    }

    printf("%u encodes against prefilled or reused scratch, %u differed\n", checks, failures);
    return failures ? 1 : 0;
}
