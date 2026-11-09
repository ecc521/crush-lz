// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Fresh, dirty and reused caller scratch must behave like internal scratch.
 * Run under MSan as well: fresh scratch intentionally remains uninitialized.
 * Ragged bitmap counts exercise the final SIMD run-boundary comparison. */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    size_t sizes[] = {8, 31, 4095, 4096, 32768, 65537};
    uint8_t src[65537], back[65537];
    size_t bound = crushlzbitmap_encode_bound(sizeof src);
    uint8_t *expected = malloc(bound), *actual = malloc(bound);
    if (!expected || !actual) abort();
    for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)(i % 45);
    unsigned checks = 0;
    for (int level = CRUSHLZBITMAP_LEVEL_MIN; level <= CRUSHLZBITMAP_LEVEL_MAX; level++) {
        crushlzbitmap_params p;
        crushlzbitmap_params_for_level(level, &p);
        size_t need = crushlzbitmap_scratch_size(&p);
        void *scratch = malloc(need);
        if (!scratch) abort();
        for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
            size_t n = sizes[k];
            size_t len = crushlzbitmap_encode_buffer(expected, bound, src, n, NULL, 0, level);
            if (!len) abort();
            for (unsigned mode = 0; mode < 3; mode++) {
                if (mode == 0) {
                    free(scratch);
                    scratch = malloc(need);
                    if (!scratch) abort();
                }
                if (mode == 1) memset(scratch, 0xa5, need);
                size_t out = crushlzbitmap_encode_buffer(actual, bound, src, n, scratch, need, level);
                size_t got = 0;
                if (out != len || memcmp(expected, actual, len) ||
                    crushlzbitmap_decode_buffer(back, n, actual, out, &got) || got != n || memcmp(src, back, n)) {
                    fprintf(stderr, "scratch initialization differs: level=%d n=%zu mode=%u\n", level, n, mode);
                    return 1;
                }
                checks++;
            }
        }
        free(scratch);
    }
    /* A raw caller buffer whose words look like epoch-1 references to
     * position zero changes this input's compressed representation
     * (3357 versus 3356 bytes) before the epoch initialization fix.
     * Compare exact bytes as well as length to reject either form of drift. */
    uint32_t rng = 5;
    for (size_t i = 0; i < 4095; i++) {
        rng = rng * 1664525u + 1013904223u;
        src[i] = (uint8_t)(rng >> 24);
    }
    for (size_t i = 16; i + 8 <= 4095; i += 32) memcpy(src + i, src, 8);
    crushlzbitmap_params params;
    crushlzbitmap_params_for_level(1, &params);
    size_t need = crushlzbitmap_scratch_size(&params);
    uint32_t *primed = malloc(need);
    if (!primed) abort();
    for (size_t i = 0; i < need / sizeof *primed; i++) primed[i] = 1u << 24;
    size_t len = crushlzbitmap_encode_buffer(expected, bound, src, 4095, NULL, 0, 1);
    size_t out = crushlzbitmap_encode_buffer(actual, bound, src, 4095, primed, need, 1);
    if (!len || out != len || memcmp(expected, actual, len)) {
        fprintf(stderr, "compressed output depends on preexisting scratch tags\n");
        return 1;
    }
    free(primed);
    checks++;
    /* Reuse one allocation across table layouts and many inputs. Each call
     * must ignore the preceding input. */
    size_t max_need = 0;
    for (int level = CRUSHLZBITMAP_LEVEL_MIN; level <= CRUSHLZBITMAP_LEVEL_MAX; level++) {
        crushlzbitmap_params_for_level(level, &params);
        size_t bytes = crushlzbitmap_scratch_size(&params);
        if (bytes > max_need) max_need = bytes;
    }
    void *shared = malloc(max_need);
    if (!shared) abort();
    memset(shared, 0xa5, max_need);
    for (unsigned call = 0; call < 1040; call++) {
        int level = (int)(call % (CRUSHLZBITMAP_LEVEL_MAX - CRUSHLZBITMAP_LEVEL_MIN + 1)) + CRUSHLZBITMAP_LEVEL_MIN;
        for (size_t i = 0; i < 4095; i++) {
            rng = rng * 1664525u + 1013904223u;
            src[i] = (uint8_t)(rng >> 24);
        }
        for (size_t i = 16; i + 8 <= 4095; i += 32) memcpy(src + i, src, 8);
        len = crushlzbitmap_encode_buffer(expected, bound, src, 4095, NULL, 0, level);
        out = crushlzbitmap_encode_buffer(actual, bound, src, 4095, shared, max_need, level);
        size_t got = 0;
        if (!len || out != len || memcmp(expected, actual, len) ||
            crushlzbitmap_decode_buffer(back, 4095, actual, out, &got) ||
            got != 4095 || memcmp(src, back, got)) {
            fprintf(stderr, "scratch reuse differs: call=%u level=%d\n", call, level);
            return 1;
        }
        checks++;
    }

    /* Exercise index continuity across many native 32-KiB chunks within
     * one encode. Epochs need not advance when the index carries forward. */
    size_t long_size = 9u * 1024u * 1024u;
    size_t long_bound = crushlzbitmap_encode_bound(long_size);
    uint8_t *long_src = malloc(long_size), *long_back = malloc(long_size);
    uint8_t *long_expected = malloc(long_bound), *long_actual = malloc(long_bound);
    if (!long_src || !long_back || !long_expected || !long_actual) abort();
    for (size_t i = 0; i < long_size; i++) long_src[i] = (uint8_t)(i % 251);
    memset(shared, 0x01, max_need);
    len = crushlzbitmap_encode_buffer(long_expected, long_bound, long_src, long_size, NULL, 0, 0);
    out = crushlzbitmap_encode_buffer(long_actual, long_bound, long_src, long_size, shared, max_need, 0);
    size_t got = 0;
    if (!len || out != len || memcmp(long_expected, long_actual, len) ||
        crushlzbitmap_decode_buffer(long_back, long_size, long_actual, out, &got) ||
        got != long_size || memcmp(long_src, long_back, got)) {
        fprintf(stderr, "scratch differs across a long multi-chunk encode\n");
        return 1;
    }
    checks++;
    free(long_src); free(long_back); free(long_expected); free(long_actual);
    free(shared);
    free(expected); free(actual);
    printf("%u scratch initialization checks passed\n", checks);
    return 0;
}
