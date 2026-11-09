// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Surplus final run blocks must consume neither period bytes nor bitmaps.
 * Sweep partial/full tails and explicit/table selectors with 0..2 period
 * bytes. The expected output is an independently constructed period-8 string. */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void u24(uint8_t *p, unsigned n)
{
    p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); p[2] = (uint8_t)(n >> 16);
}

static size_t stream(uint8_t *s, unsigned tail, unsigned pbc, int explicit_bitmap)
{
    const uint8_t seed[8] = {1, 7, 19, 31, 43, 59, 71, 89};
    memcpy(s, "ZBM\x09", 4);
    u24(s + 4, 14); u24(s + 7, 8); memcpy(s + 10, seed, 8);
    uint8_t *c = s + 18;
    unsigned blocks = (tail + 7) / 8, pos = 15;
    u24(c + 3, tail); u24(c + 6, pos);
    for (unsigned i = 0; i < blocks; ++i)
        for (unsigned j = 0; j < pbc; ++j) c[pos++] = j ? 0 : 8;
    u24(c + 9, pos);
    if (explicit_bitmap)
        for (unsigned i = 0; i < blocks; ++i) c[pos++] = 0;
    u24(c + 12, pos);
    c[pos++] = (uint8_t)(0xf0 | (explicit_bitmap ? pbc : 3));
    c[pos++] = 5; /* 4+5=9 blocks, even when tail needs fewer */
    /* Equal lengths select a stored chunk, irrespective of body contents. */
    if (pos + 17 == tail + 6) c[pos++] = 0;
    memset(c + pos, 0, 17);
    if (!explicit_bitmap) c[pos + 1] = (uint8_t)pbc;
    pos += 17;
    u24(c, pos);
    u24(c + pos, 6); u24(c + pos + 3, 0);
    return 18 + pos + 6;
}

int main(void)
{
    const uint8_t seed[8] = {1, 7, 19, 31, 43, 59, 71, 89};
    uint8_t s[128], out[96], want[80];
    unsigned cases = 0;
    for (unsigned i = 0; i < sizeof want; ++i) want[i] = seed[i % 8];
    for (int explicit_bitmap = 0; explicit_bitmap < 2; ++explicit_bitmap)
        for (unsigned pbc = 0; pbc < 3; ++pbc)
            for (unsigned tail = 1; tail <= 72; ++tail) {
                size_t n = stream(s, tail, pbc, explicit_bitmap), got;
                size_t total = 8 + tail;
                memset(out, 0xa5, sizeof out);
                int rc = crushlzbitmap_decode_buffer(out, total, s, n, &got);
                if (rc || got != total || memcmp(out, want, total)) {
                    fprintf(stderr, "run failed: explicit=%d pbc=%u tail=%u rc=%d got=%zu\n",
                            explicit_bitmap, pbc, tail, rc, got);
                    for (size_t i = 0; i < total; ++i)
                        if (out[i] != want[i])
                            fprintf(stderr, "  byte %zu: got %u want %u\n", i, out[i], want[i]);
                    return 1;
                }
                for (size_t i = total; i < sizeof out; ++i)
                    if (out[i] != 0xa5) return 1;
                for (size_t cap = 0; cap < total; ++cap) {
                    memset(out, 0xa5, sizeof out);
                    rc = crushlzbitmap_decode_buffer(out, cap, s, n, &got);
                    if (rc != CRUSHLZBITMAP_OUTPUT_TOO_SMALL || got != (cap < 8 ? 0 : 8))
                        return 1;
                    for (size_t i = cap; i < sizeof out; ++i)
                        if (out[i] != 0xa5) return 1;
                }
                ++cases;
            }
    /* A count beyond UINT16_MAX still describes a finite truncated final
     * run. This intentionally oversized compressed chunk is supported even
     * though Apple refuses its length relation. */
    uint8_t big[2600] = {0};
    memcpy(big, "ZBM\x09", 4);
    u24(big + 4, 14); u24(big + 7, 8); memcpy(big + 10, seed, 8);
    uint8_t *c = big + 18;
    u24(c + 3, 32); u24(c + 6, 15); u24(c + 9, 15); u24(c + 12, 15);
    c[15] = 0xf3;
    for (unsigned i = 0; i < 2500; ++i) c[16 + i] = 0xff;
    c[2516] = 0; /* terminal count digit; 4 + 5000*15 blocks */
    unsigned len = 2517 + 17;
    u24(c, len); u24(c + len, 6); u24(c + len + 3, 0);
    size_t got;
    int rc = crushlzbitmap_decode_buffer(out, 40, big, 18 + len + 6, &got);
    if (rc || got != 40 || memcmp(out, want, 40)) {
        fprintf(stderr, "long count failed: rc=%d got=%zu\n", rc, got); return 1;
    }
    printf("%u final-run cases, all undersized destinations and a long count passed\n", cases);
    return 0;
}
