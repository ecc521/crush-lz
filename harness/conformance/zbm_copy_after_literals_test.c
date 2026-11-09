// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Each actual copy references produced output; an early block-start check
 * would reject these coherent streams. Apple rejects the original seven
 * period-eight layouts, so this is an intentional format extension with
 * bytewise expectations. Cases with period nine and higher use a full
 * eight-byte prefix and demonstrate that the old check was reachable. */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void u24(uint8_t *p, unsigned n)
{ p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); p[2] = (uint8_t)(n >> 16); }

int main(void)
{
    const uint8_t seed[8] = {1, 7, 19, 31, 43, 59, 71, 89};
    for (unsigned testcase = 1; testcase <= 14; ++testcase) {
        unsigned prefix = testcase < 8 ? testcase : 8;
        unsigned period = testcase < 8 ? 8 : testcase + 1;
        uint8_t src[80] = {0}, want[136], out[144];
        memcpy(src, "ZBM\x09", 4); u24(src + 4, 6 + prefix);
        u24(src + 7, prefix); memcpy(src + 10, seed, prefix);
        uint8_t *c = src + 10 + prefix;
        unsigned literals = period - prefix, off1 = 15 + literals;
        unsigned off = off1 + (period > 8), len = off + 2 + 17;
        u24(c, len); u24(c + 3, 128);
        u24(c + 6, off1); u24(c + 9, off); u24(c + 12, off);
        if(period > 8) c[off1] = (uint8_t)period;
        for (unsigned i = 0; i < literals; ++i) c[15 + i] = (uint8_t)(0x41 + i);
        c[off] = 0x43; c[off + 1] = 0xbf; /* mixed block, then 15 copy blocks */
        c[off + 2] = (uint8_t)((1u << literals) - 1); /* table entry 0 */
        if(period > 8) c[off + 3] = 1; /* entry 0 pbc = 1; later copies pbc = 0 */
        u24(c + len, 6);
        size_t n = 10 + prefix + len + 6, total = prefix + 128, got;
        memcpy(want, seed, prefix);
        for (unsigned i = 0; i < 128; ++i)
            want[prefix + i] = i < literals ? (uint8_t)(0x41 + i) : want[prefix + i - period];
        memset(out, 0xa5, sizeof out);
        int rc = crushlzbitmap_decode_buffer(out, total, src, n, &got);
        if (rc || got != total || memcmp(out, want, total)) {
            fprintf(stderr, "copy after literals: prefix=%u period=%u rc=%d got=%zu\n", prefix, period, rc, got);
            return 1;
        }
        for (size_t i = total; i < sizeof out; ++i) if (out[i] != 0xa5) return 1;
        for (size_t cap = 0; cap < total; ++cap) {
            memset(out, 0xa5, sizeof out);
            rc = crushlzbitmap_decode_buffer(out, cap, src, n, &got);
            if (rc != CRUSHLZBITMAP_OUTPUT_TOO_SMALL || got != (cap < prefix ? 0 : prefix)) return 1;
            for (size_t i = cap; i < sizeof out; ++i) if (out[i] != 0xa5) return 1;
        }
    }
    puts("literal-prefix copies and all undersized destinations passed");
    return 0;
}
