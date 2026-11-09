// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Standalone 0xf reuses the last non-0xf nibble, including count digits.
 * Sweep all 15 remembered values and partial/full final blocks against
 * independent byte semantics, ordinary-run controls and Apple's decoder. */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef __APPLE__
#include <compression.h>
#endif

static void u24(uint8_t *p, unsigned n)
{ p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); p[2] = (uint8_t)(n >> 16); }

static const uint8_t seed[8] = {1, 7, 19, 31, 43, 59, 71, 89};

static size_t build(uint8_t *s, uint8_t *want, unsigned last, unsigned tail, int reuse)
{
    memset(s, 0, 256); memcpy(s, "ZBM\x09", 4);
    uint8_t *c = s + 4;
    unsigned lead = 20 + last, total = lead * 8 + tail, pos = 15;
    unsigned literals = last == 14 ? tail : (tail > 32 ? tail - 32 : 0);
    unsigned blocks = ((tail < 32 ? tail : 32) + 7) / 8;
    unsigned pbc = last < 3 ? last : 0;
    memcpy(c + pos, seed, 8); pos += 8;
    for (unsigned i = 0; i < literals; ++i) c[pos++] = (uint8_t)(0x41 + i % 26);
    u24(c + 6, pos);
    for (unsigned i = 0; i < blocks; ++i)
        for (unsigned j = 0; j < pbc; ++j) c[pos++] = j ? 0 : 8;
    u24(c + 9, pos);
    if (last < 3)
        for (unsigned i = 0; i < blocks; ++i) c[pos++] = 0;
    u24(c + 12, pos);
    uint8_t nib[10] = {14, 13, 15, 15, (uint8_t)last};
    unsigned count = 5;
    if (reuse) { nib[count++] = 15; nib[count++] = 1; }
    else { nib[count++] = (uint8_t)last; nib[count++] = 15; nib[count++] = 0; }
    nib[count++] = 14; /* literal final block, distinguishes counts 4 vs 5 */
    for (unsigned i = 0; i < count; ++i) c[pos + i / 2] |= (uint8_t)(nib[i] << (4 * (i % 2)));
    pos += (count + 1) / 2;
    c[pos + 13] = 0xc0; c[pos + 14] = 0x3f; /* entry 11: bitmap ff, pbc 0 */
    pos += 17; u24(c, pos); u24(c + 3, total);
    u24(c + pos, 6); u24(c + pos + 3, 0);

    for (unsigned i = 0; i < lead * 8; ++i) want[i] = seed[i % 8];
    unsigned literal = 0;
    for (unsigned i = 0; i < tail; ++i) {
        unsigned p = lead * 8 + i;
        want[p] = last == 14 || i >= 32 ? (uint8_t)(0x41 + literal++ % 26) : want[p - 8];
    }
    return 4 + pos + 6;
}

int main(void)
{
    uint8_t src[256], want[320], out[336];
    unsigned cases = 0;
    for (unsigned last = 0; last < 15; ++last)
        for (unsigned tail = 1; tail <= 40; ++tail)
            for (int reuse = 0; reuse < 2; ++reuse) {
                size_t n = build(src, want, last, tail, reuse), got;
                size_t total = (20 + last) * 8 + tail;
                memset(out, 0xa5, sizeof out);
                int rc = crushlzbitmap_decode_buffer(out, total, src, n, &got);
                if (rc || got != total || memcmp(out, want, total)) {
                    fprintf(stderr, "history: last=%u tail=%u reuse=%d rc=%d got=%zu\n",
                            last, tail, reuse, rc, got); return 1;
                }
                for (size_t i = total; i < sizeof out; ++i) if (out[i] != 0xa5) return 1;
#ifdef __APPLE__
                memset(out, 0, sizeof out);
                size_t apple = compression_decode_buffer(out, sizeof out, src, n, NULL, COMPRESSION_LZBITMAP);
                if (apple != total || memcmp(out, want, total)) {
                    fprintf(stderr, "Apple history: last=%u tail=%u reuse=%d len=%zu\n",
                            last, tail, reuse, apple); return 1;
                }
#endif
                ++cases;
            }
    printf("%u selector-history cases matched byte semantics and ordinary controls\n", cases);
    return 0;
}
