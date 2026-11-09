// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Fuzz harness for the LZMESH encoder: it must never overrun its bound or a
 * short destination, and everything it emits must decode back to what went
 * in, under our decoder and (on macOS) Apple's. Apple's decoder is the real
 * referee here: it rejects blocks over its scratch budget, so the synthesizer
 * leans on inputs that fill blocks with literals, short new-distance matches
 * or extras.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzmesh.h"
#include "guardbuf.h"
#include "fuzzbuf.h"
#include "apple_oracle.h"

#if defined(__APPLE__)
#include <compression.h>
#define HAVE_APPLE_DECODER 1
#else
#define HAVE_APPLE_DECODER 0
#endif

#define MAX_IN (256 * 1024)
/* The optimal levels are slow under ASan; keep their inputs smaller. */
#define MAX_IN_OPTIMAL (64 * 1024)

static uint8_t input[MAX_IN];
static uint8_t enc[MAX_IN + 4096];
static uint8_t back[MAX_IN];
static guardbuf_t enc_gb;
static int enc_gb_ready;

typedef struct { const uint8_t *p; size_t n, i; } opsrc;

/* Reads past the end yield 0, so a truncated program is still a valid one. */
static uint8_t op_u8(opsrc *s) { return s->i < s->n ? s->p[s->i++] : 0; }
static size_t op_u16(opsrc *s) { size_t hi = op_u8(s); return (hi << 8) | op_u8(s); }

static size_t synthesize(const uint8_t *data, size_t size, uint8_t *out, size_t cap)
{
    opsrc s = {data, size, 0};
    size_t n = 0;
    uint32_t alphabet = 4;
    uint32_t lcg = 0x2545F491u;

    while (s.i < s.n && n < cap) {
        uint8_t opcode = op_u8(&s);
        size_t room = cap - n;

        switch (opcode & 7) {
        case 0: { /* literal run from a small alphabet */
            size_t len = (op_u16(&s) % 512) + 1;
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++) {
                lcg = lcg * 1664525u + 1013904223u;
                out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
            }
            break;
        }
        case 1: { /* run of one byte: long rep0 matches and extras */
            size_t len = (op_u16(&s) % 8192) + 1;
            if (len > room) len = room;
            memset(out + n, op_u8(&s), len);
            n += len;
            break;
        }
        case 2: { /* back-copy at a chosen distance, near or far */
            size_t len = (op_u16(&s) % 512) + 1;
            size_t dist = n ? ((op_u16(&s) << 8 | op_u8(&s)) % n) + 1 : 0;
            if (dist == 0) break;
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
            break;
        }
        case 3: { /* incompressible island: raw blocks and literal-only pieces */
            size_t len = (op_u16(&s) % 2048 + 1) * (op_u8(&s) % 64 + 1);
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++) {
                lcg = lcg * 1664525u + 1013904223u;
                out[n++] = (uint8_t)(lcg >> 24);
            }
            break;
        }
        case 4: /* entropy regime change */
            { uint8_t a = op_u8(&s); alphabet = (a & 1) ? 2 + (a % 6) : 16 + (a % 240); }
            break;
        case 5: { /* many short matches at fresh distances: fills the
                     distance part of the block budget */
            size_t count = op_u16(&s) % 4096 + 1;
            for (size_t c = 0; c < count && n + 8 < cap && n > 64; c++) {
                lcg = lcg * 1664525u + 1013904223u;
                size_t dist = 1 + (lcg >> 8) % (n - 1);
                size_t len = 2 + (lcg & 3);
                for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
                out[n++] = (uint8_t)(lcg >> 3);
            }
            break;
        }
        case 6: { /* repeat-distance cycling: ops with every rep slot */
            size_t count = op_u16(&s) % 2048 + 1;
            size_t d[4] = {1 + op_u8(&s), 9 + op_u8(&s), 300 + op_u16(&s), 5000 + op_u16(&s)};
            for (size_t c = 0; c < count && n + 16 < cap; c++) {
                size_t dist = d[(lcg >> 13) & 3];
                lcg = lcg * 1664525u + 1013904223u;
                if (dist > n) { out[n++] = (uint8_t)lcg; continue; }
                size_t len = 2 + (lcg >> 20) % 12;
                for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
                out[n++] = (uint8_t)(lcg >> 7);
            }
            break;
        }
        default: { /* size edges, including literal and budget limits */
            static const size_t edges[] = {0, 1, 2, 15, 16, 17, 4096, 32767, 32768, 32769,
                                           62000, 62944, 65535, 65536, 65537, 131072};
            size_t want = edges[op_u8(&s) % (sizeof edges / sizeof edges[0])];
            if (want > cap) want = cap;
            if (want > n) {
                while (n < want) {
                    lcg = lcg * 1664525u + 1013904223u;
                    out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
                }
            } else {
                n = want;
            }
            break;
        }
        }
    }
    return n;
}

#if HAVE_APPLE_DECODER
static int decode_adapter(void *dst, size_t dst_size, const void *src, size_t src_size, size_t *got)
{
    return crushlzmesh_decode_buffer((uint8_t *)dst, dst_size, (const uint8_t *)src, src_size, got);
}
#endif

static void fail(const char *why, int level, size_t n, size_t got)
{
    fprintf(stderr, "FUZZ FAILURE: %s (level %d, input %zu, got %zu)\n", why, level, n, got);
    abort();
}

static void run_one(const uint8_t *data, size_t size)
{
    if (size < 8) return;

    int level = (int)(data[0] % (unsigned)(CRUSHLZMESH_LEVEL_MAX - CRUSHLZMESH_LEVEL_MIN + 1))
                + CRUSHLZMESH_LEVEL_MIN;
    crushlzmesh_params prm;
    crushlzmesh_params_for_level(level, &prm);
    // A quarter of the runs use raw params, often out of range, so the
    // encoder's clamps get exercised too.
    if ((data[1] & 3) == 0) {
        prm.strategy = (crushlzmesh_strategy)(data[2] % 5);
        prm.hash_bits = (int8_t)data[3];
        prm.max_depth = (int8_t)data[4] * 9;
        prm.search_depth = (int8_t)data[4] * 9;
        prm.lookahead = (int16_t)(data[5] << 8 | data[6]);
        prm.iterations = (int8_t)data[7] % 12;
    }
    size_t cap = prm.strategy == CRUSHLZMESH_STRAT_OPTIMAL ? MAX_IN_OPTIMAL : MAX_IN;
    size_t n = synthesize(data + 8, size - 8, input, cap);

    size_t bound = crushlzmesh_encode_bound(n);
    if (bound > sizeof enc) return;
    if (!enc_gb_ready) { guardbuf_init(&enc_gb, sizeof enc); enc_gb_ready = 1; }

    // The bound must be enough, and nothing may be written past it.
    uint8_t *dst = guard_dst(&enc_gb, bound);
    size_t elen = crushlzmesh_encode_buffer(dst, bound, input, n, NULL, &prm);
    if (elen == 0) fail("encode failed with a bound-sized destination", level, n, 0);
    if (elen > bound) fail("encode exceeded its bound", level, n, elen);
    fuzz_check_written(dst, elen);
    memcpy(enc, dst, elen);

    // A short destination must fail cleanly or fit.
    size_t small_cap = (size_t)data[1] * elen / 256;
    uint8_t *small_dst = guard_dst(&enc_gb, small_cap);
    size_t selen = crushlzmesh_encode_buffer(small_dst, small_cap, input, n, NULL, &prm);
    if (selen > small_cap) fail("encode exceeded a short destination", level, n, selen);
    fuzz_check_written(small_dst, selen);

    size_t blen = 0;
    int drc = crushlzmesh_decode_buffer(back, sizeof back, enc, elen, &blen);
    fuzz_check_written(back, blen);
    if (drc != 0 || blen != n || memcmp(back, input, n) != 0)
        fail("our decoder rejected or changed our output", level, n, blen);

#if HAVE_APPLE_DECODER
    apple_oracle(COMPRESSION_LZMESH, decode_adapter, input, n, enc, elen);
#endif
}

#include "driver.h"
