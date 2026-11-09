// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Fuzz harness for the Apple-LZ4 encoder: it must never overrun its bound,
 * and everything it emits must decode back to what went in. The fuzzer's
 * bytes are a program that synthesizes matchable input, since random bytes
 * never reach the match finder. On macOS the round trip is also checked
 * through Apple's decoder, which matters because the encoder relies on two
 * behaviours (matches across block boundaries, blocks ending on a match)
 * that reference LZ4 forbids.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"
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

static uint8_t input[MAX_IN];
static uint8_t enc[MAX_IN + MAX_IN / 16 + 4096];
static uint8_t back[MAX_IN];
/* encode()'s dst-too-small path (crushlz4.c: `out_end - hdr < 12 + block`,
 * mid-loop over multiple blocks) never fires below, since `enc` is always
 * sized to at least crushlz4_encode_bound(n). See enc_gb's use in run_one. */
static guardbuf_t enc_gb;
static int enc_gb_ready;

/* ---------------------------------------------------------------- opcode src */

typedef struct { const uint8_t *p; size_t n, i; } opsrc;

/* Reads past the end yield 0, so a truncated program is still a valid one. */
static uint8_t op_u8(opsrc *s) { return s->i < s->n ? s->p[s->i++] : 0; }
static size_t op_u16(opsrc *s) { size_t hi = op_u8(s); return (hi << 8) | op_u8(s); }

/* ---------------------------------------------------------------- synthesizer */

static size_t synthesize(const uint8_t *data, size_t size, uint8_t *out, size_t cap)
{
    opsrc s = {data, size, 0};
    size_t n = 0;
    uint32_t alphabet = 4;
    uint32_t lcg = 0x2545F491u;

    while (s.i < s.n && n < cap) {
        uint8_t opcode = op_u8(&s);
        size_t room = cap - n;
        if (room == 0) break;

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
        case 1: { /* run of one byte: maximal-length match fodder */
            size_t len = (op_u16(&s) % 4096) + 1;
            if (len > room) len = room;
            memset(out + n, op_u8(&s), len);
            n += len;
            break;
        }
        case 2: { /* back-copy at a chosen distance: the match path directly */
            size_t len = (op_u16(&s) % 512) + 1;
            size_t dist = n ? (op_u16(&s) % n) + 1 : 0;
            if (dist == 0) break;
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
            break;
        }
        case 3: { /* incompressible island */
            size_t len = (op_u16(&s) % 2048) + 1;
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++) {
                lcg = lcg * 1664525u + 1013904223u;
                out[n++] = (uint8_t)(lcg >> 24);
            }
            break;
        }
        case 4: /* entropy regime change in place */
            { uint8_t a = op_u8(&s); alphabet = (a & 1) ? 2 + (a % 6) : 16 + (a % 240); }
            break;
        case 5: { /* match at or just under CRUSHLZ4_MAX_OFFSET */
            size_t dist = CRUSHLZ4_MAX_OFFSET - (op_u8(&s) % 3);
            size_t len = (op_u16(&s) % 300) + CRUSHLZ4_MIN_MATCH;
            if (dist > n) break;
            if (len > room) len = room;
            for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
            break;
        }
        case 6: { /* land a match right on a 64 KiB block boundary */
            size_t seam = CRUSHLZ4_BLOCK_SIZE;
            while (seam <= n) seam += CRUSHLZ4_BLOCK_SIZE;
            if (seam > cap) break;
            size_t lead = seam - n - (op_u8(&s) % 64) - 1;
            for (size_t k = 0; k < lead && n < cap; k++) {
                lcg = lcg * 1664525u + 1013904223u;
                out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
            }
            size_t dist = n ? (op_u16(&s) % n) + 1 : 0;
            size_t len = (op_u16(&s) % 256) + CRUSHLZ4_MIN_MATCH;
            if (dist == 0) break;
            if (len > cap - n) len = cap - n;
            for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
            break;
        }
        default: { /* size edges */
            static const size_t edges[] = {0, 1, 2, 3, 4, 5,
                                           CRUSHLZ4_BLOCK_SIZE - 1, CRUSHLZ4_BLOCK_SIZE,
                                           CRUSHLZ4_BLOCK_SIZE + 1,
                                           2 * CRUSHLZ4_BLOCK_SIZE};
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

/* --------------------------------------------------------------------- check */

static void run_one(const uint8_t *data, size_t size)
{
    if (size < 2) return;

    int level = (int)(data[0] % (unsigned)(CRUSHLZ4_LEVEL_MAX - CRUSHLZ4_LEVEL_MIN + 1))
                + CRUSHLZ4_LEVEL_MIN;
    size_t n = synthesize(data + 1, size - 1, input, sizeof input);

    size_t bound = crushlz4_encode_bound(n);
    if (bound > sizeof enc) return;

    // Half the runs go through the level ladder; the other half drive
    // crushlz4_encode_buffer_advanced() with raw, fuzzer-chosen params:
    // the level ladder only ever reaches acceleration up to 16, which is
    // exactly why the advanced API's own int16_t truncation of a larger
    // value went unfuzzed (crushlz4.c, fixed this session). Frequently
    // out-of-range on purpose, to exercise rejection too.
    size_t elen;
    if (size >= 6 && (data[1] & 1)) {
        crushlz4_encode_params params;
        if (data[1] & 2) {
            params.mode = CRUSHLZ4_MODE_HC;
            params.hc_level = (int)((uint32_t)data[2] | (uint32_t)data[3] << 8);
        } else {
            params.mode = CRUSHLZ4_MODE_FAST;
            params.acceleration = (int)((uint32_t)data[2] | (uint32_t)data[3] << 8 |
                                        (uint32_t)data[4] << 16 | (uint32_t)data[5] << 24);
        }
        elen = crushlz4_encode_buffer_advanced(enc, sizeof enc, input, n, NULL, 0, &params);
    } else {
        elen = crushlz4_encode_buffer(enc, sizeof enc, input, n, NULL, 0, level);
    }
    if (elen == 0) return;
    fuzz_check_written(enc, elen);
    if (elen > bound) abort();

    /* A dst_size too small to hold every block must fail cleanly rather than
     * overrun: the multi-block encode loop's own range check, distinct
     * from (and upstream of) the single final end-marker check that a
     * dst_size only 1-3 bytes short would exercise instead. Sized to a
     * quarter of what the full encode needed, so anything spanning more than
     * one block runs out mid-loop; ending on a guard page turns any overrun
     * into a fault instead of a quiet corruption of `enc`. */
    if (!enc_gb_ready) { guardbuf_init(&enc_gb, sizeof enc); enc_gb_ready = 1; }
    size_t small_cap = elen / 4;
    uint8_t *small_dst = guard_dst(&enc_gb, small_cap);
    size_t selen = crushlz4_encode_buffer(small_dst, small_cap, input, n, NULL, 0, level);
    if (selen != 0 && selen > small_cap) abort();
    fuzz_check_written(small_dst, selen);

    size_t blen = 0;
    int drc = crushlz4_decode_buffer(back, sizeof back, enc, elen, &blen);
    fuzz_check_written(back, blen);
    if (drc != 0) abort();
    if (blen != n || memcmp(back, input, n) != 0) abort();

#if HAVE_APPLE_DECODER
    apple_oracle(COMPRESSION_LZ4, crushlz4_decode_buffer, input, n, enc, elen);
#endif
}

#include "driver.h"
