// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The encoder never emits copy periods 1-7, so these streams are built by hand.
 * Apple's libcompression decoder mishandles these periods on all macOS versions.
 * Our decoder rejects them instead of reproducing Apple's output.
 *
 * Container layout:
 *
 *     ZBM\x09
 *     chunk: [15-byte header][literals][meta_1][meta_2][meta_3][17-byte table]
 *     terminating chunk: len 6, decmp_len 0
 *
 * meta_1 carries period bytes, meta_2 explicit bitmaps, meta_3 a nibble
 * stream of block selectors.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

#define TABLE_BYTES 17
#define HDR_BYTES   15   /* five uint24: len, decmp_len, and three offsets */

static int failures;

/* ------------------------------------------------------------ stream writer */

typedef struct {
    uint8_t  lit[8192];  size_t nlit;
    uint8_t  m1[4096];   size_t nm1;
    uint8_t  m2[4096];   size_t nm2;
    uint8_t  m3[4096];   size_t nm3;   /* nibbles, one per byte; packed later */
    uint16_t tbl[12];                  /* bitmap | period_bytecnt << 8 */
    uint8_t  expect[16384]; size_t nexp;
    uint16_t period;
} builder;

static void put_nibble(builder *b, uint8_t v) { b->m3[b->nm3++] = (uint8_t)(v & 0xf); }

static void put_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16);
}

/*
 * Emit one block: `bitmap` marks literal positions, `new_period` is 0 to keep
 * the current period or a value to change to it. Also advances the model.
 */
static void emit_block(builder *b, uint8_t bitmap, uint16_t new_period, size_t count)
{
    uint8_t pbc = 0;

    if (new_period) {
        pbc = new_period <= 0xff ? 1 : 2;
        b->period = new_period;
    }

    /* Selector nibble 0..2 means "explicit bitmap from meta_2, with this many
     * period bytes"; 3..14 index the table. */
    put_nibble(b, pbc);
    b->m2[b->nm2++] = bitmap;
    if (pbc >= 1) b->m1[b->nm1++] = (uint8_t)new_period;
    if (pbc == 2) b->m1[b->nm1++] = (uint8_t)(new_period >> 8);

    for (size_t j = 0; j < count; j++) {
        size_t pos = b->nexp;
        if (bitmap & (1u << j)) {
            uint8_t v = (uint8_t)(0xA0 + (b->nlit & 0x3f));
            b->lit[b->nlit++] = v;
            b->expect[pos] = v;
        } else {
            b->expect[pos] = b->expect[pos - b->period];
        }
        b->nexp++;
    }
}

/* Emit a run: the same indexed bitmap repeated `repeat` times, which reaches
 * the path that fills a whole run at once. */
static void emit_run(builder *b, int tbl_idx, uint8_t bitmap, int repeat, size_t total)
{
    b->tbl[tbl_idx] = bitmap;             /* period_bytecnt 0: period unchanged */
    put_nibble(b, (uint8_t)(tbl_idx + 3));
    put_nibble(b, 0xf);
    put_nibble(b, (uint8_t)(repeat - 4)); /* count is 4 + this nibble */

    for (size_t k = 0; k < total; k++) {
        size_t pos = b->nexp;
        size_t j = k % 8;
        if (bitmap & (1u << j)) {
            uint8_t v = (uint8_t)(0xA0 + (b->nlit & 0x3f));
            b->lit[b->nlit++] = v;
            b->expect[pos] = v;
        } else {
            b->expect[pos] = b->expect[pos - b->period];
        }
        b->nexp++;
    }
}

/* Pack the 12 bitmap-table entries as a little-endian bit stream, 10 bits
 * each, at the chunk's last bytes. */
static void pack_table(const uint16_t *tbl, uint8_t *out)
{
    memset(out, 0, TABLE_BYTES);
    for (int i = 0; i < 12; i++)
        for (int bit = 0; bit < 10; bit++)
            if (tbl[i] >> bit & 1) {
                int at = i * 10 + bit;
                out[at >> 3] |= (uint8_t)(1u << (at & 7));
            }
}

/* Assemble the finished stream. Returns its length. */
static size_t finish(const builder *b, uint8_t *out, size_t cap)
{
    size_t m3_bytes = (b->nm3 + 1) / 2;
    size_t off1 = HDR_BYTES + b->nlit;
    size_t off2 = off1 + b->nm1;
    size_t off3 = off2 + b->nm2;
    size_t len  = off3 + m3_bytes + TABLE_BYTES;
    uint8_t *chunk;

    if (4 + len + 6 > cap) { fprintf(stderr, "stream buffer too small\n"); exit(1); }

    memcpy(out, "ZBM\x09", 4);
    chunk = out + 4;
    memset(chunk, 0, len);

    put_u24(chunk + 0,  (uint32_t)len);
    put_u24(chunk + 3,  (uint32_t)b->nexp);
    put_u24(chunk + 6,  (uint32_t)off1);
    put_u24(chunk + 9,  (uint32_t)off2);
    put_u24(chunk + 12, (uint32_t)off3);

    memcpy(chunk + HDR_BYTES, b->lit, b->nlit);
    memcpy(chunk + off1, b->m1, b->nm1);
    memcpy(chunk + off2, b->m2, b->nm2);
    for (size_t i = 0; i < b->nm3; i++)
        chunk[off3 + i / 2] |= (uint8_t)(b->m3[i] << (4 * (i & 1)));
    pack_table(b->tbl, chunk + len - TABLE_BYTES);

    /* Terminating chunk: decmp_len 0, len 6. `len == decmp_len + 6` marks a
     * chunk as stored; a terminator with len 0 parses as compressed. */
    memset(chunk + len, 0, 6);
    put_u24(chunk + len, 6);
    return 4 + len + 6;
}

/* ------------------------------------------------------------------- checks */

static void run_case(const char *label, const builder *b)
{
    uint8_t stream[65536], got[16384];
    size_t slen = finish(b, stream, sizeof stream);
    size_t nout = 0;
    int rc = crushlzbitmap_decode_buffer(got, sizeof got, stream, slen, &nout);

    if (rc == 0) {
        fprintf(stderr, "FAIL %s: decoder accepted a period<8 stream (nout=%zu); "
                "it must reject these\n", label, nout);
        failures++;
    }
}

static void init(builder *b)
{
    memset(b, 0, sizeof *b);
    b->period = 8;
}

int main(void)
{
    char label[96];

    /* Mixed bitmaps at every period the blend path cannot take. The first
     * block is all-literal so there is something to source from. */
    for (int period = 1; period < 8; period++) {
        for (unsigned bitmap = 0; bitmap < 256; bitmap++) {
            builder b;
            init(&b);
            emit_block(&b, 0xff, 0, 8);                    /* seed */
            emit_block(&b, (uint8_t)bitmap, (uint16_t)period, 8);
            for (int k = 0; k < 6; k++)
                emit_block(&b, (uint8_t)bitmap, 0, 8);
            snprintf(label, sizeof label, "block period=%d bitmap=0x%02x",
                     period, bitmap);
            run_case(label, &b);
        }
    }

    /* A copy in the very first block, sourcing bytes that same block wrote.
     * Legal from position `period` on. */
    for (int period = 1; period < 8; period++) {
        builder b;
        uint8_t bitmap = (uint8_t)((1u << period) - 1);  /* literals, then copies */
        init(&b);
        b.period = (uint16_t)period;
        emit_block(&b, bitmap, (uint16_t)period, 8);
        emit_block(&b, bitmap, 0, 8);
        snprintf(label, sizeof label, "first-block period=%d", period);
        run_case(label, &b);
    }

    /* Runs at a small period: all-copy reaches the run fill's doubling path,
     * mixed falls to per-block. Both must agree with the model. */
    for (int period = 1; period < 8; period++) {
        for (unsigned bitmap = 0; bitmap < 256; bitmap += 17) {
            for (int repeat = 4; repeat <= 12; repeat += 4) {
                builder b;
                init(&b);
                emit_block(&b, 0xff, 0, 8);
                emit_block(&b, 0xff, (uint16_t)period, 8);
                emit_run(&b, 0, (uint8_t)bitmap, repeat, (size_t)repeat * 8);
                emit_block(&b, 0xff, 0, 8);
                snprintf(label, sizeof label,
                         "run period=%d bitmap=0x%02x repeat=%d",
                         period, bitmap, repeat);
                run_case(label, &b);
            }
        }
    }

    /* A trailing partial block, where the bitmap's high bits are don't-care. */
    for (int period = 1; period < 8; period++) {
        for (size_t tail = 1; tail < 8; tail++) {
            builder b;
            init(&b);
            emit_block(&b, 0xff, 0, 8);
            emit_block(&b, 0x0f, (uint16_t)period, 8);
            emit_block(&b, 0x0f, 0, tail);
            snprintf(label, sizeof label, "partial period=%d tail=%zu",
                     period, tail);
            run_case(label, &b);
        }
    }

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("small-period rejection ok\n");
    return 0;
}
