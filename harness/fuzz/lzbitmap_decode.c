// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Fuzz harness for the LZBITMAP decoder on hostile input. The contract is
 * that a decode returns an error or a correct length and never touches
 * memory outside its buffers; ASan and UBSan are the judges.
 *
 * Random bytes rarely pass the magic check, so half the budget goes to real
 * streams damaged by byte flips, truncation, or extension past the end.
 * Periods 1-7 are rejected by the decoder and never emitted by the encoder.
 * Hand-built seeds exercise rejection of those periods.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"
#include "guardbuf.h"
#include "fuzzbuf.h"

#define MAX_IN  (256 * 1024)
#define MAX_OUT (512 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t seed_data[64 * 1024];
/* Our own decoder is ASan-instrumented, so a write past a plain array's true
 * allocation is already caught — the gap a fixed oversized `out` leaves is
 * an overflow that stays inside that allocation but past the *logical*
 * length the decoder reports. A guarded, exactly-sized destination turns
 * that into a fault too. */
static guardbuf_t out_gb;
static uint8_t *out;

/* A hand-built chunk at a period below 8, laid out as
 * [15-byte header][literals][meta_1][meta_2][meta_3][17-byte table]; the same
 * construction zbm_small_period_rejected_test.c checks. Returns its length. */
static size_t build_small_period_stream(const uint8_t *prog, size_t plen) {
    unsigned period = 1u + (prog[1] % 7u);
    unsigned blocks = 4u + (prog[2] % 60u);
    uint8_t bitmap = prog[3];
    size_t nlit = 8;
    size_t nm2 = blocks + 1, nm1 = 1;
    size_t off1, off2, off3, m3_bytes, len;
    uint8_t *c = stream + 4;

    for (unsigned b = 0; b < blocks; b++)
        nlit += (size_t)__builtin_popcount(bitmap);

    m3_bytes = (blocks + 1 + 1) / 2;
    off1 = 15 + nlit;
    off2 = off1 + nm1;
    off3 = off2 + nm2;
    len  = off3 + m3_bytes + 17;
    if (4 + len + 6 > sizeof stream) return 0;

    memcpy(stream, "ZBM\x09", 4);
    memset(c, 0, len + 6);
    /* five uint24: len, decmp_len, and the three area offsets */
    for (int f = 0; f < 5; f++) {
        uint32_t v = (uint32_t)(f == 0 ? len : f == 1 ? (blocks + 1) * 8
                                            : f == 2 ? off1 : f == 3 ? off2 : off3);
        c[f * 3] = (uint8_t)v; c[f * 3 + 1] = (uint8_t)(v >> 8); c[f * 3 + 2] = (uint8_t)(v >> 16);
    }
    for (size_t i = 0; i < nlit; i++) c[15 + i] = (uint8_t)(prog[(i + 4) % plen]);
    c[off1] = (uint8_t)period;
    c[off2] = 0xff;                               /* seed block: all literal */
    for (unsigned b = 0; b < blocks; b++) c[off2 + 1 + b] = bitmap;
    /* Selector nibbles: 0 for the seed block, then 1 to move to the small
     * period, then 0s. */
    c[off3] = 1 << 4;
    (void)0;
    memset(c + len, 0, 6);
    c[len] = 6;                                   /* terminator's own length */
    return 4 + len + 6;
}

/* Build a real stream and damage it. Returns its length, or 0. */
static size_t damage_valid_stream(const uint8_t *prog, size_t plen) {
    size_t len = 0;

    if (plen < 8) return 0;

    if ((prog[0] >> 3) & 1) {
        len = build_small_period_stream(prog, plen);
    } else {
        unsigned period = 1u + (prog[1] % 64u);
        size_t n = 4096 + ((size_t)prog[2] << 6);
        if (n > sizeof seed_data) n = sizeof seed_data;
        for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);
        len = crushlzbitmap_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0,
                                          CRUSHLZBITMAP_LEVEL_DEFAULT);
    }
    if (len == 0) return 0;

    switch ((prog[0] >> 1) & 3) {
    case 0: /* flips */
        for (size_t i = 4; i + 1 < plen && i < 64; i += 2)
            stream[((size_t)prog[i] << 8 | prog[i + 1]) % len] ^= prog[(i + 1) % plen];
        break;
    case 1: /* truncation, anywhere including mid-header */
        len = 1 + (((size_t)prog[4] << 8 | prog[5]) % len);
        break;
    case 2: /* truncation plus flips inside what is left */
        len = 1 + (((size_t)prog[4] << 8 | prog[5]) % len);
        for (size_t i = 6; i + 1 < plen && i < 64; i += 2)
            stream[((size_t)prog[i] << 8 | prog[i + 1]) % len] ^= prog[(i + 1) % plen];
        break;
    default: /* extension: bytes past the terminating chunk */
        for (size_t i = 4; i < plen && i < 40 && len < sizeof stream; i++)
            stream[len++] = prog[i];
        break;
    }
    return len;
}

static void run_one(const uint8_t *data, size_t size) {
    if (size < 2) return;

    if (!out) { guardbuf_init(&out_gb, MAX_OUT); out = guard_dst(&out_gb, MAX_OUT); }

    size_t len;
    if (data[0] & 1) {
        len = damage_valid_stream(data, size);
        if (len == 0) return;
    } else {
        len = size < MAX_IN ? size : MAX_IN;
        memcpy(stream, data, len);
        if ((data[0] & 2) && len >= 4) memcpy(stream, "ZBM\x09", 4);
    }

    out = guard_dst(&out_gb, MAX_OUT);
    static fuzzbuf_t source_buf;
    const uint8_t *exact_stream = fuzz_copy(&source_buf, stream, len);
    /* Learn the claimed output length against the guarded full-capacity destination. */
    size_t got = 0;
    int rc = crushlzbitmap_decode_buffer(out, MAX_OUT, exact_stream, len, &got);
    fuzz_check_written(out, got);
    if (rc == 0 && got > MAX_OUT) {
        fprintf(stderr, "FUZZ FAILURE: reported %zu bytes into a %zu-byte buffer\n",
                got, (size_t)MAX_OUT);
        abort();
    }

    /* Exact-fit path: re-decode into a destination sized to precisely what
     * the decoder just claimed, in the selected guard placement. Any write past `got` —
     * even one byte, even one that would have stayed inside the plain 512
     * KiB `out` above — now faults instead of going unnoticed. */
    if (rc == 0 && got > 0) {
        uint8_t *tight_dst = guard_dst(&out_gb, got);
        size_t tight_got = 0;
        int trc = crushlzbitmap_decode_buffer(tight_dst, got, exact_stream, len, &tight_got);
        fuzz_check_written(tight_dst, tight_got);
        if (trc != 0 || tight_got != got) {
            fprintf(stderr,
                    "FUZZ FAILURE: exact-fit decode disagreed with the generous one "
                    "(rc=%d got=%zu vs %zu)\n",
                    trc, tight_got, got);
            abort();
        }
    }

    /* Tight-buffer path: a decoder that only checks bounds against a generous
     * destination passes above and fails here — must reject or truncate
     * cleanly when told the destination is one byte short of what it needs. */
    if (rc == 0 && got > 0) {
        uint8_t *short_dst = guard_dst(&out_gb, got - 1);
        size_t short_got = 0;
        (void)crushlzbitmap_decode_buffer(short_dst, got - 1, exact_stream, len, &short_got);
        fuzz_check_written(short_dst, short_got);
    }
}

#include "driver.h"
