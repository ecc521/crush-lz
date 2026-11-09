// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Memory safety of our Apple-LZ4 decoder on hostile input, under ASan/UBSan.
 * Parity with Apple's decoder is lz4_decode_diff_vs_apple.c's job.
 *
 * Random bytes rarely pass the frame magic, so half the budget goes to real
 * streams damaged by byte flips, truncation, or extension past the end.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"
#include "guardbuf.h"
#include "fuzzbuf.h"

#define MAX_IN  (256 * 1024)
#define MAX_OUT (4 * 1024 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t seed_data[64 * 1024];
/* Our own decoder is ASan-instrumented, so a write past a plain array's true
 * allocation is already caught — the gap a fixed oversized `out` leaves is
 * an overflow that stays inside that allocation but past the *logical*
 * length the decoder reports. A guarded, exactly-sized destination turns
 * that into a fault too. */
static guardbuf_t out_gb;
static uint8_t *out;

/* Build a real stream and damage it. Returns its length, or 0. */
static size_t damage_valid_stream(const uint8_t *data, size_t size)
{
    size_t len = 0;
    unsigned period = 1u + (data[1] % 64u);
    size_t n = 1024 + ((size_t)data[2] << 8);

    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);
    len = crushlz4_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0,
                                 (int)(data[3] % 13) - 2);
    if (len == 0)
        return 0;

    switch ((data[0] >> 1) & 3) {
    case 0: /* flips */
        for (size_t k = 4; k < size && k < 20; k++)
            stream[((size_t)data[k] << 3 | k) % len] ^= data[size - 1 - (k % size)];
        break;
    case 1: /* truncation, anywhere including mid-header */
        len = 1 + (((size_t)data[4 % size] << 8 | data[5 % size]) % len);
        break;
    case 2: /* truncation plus flips inside what is left */
        len = 1 + (((size_t)data[4 % size] << 8 | data[5 % size]) % len);
        for (size_t k = 6; k < size && k < 20; k++)
            stream[((size_t)data[k] << 3 | k) % len] ^= data[size - 1 - (k % size)];
        break;
    default: /* extension: trailing bytes past a complete frame */
        for (size_t k = 4; k < size && k < 36 && len < sizeof stream; k++)
            stream[len++] = data[k];
        break;
    }
    return len;
}

static void run_one(const uint8_t *data, size_t size)
{
    size_t len;

    if (size < 8) return;

    if (!out) { guardbuf_init(&out_gb, MAX_OUT); out = guard_dst(&out_gb, MAX_OUT); }

    if (data[0] & 1) {
        len = damage_valid_stream(data, size);
        if (len == 0) return;
    } else {
        len = size > sizeof stream ? sizeof stream : size;
        memcpy(stream, data, len);
        if ((data[0] & 2) && len >= 4) {
            static const uint32_t magics[] = {CRUSHLZ4_MAGIC_COMPRESSED,
                                              CRUSHLZ4_MAGIC_STORED,
                                              CRUSHLZ4_MAGIC_END};
            uint32_t m = magics[(data[0] >> 2) % 3];
            memcpy(stream, &m, 4);
        }
    }

    out = guard_dst(&out_gb, MAX_OUT);

    /* The NULL-destination sizing path has its own header arithmetic. */
    size_t want = 0;
    (void)crushlz4_decode_buffer(NULL, 0, stream, len, &want);

    size_t got = 0;
    int rc = crushlz4_decode_buffer(out, MAX_OUT, stream, len, &got);
    fuzz_check_written(out, got);
    if (rc == 0 && got > MAX_OUT) {
        fprintf(stderr, "FUZZ FAILURE: reported %zu bytes into a %zu-byte buffer\n",
                got, (size_t)MAX_OUT);
        abort();
    }

    /* Exact-fit path: re-decode into a destination sized to precisely what
     * the decoder just claimed, ending on the guard. Any write past `got` —
     * even one that would have stayed inside the plain 4 MiB `out` before —
     * now faults instead of going unnoticed. */
    if (rc == 0 && got > 0) {
        uint8_t *tight_dst = guard_dst(&out_gb, got);
        size_t tight_got = 0;
        int trc = crushlz4_decode_buffer(tight_dst, got, stream, len, &tight_got);
        fuzz_check_written(tight_dst, tight_got);
        if (trc != 0 || tight_got != got) {
            fprintf(stderr, "FUZZ FAILURE: exact-fit decode disagreed (rc=%d got=%zu vs %zu)\n",
                    trc, tight_got, got);
            abort();
        }
    }

    /* Tight-buffer path: a decoder that only checks bounds against a generous
     * destination passes above and fails here. */
    if (rc == 0 && got > 0) {
        uint8_t *short_dst = guard_dst(&out_gb, got - 1);
        size_t short_got = 0;
        (void)crushlz4_decode_buffer(short_dst, got - 1, stream, len, &short_got);
        fuzz_check_written(short_dst, short_got);
    }
}

#include "driver.h"
