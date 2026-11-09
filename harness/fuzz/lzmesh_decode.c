// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Memory safety of our LZMESH decoder on hostile input, under ASan/UBSan.
 * Parity with Apple's decoder is lzmesh_decode_diff_vs_apple.c's job.
 *
 * Random bytes almost never form a valid Huffman block, so most of the
 * budget goes to real streams damaged by byte flips, truncation, or
 * trailing bytes.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzmesh.h"
#include "guardbuf.h"
#include "fuzzbuf.h"
#include "lzmesh_seed.h"

#define MAX_IN  (256 * 1024)
#define MAX_OUT (4 * 1024 * 1024)

static uint8_t stream[MAX_IN];
static guardbuf_t out_gb;
static uint8_t *out;

static size_t damage_valid_stream(const uint8_t *data, size_t size)
{
    size_t len = lzmesh_seed_stream(data, size, stream, sizeof stream);
    if (len == 0) return 0;

    switch ((data[0] >> 1) & 3) {
    case 0: /* flips */
        for (size_t k = 8; k < size && k < 24; k++)
            stream[((size_t)data[k] << 3 | k) % len] ^= data[size - 1 - (k % size)];
        break;
    case 1: /* truncation, anywhere including mid-header */
        len = 1 + (((size_t)data[8 % size] << 8 | data[9 % size]) % len);
        break;
    case 2: /* truncation plus flips inside what is left */
        len = 1 + (((size_t)data[8 % size] << 8 | data[9 % size]) % len);
        for (size_t k = 10; k < size && k < 24; k++)
            stream[((size_t)data[k] << 3 | k) % len] ^= data[size - 1 - (k % size)];
        break;
    default: /* trailing bytes after the end marker */
        for (size_t k = 8; k < size && k < 40 && len < sizeof stream; k++)
            stream[len++] = data[k];
        break;
    }
    return len;
}

static void run_one(const uint8_t *data, size_t size)
{
    size_t len;
    if (size < 12) return;
    if (!out) guardbuf_init(&out_gb, MAX_OUT);

    if (data[0] & 1) {
        len = damage_valid_stream(data, size);
        if (len == 0) return;
    } else {
        // Raw bytes, steered into a compressed block header half the time.
        len = size > sizeof stream ? sizeof stream : size;
        memcpy(stream, data, len);
        if (data[0] & 2) stream[0] = CRUSHLZMESH_BLOCK_COMP;
    }

    // A destination of zero, as in a sizing probe.
    size_t want = 0;
    (void)crushlzmesh_decode_buffer(NULL, 0, stream, len, &want);

    out = guard_dst(&out_gb, MAX_OUT);
    size_t got = 0;
    int rc = crushlzmesh_decode_buffer(out, MAX_OUT, stream, len, &got);
    fuzz_check_written(out, got);
    if (got > MAX_OUT) {
        fprintf(stderr, "FUZZ FAILURE: reported %zu bytes into a %zu-byte buffer\n", got, (size_t)MAX_OUT);
        abort();
    }

    // Exact fit: any write past `got` lands on the guard.
    if (rc == 0 && got > 0) {
        uint8_t *tight = guard_dst(&out_gb, got);
        size_t tgot = 0;
        int trc = crushlzmesh_decode_buffer(tight, got, stream, len, &tgot);
        fuzz_check_written(tight, tgot);
        if (trc != 0 || tgot != got) {
            fprintf(stderr, "FUZZ FAILURE: exact-fit decode disagreed (rc=%d got=%zu vs %zu)\n", trc, tgot, got);
            abort();
        }
    }

    // One byte short must fail cleanly.
    if (rc == 0 && got > 0) {
        uint8_t *shrt = guard_dst(&out_gb, got - 1);
        size_t sgot = 0;
        int src = crushlzmesh_decode_buffer(shrt, got - 1, stream, len, &sgot);
        fuzz_check_written(shrt, sgot);
        if (src == 0) {
            fprintf(stderr, "FUZZ FAILURE: decode into %zu bytes claimed success\n", got - 1);
            abort();
        }
    }
}

#include "driver.h"
