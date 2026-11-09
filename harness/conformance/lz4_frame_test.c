// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Frame invariants Apple's LZ4 decoder enforces, asserted directly on the
 * bytes we emit, since a round trip through our own decoder cannot see them:
 *
 *   1. Every stream ends with "bv4$".
 *   2. Walking the block headers lands exactly on the end of the buffer, and
 *      each bv41 block's encoded_size is the real distance to the next header.
 *   3. decoded_size across all blocks sums to the input length.
 *   4. An empty input encodes to a bare terminator.
 *   5. Blocks never exceed 64 KiB of decoded data, which decmpfs chunking needs.
 *
 * Deliberately NOT checked here: whether Apple accepts the stream. That is
 * lz4_decode_diff_vs_apple.c's job and it needs libcompression; this file is
 * portable and runs everywhere, so a non-Apple CI still gets the frame
 * invariants rather than nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"

#define SRC_SZ (200 * 1024)   /* several 64 KiB blocks */

static int failures, checks;

static void fail(const char *what, int level, size_t n, const char *detail)
{
    printf("FAIL level %d, %zu bytes: %s (%s)\n", level, n, what, detail);
    failures++;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Mostly compressible, with a stretch of noise so at least one block is
 * emitted stored. */
static void fill(uint8_t *b, size_t n)
{
    uint32_t x = 22222;
    for (size_t i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        b[i] = (i > n / 2 && i < n / 2 + 40000)
                   ? (uint8_t)(x >> 24)
                   : (uint8_t)("abcdefgh"[(i / 3) % 8] + (i % 5));
    }
}

static void walk(const uint8_t *s, size_t len, int level, size_t n)
{
    size_t p = 0, decoded = 0;
    int saw_end = 0;

    while (p + 4 <= len) {
        uint32_t m = rd32(s + p);
        if (m == CRUSHLZ4_MAGIC_END) { p += 4; saw_end = 1; break; }

        if (m == CRUSHLZ4_MAGIC_STORED) {
            if (p + 8 > len) { fail("stored header past end", level, n, "truncated"); return; }
            uint32_t raw = rd32(s + p + 4);
            if (raw > CRUSHLZ4_BLOCK_SIZE)
                fail("stored block over 64 KiB", level, n, "breaks decmpfs chunking");
            if (p + 8 + raw > len) { fail("stored payload past end", level, n, "truncated"); return; }
            p += 8 + raw;
            decoded += raw;
            continue;
        }

        if (m == CRUSHLZ4_MAGIC_COMPRESSED) {
            if (p + 12 > len) { fail("bv41 header past end", level, n, "truncated"); return; }
            uint32_t dec = rd32(s + p + 4), enc = rd32(s + p + 8);
            if (dec > CRUSHLZ4_BLOCK_SIZE)
                fail("bv41 decoded_size over 64 KiB", level, n, "breaks decmpfs chunking");
            if (enc == 0) fail("bv41 encoded_size is zero", level, n, "no payload");
            if (p + 12 + enc > len) { fail("bv41 payload past end", level, n, "truncated"); return; }
            p += 12 + enc;
            decoded += dec;
            continue;
        }

        fail("unknown block magic", level, n, "not bv41/bv4-/bv4$");
        return;
    }

    checks++;
    if (!saw_end) fail("stream does not end with bv4$", level, n, "missing terminator");
    else if (p != len) fail("trailing bytes after bv4$", level, n, "frame walk did not land on end");
    if (decoded != n) fail("decoded_size sum != input length", level, n, "block sizes disagree");
}

int main(void)
{
    static uint8_t src[SRC_SZ], enc[SRC_SZ * 2];
    static const size_t sizes[] = { 0, 1, 4095, 65535, 65536, 65537, 131072, SRC_SZ };

    fill(src, sizeof src);

    for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++) {
        for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            size_t n = sizes[i], len = 0;
            len = crushlz4_encode_buffer(enc, sizeof enc, src, n, NULL, 0, level);
            if (len == 0) {
                fail("encode refused a valid input", level, n, "no mutation involved");
                continue;
            }
            if (n == 0) {
                checks++;
                if (len != 4 || rd32(enc) != CRUSHLZ4_MAGIC_END)
                    fail("empty input is not a bare terminator", level, n, "expected 4 bytes of bv4$");
                continue;
            }
            walk(enc, len, level, n);
        }
    }

    printf("\nlz4_frame_test: %d checks, %d failures\n", checks, failures);
    if (!checks) {              /* a suite that ran nothing has verified nothing */
        printf("NO CHECKS RAN: treating as failure\n");
        return 1;
    }
    return failures != 0;
}
