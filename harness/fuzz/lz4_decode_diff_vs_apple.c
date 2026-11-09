// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential fuzz harness: our Apple-LZ4 decoder against Apple's, on the
 * same bytes. Where both succeed, lengths and bytes must match (contract 1);
 * where only one succeeds, that is reported (contracts 2 and 3).
 *
 * Apple truncates and reports success when the destination is too small,
 * where we return CRUSHLZ4_OUTPUT_TOO_SMALL; both decoders are therefore
 * given a destination large enough for any claim a stream can make.
 *
 * macOS only; elsewhere this compiles to a harness that does nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"
#include "guardbuf.h"

#if defined(__APPLE__)
#include <compression.h>
#define HAVE_APPLE_DECODER 1
#else
#define HAVE_APPLE_DECODER 0
#endif

#define MAX_IN  (256 * 1024)
#define MAX_OUT (4 * 1024 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t out_ours[MAX_OUT];
/* Apple's destination is guarded; see guardbuf.h. */
static guardbuf_t apple_gb;
static uint8_t *out_apple;
static uint8_t seed_data[64 * 1024];

#if HAVE_APPLE_DECODER

static unsigned long long ours_only_hits, apple_only_hits;

/* Random bytes rarely pass the frame magic, so half the budget goes to real
 * multi-block streams the fuzzer then damages; a corrupted offset in block N
 * can then reference block N-1. */
static size_t corrupt_valid_stream(const uint8_t *prog, size_t plen)
{
    if (plen < 4) return 0;

    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 4096 + ((size_t)prog[2] << 8);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);

    int level = (int)(prog[3] % 13) - 2;
    size_t len = crushlz4_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0, level);
    if (len == 0)
        return 0;

    size_t nmut = 1 + (prog[0] % 4);
    for (size_t k = 0; k < nmut && 4 + k * 2 + 1 < plen; k++) {
        size_t off = ((size_t)prog[4 + k * 2] << 8 | prog[4 + k * 2 + 1]) % len;
        stream[off] = prog[(4 + k * 2) % plen];
    }
    return len;
}

static void run_one(const uint8_t *data, size_t size)
{
    size_t len;

    if (size && (data[0] & 1)) {
        len = corrupt_valid_stream(data, size);
        if (!len) return;
    } else {
        len = size > sizeof stream ? sizeof stream : size;
        memcpy(stream, data, len);
    }

    if (!out_apple) { guardbuf_init(&apple_gb, MAX_OUT); out_apple = guard_dst(&apple_gb, MAX_OUT); }

    size_t olen = 0;
    int orc = crushlz4_decode_buffer(out_ours, sizeof out_ours, stream, len, &olen);

    memset(out_apple, 0xA5, 64);
    size_t alen = compression_decode_buffer(out_apple, MAX_OUT,
                                            stream, len, NULL, COMPRESSION_LZ4);

    /* Apple reports failure as 0, which is also its answer for an empty
     * stream; treat 0 as failure only when we also produced nothing. */
    int apple_ok = (alen > 0) || (orc == 0 && olen == 0);
    int ours_ok  = (orc == 0);

    if (ours_ok && apple_ok && alen > 0) {
        if (olen != alen || memcmp(out_ours, out_apple, olen) != 0) {
            fprintf(stderr, "DIVERGE: both accepted, ours=%zu apple=%zu, bytes differ\n",
                    olen, alen);
            abort();
        }
        return;
    }

    if (ours_ok && !apple_ok) {
        unsigned long long h = ++ours_only_hits;
        if ((h & (h - 1)) == 0)
            fprintf(stderr, "contract 2: we accept, Apple refuses (%llu so far)\n", h);
        return;
    }

    if (!ours_ok && apple_ok && alen > 0) {
        unsigned long long h = ++apple_only_hits;
        if ((h & (h - 1)) == 0)
            fprintf(stderr, "contract 3: Apple accepts, we refuse rc=%d (%llu so far)\n",
                    orc, h);
        return;
    }
}

#else

static void run_one(const uint8_t *data, size_t size) { (void)data; (void)size; }

#endif

#include "driver.h"
