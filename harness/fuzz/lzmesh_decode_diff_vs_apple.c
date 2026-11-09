// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential fuzz harness: our LZMESH decoder against Apple's, on the same
 * bytes. Where both succeed, lengths and bytes must match (contract 1);
 * where only one succeeds, that is reported (contracts 2 and 3).
 *
 * Apple truncates the final match of a block at its stated size and treats
 * a too-small destination as a cap, so both decoders get a destination
 * larger than any stream here can claim.
 *
 * macOS only; elsewhere this compiles to a harness that does nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzmesh.h"
#include "guardbuf.h"
#include "lzmesh_seed.h"

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
static guardbuf_t apple_gb;
static uint8_t *out_apple;

#if HAVE_APPLE_DECODER

static unsigned long long ours_only_hits, apple_only_hits;

static void report_counts(void)
{
    if (ours_only_hits || apple_only_hits)
        fprintf(stderr, "contract totals: we accept/Apple refuses %llu, Apple accepts/we refuse %llu\n",
                ours_only_hits, apple_only_hits);
}

static void run_one(const uint8_t *data, size_t size)
{
    size_t len;
    if (size >= 12 && (data[0] & 1)) {
        len = lzmesh_seed_stream(data, size, stream, sizeof stream);
        if (!len) return;
        size_t nmut = 1 + (data[0] >> 1) % 4;
        for (size_t k = 0; k < nmut && 9 + k * 2 < size; k++) {
            size_t off = ((size_t)data[8 + k * 2] << 8 | data[9 + k * 2]) % len;
            stream[off] = data[(8 + k * 2 + 7) % size];
        }
    } else {
        len = size > sizeof stream ? sizeof stream : size;
        memcpy(stream, data, len);
    }

    if (!out_apple) {
        guardbuf_init(&apple_gb, MAX_OUT);
        out_apple = guard_dst(&apple_gb, MAX_OUT);
        atexit(report_counts);
    }

    size_t olen = 0;
    int orc = crushlzmesh_decode_buffer(out_ours, sizeof out_ours, stream, len, &olen);
    size_t alen = compression_decode_buffer(out_apple, MAX_OUT, stream, len, NULL, COMPRESSION_LZMESH);

    /* Apple reports failure as 0, which is also its answer for an empty
     * stream; treat 0 as failure only when we also produced nothing. */
    int apple_ok = (alen > 0) || (orc == 0 && olen == 0);
    int ours_ok = (orc == 0);

    if (ours_ok && apple_ok && alen > 0) {
        if (olen != alen || memcmp(out_ours, out_apple, olen) != 0) {
            fprintf(stderr, "DIVERGE: both accepted, ours=%zu apple=%zu, bytes differ\n", olen, alen);
            abort();
        }
        return;
    }
    if (ours_ok && !apple_ok) {
        unsigned long long h = ++ours_only_hits;
        if ((h & (h - 1)) == 0) fprintf(stderr, "contract 2: we accept, Apple refuses (%llu so far)\n", h);
        return;
    }
    if (!ours_ok && apple_ok && alen > 0) {
        unsigned long long h = ++apple_only_hits;
        if ((h & (h - 1)) == 0)
            fprintf(stderr, "contract 3: Apple accepts, we refuse rc=%d (%llu so far)\n", orc, h);
        return;
    }
}

#else

static void run_one(const uint8_t *data, size_t size) { (void)data; (void)size; }

#endif

#include "driver.h"
